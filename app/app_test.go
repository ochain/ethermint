package app

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/cmd/utils"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/eth"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/tendermint/ethermint/ethereum"
)

func makeTestSystemNode(tempDatadir string, accman *accounts.Manager, acc accounts.Account) *node.Node {

	params.TargetGasLimit = common.String2Big("1000000") // ctx.GlobalString(utils.TargetGasLimitFlag.Name)

	// Configure the node's service container
	stackConf := &node.Config{
		DataDir:     tempDatadir,
		PrivateKey:  nil,        // utils.MakeNodeKey(ctx),
		Name:        "",         // utils.MakeNodeName(name, version, ctx),
		IPCPath:     "",         // utils.MakeIPCPath(ctx),
		HTTPHost:    "",         // utils.MakeHTTPRpcHost(ctx),
		HTTPPort:    0,          // ctx.GlobalInt(utils.RPCPortFlag.Name),
		HTTPCors:    "",         // ctx.GlobalString(utils.RPCCORSDomainFlag.Name),
		HTTPModules: []string{}, // utils.MakeRPCModules(ctx.GlobalString(utils.RPCApiFlag.Name)),
		WSHost:      "",         // utils.MakeWSRpcHost(ctx),
		WSPort:      0,          // ctx.GlobalInt(utils.WSPortFlag.Name),
		WSOrigins:   "",         // ctx.GlobalString(utils.WSAllowedOriginsFlag.Name),
		WSModules:   []string{}, // utils.MakeRPCModules(ctx.GlobalString(utils.WSApiFlag.Name)),
	}
	// Configure the Ethereum service
	jitEnabled := false

	genesis, err := ioutil.ReadFile("/media/sf_sources/omise/golang/src/github.com/tendermint/ethermint/dev/genesis.json")
	if err != nil {
		utils.Fatalf("Failed reading test genesis.json %v", err)
	}

	var genesisdict map[string]interface{}
	err = json.Unmarshal(genesis, &genesisdict)
	if err != nil {
		utils.Fatalf("Failed to unmarshal genesis json string %v", err)
	}

	genesisdict["alloc"].(map[string]interface{})[acc.Address.Hex()] = map[string]string{"balance": "10000000000000000000000000000000000"}

	genesis, err = json.Marshal(genesisdict)
	if err != nil {
		utils.Fatalf("Failed to marshal genesis json string %v", err)
	}

	ethConf := &eth.Config{
		Genesis:                 string(genesis),
		ChainConfig:             &core.ChainConfig{big.NewInt(0), big.NewInt(0), true, big.NewInt(0), vm.Config{}},
		BlockChainVersion:       1, // ctx.GlobalInt(utils.BlockchainVersionFlag.Name),
		DatabaseCache:           0, // ctx.GlobalInt(utils.CacheFlag.Name),
		DatabaseHandles:         utils.MakeDatabaseHandles(),
		NetworkId:               0, // ctx.GlobalInt(utils.NetworkIdFlag.Name),
		AccountManager:          accman,
		Etherbase:               common.Address{}, // utils.MakeEtherbase(accman, ctx),
		EnableJit:               jitEnabled,
		ForceJit:                false,                      // ctx.GlobalBool(utils.VMForceJitFlag.Name),
		GasPrice:                common.String2Big("1000"),  // ctx.GlobalString(utils.GasPriceFlag.Name)
		GpoMinGasPrice:          common.String2Big("100"),   // ctx.GlobalString(utils.GpoMinGasPriceFlag.Name)
		GpoMaxGasPrice:          common.String2Big("10000"), // ctx.GlobalString(utils.GpoMaxGasPriceFlag.Name)
		GpoFullBlockRatio:       0,                          // ctx.GlobalInt(utils.GpoFullBlockRatioFlag.Name),
		GpobaseStepDown:         0,                          // ctx.GlobalInt(utils.GpobaseStepDownFlag.Name),
		GpobaseStepUp:           0,                          // ctx.GlobalInt(utils.GpobaseStepUpFlag.Name),
		GpobaseCorrectionFactor: 0,                          // ctx.GlobalInt(utils.GpobaseCorrectionFactorFlag.Name),
		SolcPath:                "",                         // ctx.GlobalString(utils.SolcPathFlag.Name),
	}

	// Assemble and return the protocol stack
	stack, err := node.New(stackConf)
	if err != nil {
		utils.Fatalf("Failed to create the protocol stack: %v", err)
	}
	if err := stack.Register(func(ctx *node.ServiceContext) (node.Service, error) {
		return ethereum.NewBackend(ctx, ethConf)
	}); err != nil {
		utils.Fatalf("Failed to register the TMSP application service: %v", err)
	}
	return stack
}

func prepareTx(nonce uint64, acc accounts.Account, accman *accounts.Manager) ([]byte, error) {
	tx := types.NewTransaction(nonce, acc.Address, big.NewInt(10), big.NewInt(21000), big.NewInt(10), []byte{})

	signature, err := accman.Sign(acc.Address, tx.SigHash().Bytes())
	if err != nil {
		return nil, err
	}

	signedtx, err := tx.WithSignature(signature)
	if err != nil {
		return nil, err
	}

	return rlp.EncodeToBytes(signedtx)
}

func getTxPoolAPI(app *EthermintApplication) *eth.PublicTransactionPoolAPI {
	apis := app.Backend().Ethereum().APIs()
	for _, v := range apis {
		if v.Namespace == "net" {
			continue
		}
		if txPoolAPI, ok := v.Service.(*eth.PublicTransactionPoolAPI); ok {
			return txPoolAPI
		}
	}
	return nil
}

func TestBumpingNonces(t *testing.T) {
	fmt.Print("")

	tempDatadir, err := ioutil.TempDir("", "ethermint_test")
	if err != nil {
		t.Error("unable to create temporary datadir")
	}
	defer func() {
		os.RemoveAll(tempDatadir)
		t.Log("removed", tempDatadir)
	}()

	accman := accounts.NewPlaintextManager(tempDatadir + "/keystore")

	// acc, err := accman.NewAccount("")
	// deterministic version of the above
	acc, err := accman.Import([]byte{123, 34, 97, 100, 100, 114, 101, 115, 115, 34, 58, 34, 52, 99, 49, 48, 57, 98, 97, 54, 52, 99, 48, 99, 98, 48, 50, 98, 51, 99, 55, 53, 102, 50, 101, 99, 51, 100, 52, 54, 48, 55, 57, 49, 50, 102, 51, 101, 50, 56, 100, 54, 34, 44, 34, 99, 114, 121, 112, 116, 111, 34, 58, 123, 34, 99, 105, 112, 104, 101, 114, 34, 58, 34, 97, 101, 115, 45, 49, 50, 56, 45, 99, 116, 114, 34, 44, 34, 99, 105, 112, 104, 101, 114, 116, 101, 120, 116, 34, 58, 34, 49, 52, 48, 53, 56, 56, 97, 102, 53, 54, 53, 52, 102, 97, 54, 55, 97, 48, 101, 102, 97, 55, 51, 51, 50, 52, 102, 99, 55, 52, 55, 56, 53, 102, 48, 99, 100, 55, 101, 102, 55, 51, 48, 50, 98, 48, 50, 97, 100, 54, 56, 54, 49, 56, 53, 54, 54, 98, 52, 53, 101, 48, 98, 99, 34, 44, 34, 99, 105, 112, 104, 101, 114, 112, 97, 114, 97, 109, 115, 34, 58, 123, 34, 105, 118, 34, 58, 34, 49, 56, 48, 57, 49, 53, 57, 54, 102, 51, 102, 48, 53, 98, 54, 57, 99, 53, 97, 100, 53, 100, 54, 102, 102, 48, 100, 98, 51, 57, 56, 55, 34, 125, 44, 34, 107, 100, 102, 34, 58, 34, 115, 99, 114, 121, 112, 116, 34, 44, 34, 107, 100, 102, 112, 97, 114, 97, 109, 115, 34, 58, 123, 34, 100, 107, 108, 101, 110, 34, 58, 51, 50, 44, 34, 110, 34, 58, 50, 54, 50, 49, 52, 52, 44, 34, 112, 34, 58, 49, 44, 34, 114, 34, 58, 56, 44, 34, 115, 97, 108, 116, 34, 58, 34, 48, 57, 51, 50, 56, 101, 50, 52, 57, 54, 98, 98, 56, 54, 55, 98, 102, 55, 102, 98, 54, 56, 48, 97, 102, 54, 102, 100, 97, 98, 97, 98, 100, 97, 52, 55, 102, 55, 102, 101, 97, 55, 54, 48, 54, 97, 53, 53, 50, 100, 57, 55, 53, 100, 99, 50, 100, 98, 53, 49, 98, 53, 100, 98, 34, 125, 44, 34, 109, 97, 99, 34, 58, 34, 97, 101, 56, 50, 57, 98, 97, 57, 54, 97, 98, 48, 53, 51, 52, 98, 55, 50, 98, 55, 100, 100, 54, 57, 56, 98, 98, 55, 98, 97, 55, 54, 102, 55, 100, 54, 99, 98, 97, 97, 98, 51, 49, 100, 100, 98, 98, 51, 51, 52, 51, 51, 57, 100, 99, 98, 53, 52, 53, 51, 50, 56, 57, 57, 34, 125, 44, 34, 105, 100, 34, 58, 34, 101, 53, 50, 56, 100, 100, 51, 56, 45, 54, 49, 98, 53, 45, 52, 57, 56, 53, 45, 57, 48, 100, 102, 45, 56, 48, 100, 57, 57, 98, 50, 51, 102, 53, 100, 51, 34, 44, 34, 118, 101, 114, 115, 105, 111, 110, 34, 58, 51, 125},
		"", "")
	if err != nil {
		t.Error("Failed to create testing account &v", err)
	}

	err = accman.Unlock(acc, "")
	if err != nil {
		t.Error("Error unlocking account %v: %v", acc, err)
	}
	exbytes, err := accman.Export(acc, "", "")
	t.Log(exbytes)

	stack := makeTestSystemNode(tempDatadir, accman, acc)
	utils.StartNode(stack)

	var backend *ethereum.Backend
	if err := stack.Service(&backend); err != nil {
		t.Error("backend service not running: %v", err)
	}

	app, err := NewEthermintApplication(backend, nil, nil)
	if err != nil {
		t.Error("Failed to create ethermint app")
	}

	tx1, err := prepareTx(0, acc, accman)
	if err != nil {
		t.Error("Error preparing transaction %v for %v: %v", 0, acc, err)
	}

	txPoolAPI := getTxPoolAPI(app)
	if txPoolAPI == nil {
		t.Error("Unable to fetch tx pool api")
	}

	t.Log(app.CheckTx(tx1))
	t.Log(app.AppendTx(tx1))
	t.Log(app.Commit())
	time.Sleep(0 * time.Second)

	// tx2, err := prepareTx(1, acc, accman)

	// result, err := txPoolAPI.SendRawTransaction(common.ToHex(tx2))
	sendargs := eth.SendTxArgs{
		From:     acc.Address,
		To:       &acc.Address,
		Gas:      rpc.NewHexNumber(21000),
		GasPrice: rpc.NewHexNumber(10),
		Value:    rpc.NewHexNumber(10),
		Data:     "",
		Nonce:    nil,
	}
	result, err := txPoolAPI.SendTransaction(sendargs)
	if err != nil {
		t.Errorf("error sending raw tx:  %v", err)
	}
	t.Log(result)

	t.Log(app.Commit())

	apinonce, err := txPoolAPI.GetTransactionCount(acc.Address, -1)
	if app.txPool.State() == nil {
		app.txPool.Pending()
	}
	t.Log(app.txPool.State().GetNonce(acc.Address))
	assert.Equal(t, app.txPool.State().GetNonce(acc.Address), apinonce.Uint64(), "nonce out of sync")
	assert.Equal(t, uint64(2), apinonce.Uint64(), "nonce in API not bumped")
}
