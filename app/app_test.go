package app

import (
	// "flag"
	"gopkg.in/urfave/cli.v1"
	"io/ioutil"
	"math/big"
	"os"
	"testing"

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
	"github.com/tendermint/ethermint/ethereum"
)

// func testEthConf() *eth.Config {
// 	&eth.Config{
// 		ChainConfig:             utils.MustMakeChainConfig(ctx),
// 		BlockChainVersion:       ctx.GlobalInt(utils.BlockchainVersionFlag.Name),
// 		DatabaseCache:           ctx.GlobalInt(utils.CacheFlag.Name),
// 		DatabaseHandles:         utils.MakeDatabaseHandles(),
// 		NetworkId:               ctx.GlobalInt(utils.NetworkIdFlag.Name),
// 		AccountManager:          accman,
// 		Etherbase:               utils.MakeEtherbase(accman, ctx),
// 		EnableJit:               jitEnabled,
// 		ForceJit:                ctx.GlobalBool(utils.VMForceJitFlag.Name),
// 		GasPrice:                common.String2Big(ctx.GlobalString(utils.GasPriceFlag.Name)),
// 		GpoMinGasPrice:          common.String2Big(ctx.GlobalString(utils.GpoMinGasPriceFlag.Name)),
// 		GpoMaxGasPrice:          common.String2Big(ctx.GlobalString(utils.GpoMaxGasPriceFlag.Name)),
// 		GpoFullBlockRatio:       ctx.GlobalInt(utils.GpoFullBlockRatioFlag.Name),
// 		GpobaseStepDown:         ctx.GlobalInt(utils.GpobaseStepDownFlag.Name),
// 		GpobaseStepUp:           ctx.GlobalInt(utils.GpobaseStepUpFlag.Name),
// 		GpobaseCorrectionFactor: ctx.GlobalInt(utils.GpobaseCorrectionFactorFlag.Name),
// 		SolcPath:                ctx.GlobalString(utils.SolcPathFlag.Name),
// 	}
// }

func testApp() *cli.App {

	DataDirFlag := utils.DirectoryFlag{
		Name:  "datadir",
		Usage: "Data directory for the databases and keystore",
		Value: utils.DirectoryString{""},
	}
	app := cli.NewApp()
	app.Flags = []cli.Flag{
		utils.IdentityFlag,
		utils.UnlockedAccountFlag,
		utils.PasswordFileFlag,
		utils.BootnodesFlag,
		DataDirFlag,
		utils.KeyStoreDirFlag,
		utils.BlockchainVersionFlag,
		utils.CacheFlag,
		utils.LightKDFFlag,
		utils.JSpathFlag,
		utils.ListenPortFlag,
		utils.MaxPeersFlag,
		utils.MaxPendingPeersFlag,
		utils.EtherbaseFlag,
		utils.TargetGasLimitFlag,
		utils.GasPriceFlag,
		utils.NATFlag,
		utils.NatspecEnabledFlag,
		utils.NodeKeyFileFlag,
		utils.NodeKeyHexFlag,
		utils.RPCEnabledFlag,
		utils.RPCListenAddrFlag,
		utils.RPCPortFlag,
		utils.RPCApiFlag,
		utils.WSEnabledFlag,
		utils.WSListenAddrFlag,
		utils.WSPortFlag,
		utils.WSApiFlag,
		utils.WSAllowedOriginsFlag,
		utils.IPCDisabledFlag,
		utils.IPCApiFlag,
		utils.IPCPathFlag,
		utils.ExecFlag,
		utils.PreloadJSFlag,
		utils.TestNetFlag,
		utils.VMForceJitFlag,
		utils.VMJitCacheFlag,
		utils.VMEnableJitFlag,
		utils.NetworkIdFlag,
		utils.RPCCORSDomainFlag,
		utils.MetricsEnabledFlag,
		utils.SolcPathFlag,
		utils.GpoMinGasPriceFlag,
		utils.GpoMaxGasPriceFlag,
		utils.GpoFullBlockRatioFlag,
		utils.GpobaseStepDownFlag,
		utils.GpobaseStepUpFlag,
		utils.GpobaseCorrectionFactorFlag,
		cli.StringFlag{
			Name:  "node_laddr",
			Value: "tcp://0.0.0.0:46656",
			Usage: "Node listen address. (0.0.0.0:0 means any interface, any port)",
		},
		cli.StringFlag{
			Name:  "log_level",
			Value: "info",
			Usage: "Tendermint Log level",
		},
		cli.StringFlag{
			Name:  "seeds",
			Value: "",
			Usage: "Comma delimited host:port seed nodes",
		},
		cli.BoolFlag{
			Name:  "no_fast_sync",
			Usage: "Disable fast blockchain syncing",
		},
		cli.BoolFlag{
			Name:  "skip_upnp",
			Usage: "Skip UPNP configuration",
		},
		cli.StringFlag{
			Name:  "rpc_laddr",
			Value: "tcp://0.0.0.0:46657",
			Usage: "RPC listen address. Port required",
		},
		cli.StringFlag{
			Name:  "addr",
			Value: "tcp://0.0.0.0:46658",
			Usage: "TMSP app listen address",
		},
		cli.StringFlag{
			Name:  "tmsp",
			Value: "socket",
			Usage: "socket | grpc",
		},
	}
	return app
}

func makeTestSystemNode(tempDatadir string) *node.Node {

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
	accman := accounts.NewPlaintextManager(tempDatadir + "/keystore") // utils.MakeAccountManager(ctx)
	jitEnabled := false                                               // ctx.GlobalBool(utils.VMEnableJitFlag.Name)
	ethConf := &eth.Config{
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

func TestBumpingNonces(t *testing.T) {
	// app := testApp()
	// ctx := cli.NewContext(app, flag.NewFlagSet("test", 0), nil)
	//
	tempDatadir, err := ioutil.TempDir("", "ethermint_test")
	if err != nil {
		t.Error("unable to create temporary datadir")
	}
	defer os.RemoveAll(tempDatadir)
	t.Log("created &v", tempDatadir)
	//
	// if err := ctx.Set("datadir", tempDatadir); err != nil {
	// 	t.Fatal("Unable set temporary datadir")
	// }
	// testss := ctx.GlobalString("datadir")
	// t.Log("aparent datadir %v", testss)

	stack := makeTestSystemNode(tempDatadir)
	utils.StartNode(stack)

	// get backend differently ? not for now
	var backend *ethereum.Backend
	if err := stack.Service(&backend); err != nil {
		t.Error("backend service not running: %v", err)
	}
	// ethConf := testEthConf()
	//
	// backend, err := ethereum.NewBackend(ctx, config)

	// hopefully client isn't ever needed (used by Query calls)
	// client, err := stack.Attach()
	// if err != nil {
	// 	t.Error("Failed to attach to the inproc geth: %v", err)
	// }
	app, err := NewEthermintApplication(backend, nil, nil)
	if err != nil {
		t.Error("Failed to create ethermint app")
	}

	t.Log(app.Info())
	t.Log(app.CheckTx([]byte{}))

	tx := types.NewTransaction(0, common.Address{}, big.NewInt(0), big.NewInt(0), big.NewInt(0), []byte{})

	encodedtx, err := rlp.EncodeToBytes(tx)

	if err != nil {
		t.Error("Error encoding transaction %v", tx)
	}
	t.Log("encoded %v", encodedtx)

	// TODO fails because transaction is not signed
	t.Log(app.CheckTx(encodedtx))
}
