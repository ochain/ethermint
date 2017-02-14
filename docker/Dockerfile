FROM golang
MAINTAINER kobigurk@gmail.com

RUN curl https://glide.sh/get | sh

# getting local ethermint code, see ochain/oc#
COPY . /go/src/github.com/tendermint/ethermint
RUN go install github.com/tendermint/ethermint/cmd/ethermint

RUN mkdir /ethermint && chmod 777 /ethermint
RUN useradd -ms /bin/bash ethermint
RUN chown ethermint /var/run
USER ethermint 

RUN mkdir -p /ethermint/setup
COPY docker/genesis.json /ethermint/setup/

# sometimes the ownership/permissions is ok sometimes it's not, see ochain/oc#
USER root
RUN chown ethermint /ethermint/setup/genesis.json
USER ethermint

RUN ethermint -datadir /ethermint/data init /ethermint/setup/genesis.json
COPY docker/keystore /ethermint/data/keystore
EXPOSE 8545

CMD ["ethermint", "-datadir", "/ethermint/data"]
