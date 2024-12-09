# ROFL (Runtime OFf-chain Logic) App

## Prerequisites

Install the [`ROFL pre-requisites`](https://docs.oasis.io/rofl/prerequisites)

## Build

Build the off-chain app binary:

```sh
oasis rofl build sgx --mode unsafe
```

## Run

Start the localnet node using Docker:

```sh
docker run -it \
  -p8545:8545 \
  -p8546:8546 \
  -p8547:8547 \
  -p80:80 \
  -p8544:8544 \
  -v ./:/rofls \
  ghcr.io/oasisprotocol/sapphire-localnet
```

## Logs

Read the logs from the running node:

```sh
docker ps | awk '{print $NF}' | xargs -I {} docker exec {} tail -f /serverdir/node/net-runner/network/compute-0/node.log
```