# seed-peers

Files in this repo are a convenient place to find 0L Network seed node details.

## RPC Service Nodes
Wallets such as Cape can seed their RPC node list like [this](https://github.com/0LNetworkCommunity/carpe/blob/main/src/modules/networks.ts#L27) from the file [fullnode_seed_playlist.json](./fullnode_seed_playlist.json) in this repo.

## P2P Seed Nodes
Full nodes and other deployments using p2p protocols to sync chain state can use the file [seed_peers.yaml](./seed_peers.yaml) for a list of initial peers. This file is included in the libra node config generation tool at the time a libra release is built.

## Checks
This repo includes GitHub Action jobs that check the content of these lists, and also the on-chain VFN set. Specifically the checks test whether the listed nodes accept an inbound TCP connection and in the case of RPC service there is also a check that the node reports a block height close to a known good height.

## Updating Seed Peers

The file [seed_peers.yaml](./seed_peers.yaml) may become out of date. It can be updated by cloning this repo and then running this command:
```
$ python ./scripts/check_nodes.py --vfns --update-seed-peers
```
The updated seed_peers.yaml can then be commited back to the repo.
