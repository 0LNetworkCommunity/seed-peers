# Code originally copied from: https://raw.githubusercontent.com/0LNetworkCommunity/rpc-load-balancer/93b9bb394c61db015e27f8c86f40cc5eafd5dc52/fullnodes.py
# This script is a work in progress. The idea is to eventually enhance it so it can check VFNs and VNs.

import subprocess
import json
import re
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

HEALTHY_THRESHOLD = 100

# TODO: Get this information from the VN data
trusted_rpc_url = "http://70.15.242.6:8080/v1"

def get_auction_winners():
    command = f"libra query --url {trusted_rpc_url} view --function-id 0x1::epoch_boundary::get_auction_winners"
    result = subprocess.check_output(command, shell=True)
    data = json.loads(result.decode())
    if "body" in data and len(data["body"]) > 0:
        return data["body"][0]
    return []

def get_fullnode_info(addresses):
    peer_info = {}
    for address in addresses:
        command = f"libra query --url {trusted_rpc_url} val-config {address}"
        result = subprocess.check_output(command, shell=True)
        data = json.loads(result.decode())
        fna = data.get("fullnode_network_addresses", [])
        for entry in fna:
            match = re.search(r"/ip4/([\d.]+)/tcp/(\d+)/noise-ik/0x([a-fA-F0-9]+)/", entry)
            if match:
                ip, port, peer_id = match.groups()
                full_address = f"/ip4/{ip}/tcp/{port}/noise-ik/0x{peer_id}/handshake/0"
                peer_info[peer_id] = full_address
    return peer_info


def get_fullnode_playlist_info():
    nodes_info = {}
    with open('fullnode_seed_playlist.json', 'r') as playlist_file:
        playlist_data = json.load   (playlist_file)
        nodes_info = playlist_data['nodes']
        return nodes_info

def get_reference_block_height():
    url = "https://rpc.openlibra.space:8080/v1"
    response = requests.get(url, timeout=5)
    data = response.json()
    return int(data["block_height"])

def check_single_node(url, reference_height):
    try:
        response = requests.get(url, timeout=5)
        data = response.json()
        node_height = int(data.get("block_height", 0))
        diff = reference_height - node_height
        if diff <= HEALTHY_THRESHOLD:
            return ("healthy", url, diff)
        else:
            return ("unhealthy", url, diff)
    except Exception:
        return ("unhealthy", url, "timeout or error")

def check_node_health(nodes_info, reference_height, max_threads=10):
    healthy = {}
    unhealthy = {}
    peer_info = {}
    for node in nodes_info:
        peer_info[node['note']] = node['url']
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {
            executor.submit(check_single_node, url, reference_height): (node_id, url)
            for node_id, url in peer_info.items()
        }
        for future in as_completed(futures):
            node_id, addr = futures[future]
            status, ip, detail = future.result()
            if status == "healthy":
                healthy[node_id] = addr
            else:
                unhealthy[node_id] = (addr, detail)
    return healthy, unhealthy

def write_seed_peers_yaml(peer_dict, filename="seed_peers.yaml"):
    with open(filename, "w") as f:
        for peer_id, addr in peer_dict.items():
            f.write(f"{peer_id}:\n")
            f.write(f"- \"{addr}\"\n")

if __name__ == "__main__":
    # print("Getting auction winner addresses...")
    # auction_winners = get_auction_winners()
    # print("Auction winner addresses:")
    # print(auction_winners)

    # print("\nGetting fullnode peer info...")
    # peer_info = get_fullnode_info(auction_winners)
    # print("\n📡 Discovered fullnode peers (address, IP):")
    # for peer_id, addr in peer_info.items():
    #     ip_match = re.search(r"/ip4/([\d.]+)/", addr)
    #     if ip_match:
    #         print(f"{peer_id} -> {ip_match.group(1)}")

    print("\nGetting fullnode playlist info...")
    nodes_info = get_fullnode_playlist_info()
    print("\n📡 Discovered fullnode peers (name, url):")
    for node in nodes_info:
        print(f"{node['note']} -> {node['url']}")

    print("\nGetting reference block height from RPC...")
    ref_height = get_reference_block_height()
    print(f"Reference block height: {ref_height}")

    print("\nChecking health of each node...")
    healthy_peers, unhealthy_peers = check_node_health(nodes_info, ref_height)

    print("\n✅ Healthy nodes (IP and block height diff):")
    for peer_id, url in healthy_peers.items():
        # Extract block diff from earlier health check
        try:
            response = requests.get(url, timeout=5)
            node_height = int(response.json().get("block_height", 0))
            diff = ref_height - node_height
            print(f"{peer_id} (block height diff: {diff})")
        except:
            print(f"{peer_id} (unexpected error re-checking height)")

    print("\n❌ Unhealthy nodes (IP and reason):")
    for peer_id, (url, reason) in unhealthy_peers.items():
        print(f"{peer_id} (reason: {reason})")

    exit_status = 1 if len(unhealthy_peers) else 0

    # print("\n📝 Writing healthy nodes to seed_peers.yaml...")
    # write_seed_peers_yaml(healthy_peers)
    print("Done.")
