# Code originally copied from: https://raw.githubusercontent.com/0LNetworkCommunity/rpc-load-balancer/93b9bb394c61db015e27f8c86f40cc5eafd5dc52/fullnodes.py
# This script is a work in progress. The idea is to eventually enhance it so it can check VFNs and VNs.

import click
import subprocess
import json
import re
import requests
import sys
import socket
import yaml
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


def check_p2p_node_health(addr: str):
    port = 6182
    ip_match = re.search(r"/ip4/([\d.]+)/", addr)
    host = ip_match.group(1)
    try:
        with socket.create_connection((host, port), timeout=5):
            print(f"Connection to {host}:{port} succeeded.")
            return ("healthy", host, "")
    except (socket.timeout, socket.error) as e:
        print(f"Connection to {host}:{port} failed: {e}")
        return ("unhealthy", host, e)


def check_rpc_nodes_health(nodes_info, reference_height, max_threads=10):
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


def check_p2p_nodes_health(nodes_info, max_threads=10):
    healthy = {}
    unhealthy = {}
    peer_info = {}
    for node in nodes_info:
        peer_info[node['note']] = node['addr']
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {
            executor.submit(check_p2p_node_health, ip): (node_id, ip)
            for node_id, ip in peer_info.items()
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


def get_fullnode_playlist():
    print("\nGetting fullnode playlist info...")
    nodes_info = get_fullnode_playlist_info()
    print("\n📡 Discovered fullnode peers (name, url):")
    for node in nodes_info:
        print(f"{node['note']} -> {node['url']}")
    return nodes_info


def get_vfns():
    nodes_info = []
    print("Getting auction winner addresses...")
    auction_winners = get_auction_winners()
    print("Auction winner addresses:")
    print(auction_winners)

    print("\nGetting fullnode peer info...")
    peer_info = get_fullnode_info(auction_winners)
    print("\n📡 Discovered fullnode peers (address, IP):")
    for peer_id, addr in peer_info.items():
        ip_match = re.search(r"/ip4/([\d.]+)/", addr)
        if ip_match:
            ip_address = ip_match.group(1)
            print(f"{peer_id} -> {ip_address}")
            nodes_info.append({'note': peer_id, 'addr': addr})
    return nodes_info


def get_seed_peers():
    nodes_info = []
    print("\nGetting seed peers info...")
    seed_peers_file = "./seed_peers.yaml"
    seed_peers_data = {}
    try:
        with open(seed_peers_file, 'r') as file:
            seed_peers_data = yaml.safe_load(file)
    except FileNotFoundError:
        print(f"Error: File not found: {seed_peers_file}")
        return None
    except yaml.YAMLError as e:
        print(f"Error: Failed to parse YAML file: {e}")
        return None
    print(f"{seed_peers_data}")
    for peer_id, addr_array in seed_peers_data.items():
        addr = addr_array[0]
        ip_match = re.search(r"/ip4/([\d.]+)/", addr)
        if ip_match:
            ip_address = ip_match.group(1)
            print(f"{peer_id} -> {ip_address}")
            nodes_info.append({'note': peer_id, 'addr': addr})
    return nodes_info


@click.command()
@click.option('--fullnode-playlist', is_flag=True)
@click.option('--seed-peers', is_flag=True)
@click.option('--vfns', is_flag=True)
@click.option('--update-seed-peers', is_flag=True)
def main(fullnode_playlist, seed_peers, vfns, update_seed_peers):

    if sum([fullnode_playlist, seed_peers, vfns]) > 1:
        print("ERROR: only one of --fullnode-playlist, --seed-peers, --vfns can be specified")
        sys.exit(1)

    # Default to --fullnode-playlist
    if sum([fullnode_playlist, seed_peers, vfns]) == 0:
        fullnode_playlist = True

    if update_seed_peers and not vfns:
        print("ERROR: --update-seed-peers can only be used with --vfns")
        sys.exit(1)

    if (fullnode_playlist):
        nodes_info = get_fullnode_playlist()
    elif (vfns):
        nodes_info = get_vfns()
    elif (seed_peers):
        nodes_info = get_seed_peers()

    print("\nGetting reference block height from RPC...")
    ref_height = get_reference_block_height()
    print(f"Reference block height: {ref_height}")

    print("\nChecking health of each node...")
    if fullnode_playlist:
        healthy_peers, unhealthy_peers = check_rpc_nodes_health(nodes_info, ref_height)
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

    if vfns or seed_peers:
        healthy_peers, unhealthy_peers = check_p2p_nodes_health(nodes_info)

    exit_status = 1 if len(unhealthy_peers) else 0

    if update_seed_peers:
        print("\n📝 Writing healthy nodes to seed_peers.yaml...")
        write_seed_peers_yaml(healthy_peers)
        print("Done.")
    
    sys.exit(exit_status)

if __name__ == "__main__":
    main()