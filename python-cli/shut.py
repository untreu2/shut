import asyncio
import json
import websockets
import secp256k1
import hashlib
import binascii
import base64
import os
import sys
import time
from bech32 import bech32_decode, convertbits, bech32_encode

RELAY_URLS = [
    "wss://eu.purplerelay.com",
    "wss://nos.lol",
    "wss://nosdrive.app/relay",
    "wss://nostr.mom",
    "wss://nostrelites.org",
    "wss://relay.damus.io",
    "wss://relay.nostr.band",
    "wss://relay.primal.net",
    "wss://relay.snort.social",
    "wss://vitor.nostr1.com"
]

NSEC = ""
seen_events = set()

def get_nsec_from_user():
    while True:
        nsec_input = input("Please enter your private key in 'nsec...' format: ").strip()
        if not nsec_input.startswith("nsec"):
            print("Error: The private key must start with 'nsec'.")
            continue
        hrp, data = bech32_decode(nsec_input)
        if hrp != 'nsec' or data is None:
            print("Error: Invalid NIP-19 format.")
            continue
        decoded_bits = convertbits(data, 5, 8, False)
        if decoded_bits is None:
            print("Error: Could not decode NIP-19 data.")
            continue
        private_key_bytes = bytes(decoded_bits)
        if len(private_key_bytes) != 32:
            print("Error: Invalid NSEC key length.")
            continue
        global NSEC
        NSEC = private_key_bytes.hex()
        break

def get_public_key_from_nsec(nsec):
    private_key = bytes.fromhex(nsec)
    pubkey_obj = secp256k1.PrivateKey(private_key)
    return pubkey_obj.pubkey.serialize().hex()[2:]

def create_event(kind, content, tags=[]):
    public_key = get_public_key_from_nsec(NSEC)
    created_at = int(time.time())
    event_data = [0, public_key, created_at, kind, tags, content]
    event_json = json.dumps(event_data, separators=(",", ":"), ensure_ascii=False)
    event_id = hashlib.sha256(event_json.encode()).hexdigest()
    private_key_obj = secp256k1.PrivateKey(bytes.fromhex(NSEC))
    sig = private_key_obj.schnorr_sign(bytes.fromhex(event_id), None, raw=True)
    signature = binascii.hexlify(sig).decode()
    return {
        "id": event_id,
        "pubkey": public_key,
        "created_at": created_at,
        "kind": kind,
        "tags": tags,
        "content": content,
        "sig": signature
    }

def encode_file_to_base64(file_path):
    with open(file_path, "rb") as file:
        raw_data = file.read()
    encoded = base64.b64encode(raw_data).decode('utf-8')
    if len(encoded) > 128 * 1024:
        raise ValueError("Base64 data size exceeds 128 KB. Upload canceled.")
    file_name, file_extension = os.path.splitext(os.path.basename(file_path))
    file_extension = file_extension.lstrip('.')
    tags = [
        ["name", file_name],
        ["extension", file_extension],
        ["encode", "base64"]
    ]
    return encoded, tags

def create_deletion_request(event_ids, reason="Request for deletion"):
    tags = [["e", event_id.strip()] for event_id in event_ids]
    tags.append(["k", "666"])
    return create_event(5, reason, tags)

def create_kind666_event(file_path):
    file_content, tags = encode_file_to_base64(file_path)
    return create_event(666, file_content, tags)

async def send_event(event):
    tasks = []
    for relay in RELAY_URLS:
        tasks.append(send_event_to_relay(relay, event))
    responses = await asyncio.gather(*tasks, return_exceptions=True)
    all_failed = True
    for relay, response in zip(RELAY_URLS, responses):
        if isinstance(response, Exception):
            print(f"[Error] Relay {relay}: {response}")
        else:
            all_failed = False
    if all_failed:
        print("File could not be uploaded.")

async def send_event_to_relay(relay_url, event):
    try:
        async with websockets.connect(relay_url) as websocket:
            message = ["EVENT", event]
            await websocket.send(json.dumps(message))
            return await websocket.recv()
    except Exception as e:
        raise e

async def delete_events(event_ids, reason):
    event = create_deletion_request(event_ids, reason)
    await send_event(event)
    print("Deletion request sent.")

async def upload_file(file_path):
    if not os.path.isfile(file_path):
        print("File does not exist.")
        return
    try:
        event = create_kind666_event(file_path)
    except ValueError as ve:
        print(ve)
        return
    await send_event(event)
    print("File uploaded. Event ID:", event["id"])

async def download_file(event_id):
    global seen_events
    seen_events = set()
    tasks = []
    for relay in RELAY_URLS:
        tasks.append(download_file_from_relay(relay, event_id))
    await asyncio.gather(*tasks, return_exceptions=True)

async def download_file_from_relay(relay_url, event_id):
    try:
        async with websockets.connect(relay_url) as websocket:
            sub_request = ["REQ", "sub_id", {"ids": [event_id]}]
            await websocket.send(json.dumps(sub_request))
            while True:
                response = await websocket.recv()
                event_data = json.loads(response)
                if event_data[0] == "EOSE":
                    break
                if event_data[0] == "EVENT":
                    event = event_data[2]
                    if event['id'] in seen_events:
                        continue
                    seen_events.add(event['id'])
                    tags = event.get("tags", [])
                    file_name, file_extension = "downloaded", "bin"
                    encoding = None
                    for tag in tags:
                        if tag[0] == "name":
                            file_name = tag[1]
                        elif tag[0] == "extension":
                            file_extension = tag[1]
                        elif tag[0] == "encode":
                            encoding = tag[1]
                    content = event.get("content", "")
                    try:
                        if encoding == "base64":
                            decoded_content = base64.b64decode(content)
                            output_file = f"{file_name}.{file_extension}"
                            with open(output_file, "wb") as file:
                                file.write(decoded_content)
                            print(f"[Relay: {relay_url}] File saved as '{output_file}'.")
                        else:
                            print(f"[Relay: {relay_url}] encode tag is not base64 or not found. (Event ID: {event['id']})")
                    except Exception as e:
                        print(f"[Relay: {relay_url}] Could not decode file content. Error: {e}")
    except Exception:
        pass

def npub_to_pubkey(npub):
    hrp, data = bech32_decode(npub)
    if hrp != 'npub' or data is None:
        return None
    pubkey_bytes = convertbits(data, 5, 8, False)
    if pubkey_bytes is None:
        return None
    return ''.join([f"{byte:02x}" for byte in pubkey_bytes])

def pubkey_to_npub(pubkey):
    if len(pubkey) != 64:
        return None
    pubkey_bytes = bytes.fromhex(pubkey)
    data = convertbits(pubkey_bytes, 8, 5)
    if data is None:
        return None
    return bech32_encode('npub', data)

async def fetch_profile_and_files_from_relay(relay_url, pubkey):
    events = []
    try:
        async with websockets.connect(relay_url) as websocket:
            sub_request = ["REQ", "sub_id", {"kinds": [0, 666], "authors": [pubkey]}]
            await websocket.send(json.dumps(sub_request))
            while True:
                response = await websocket.recv()
                data = json.loads(response)
                if data[0] == "EOSE":
                    break
                if data[0] == "EVENT":
                    event = data[2]
                    events.append(event)
    except:
        pass
    return events

async def fetch_profile_and_files(pubkey):
    global seen_events
    seen_events = set()
    tasks = [fetch_profile_and_files_from_relay(relay, pubkey) for relay in RELAY_URLS]
    all_results = await asyncio.gather(*tasks, return_exceptions=True)
    combined_events = []
    for result in all_results:
        if isinstance(result, list):
            combined_events.extend(result)
    unique_events = {}
    for e in combined_events:
        if e["id"] not in unique_events:
            unique_events[e["id"]] = e
    final_events = list(unique_events.values())
    profile_events = [ev for ev in final_events if ev.get("kind") == 0]
    file_events = [ev for ev in final_events if ev.get("kind") == 666]
    if profile_events:
        profile_events.sort(key=lambda x: x["created_at"], reverse=True)
        latest_profile = profile_events[0]
    else:
        latest_profile = None
    return latest_profile, file_events

async def view_profile(npub):
    pubkey = npub_to_pubkey(npub)
    if not pubkey:
        print("Invalid npub.")
        return
    latest_profile, file_events = await fetch_profile_and_files(pubkey)
    profile_data = {}
    if latest_profile:
        content_str = latest_profile.get("content", "")
        try:
            profile_data = json.loads(content_str)
        except:
            pass
    name = profile_data.get("name", "")
    picture = profile_data.get("picture", "")
    banner = profile_data.get("banner", "")
    nip05 = profile_data.get("nip05", "")
    lud16 = profile_data.get("lud16", "")
    file_list = []
    for f_event in file_events:
        tags = f_event.get("tags", [])
        f_name, f_ext, encoding = None, None, None
        for tag in tags:
            if tag[0] == "name":
                f_name = tag[1]
            elif tag[0] == "extension":
                f_ext = tag[1]
            elif tag[0] == "encode":
                encoding = tag[1]
        if f_name and f_ext:
            file_list.append((f_name, f_ext, encoding))
    print("\nUser Profile")
    print(f"name: {name}")
    print(f"profile picture: {picture}")
    print(f"banner: {banner}")
    print(f"nip05: {nip05}")
    print(f"lightning address: {lud16}")
    print("\nFiles uploaded:")
    if file_list:
        for file_item in file_list:
            file_name, file_ext, file_enc = file_item
            if file_enc:
                print(f"{file_name}.{file_ext} (Encoding: {file_enc})")
            else:
                print(f"{file_name}.{file_ext} (Encoding not found)")
    else:
        print("No files uploaded yet.")

async def general_search():
    global seen_events
    seen_events = set()
    tasks = []
    for relay in RELAY_URLS:
        tasks.append(general_search_on_relay(relay))
    await asyncio.gather(*tasks, return_exceptions=True)

async def general_search_on_relay(relay_url):
    try:
        async with websockets.connect(relay_url) as websocket:
            sub_request = ["REQ", "sub_id", {"kinds": [666]}]
            await websocket.send(json.dumps(sub_request))
            while True:
                response = await websocket.recv()
                event_data = json.loads(response)
                if event_data[0] == "EOSE":
                    break
                if event_data[0] == "EVENT":
                    event = event_data[2]
                    if event['id'] in seen_events:
                        continue
                    seen_events.add(event['id'])
                    pubkey = event.get("pubkey", "")
                    tags = event.get("tags", [])
                    file_name, file_extension = None, None
                    encoding = None
                    for tag in tags:
                        if tag[0] == "name":
                            file_name = tag[1]
                        elif tag[0] == "extension":
                            file_extension = tag[1]
                        elif tag[0] == "encode":
                            encoding = tag[1]
                    npub = pubkey_to_npub(pubkey)
                    if file_name and file_extension:
                        print(f"npub: {npub}")
                        print(f"File: {file_name}.{file_extension}")
                        if encoding:
                            print(f"Encoding: {encoding}")
                        print(f"Event ID: {event['id']}\n")
                    else:
                        print(f"npub: {npub}")
                        print(f"No file tags found (Event ID: {event['id']})\n")
    except:
        pass

async def fetch_event_by_id_from_relay(relay_url, event_id):
    events = []
    try:
        async with websockets.connect(relay_url) as websocket:
            sub_request = ["REQ", "sub_id", {"ids": [event_id]}]
            await websocket.send(json.dumps(sub_request))
            while True:
                response = await websocket.recv()
                data = json.loads(response)
                if data[0] == "EOSE":
                    break
                if data[0] == "EVENT":
                    event = data[2]
                    events.append(event)
    except:
        pass
    return events

async def fetch_event_by_id(event_id):
    tasks = []
    for relay in RELAY_URLS:
        tasks.append(fetch_event_by_id_from_relay(relay, event_id))
    results = await asyncio.gather(*tasks, return_exceptions=True)
    all_events = []
    for r in results:
        if isinstance(r, list):
            all_events.extend(r)
    unique_events = {}
    for e in all_events:
        if e["id"] not in unique_events:
            unique_events[e["id"]] = e
    if event_id in unique_events:
        return unique_events[event_id]
    return None

async def query_event_id():
    event_id = input("Enter the Event ID to query: ").strip()
    event = await fetch_event_by_id(event_id)
    if not event:
        print("Event not found on any relay.")
        return
    if event.get("kind") != 666:
        print("This event is not of kind 666.")
        return
    tags = event.get("tags", [])
    file_name, file_extension = "unknown", "bin"
    encoding = None
    for tag in tags:
        if tag[0] == "name":
            file_name = tag[1]
        elif tag[0] == "extension":
            file_extension = tag[1]
        elif tag[0] == "encode":
            encoding = tag[1]
    print(f"Found event of kind 666. File: {file_name}.{file_extension}")
    if encoding:
        print(f"Encoding: {encoding}")
    choice = input("Do you want to download this file? (y/n): ").strip().lower()
    if choice == 'y':
        await download_file(event_id)

async def main_menu():
    while True:
        print("\nWelcome to Shut")
        print("1. View Profile")
        print("2. General Search for Kind 666 Events")
        print("3. Request to Delete Event")
        print("4. Upload File")
        print("5. Download File")
        print("6. Fetch Event by ID")
        print("7. Exit")
        choice = input("Enter your choice (1-7): ").strip()
        if choice == '1':
            npub = input("Enter npub to view the profile: ").strip()
            await view_profile(npub)
        elif choice == '2':
            await general_search()
        elif choice == '3':
            event_ids = input("Enter the event IDs to delete, separated by commas: ").strip().split(',')
            reason = input("Enter the reason for deletion: ").strip() or "Deletion request"
            await delete_events(event_ids, reason)
        elif choice == '4':
            file_path = input("Enter the full path of the file to be uploaded: ").strip()
            await upload_file(file_path)
        elif choice == '5':
            event_id = input("Enter the Event ID to download the file: ").strip()
            await download_file(event_id)
        elif choice == '7':
            print("Exiting the application.")
            sys.exit()
        elif choice == '6':
            await query_event_id()
        else:
            print("Invalid choice. Please enter a number between 1 and 7.")

async def main():
    get_nsec_from_user()
    await main_menu()

if __name__ == "__main__":
    asyncio.run(main())
