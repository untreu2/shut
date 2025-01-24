# shut
Shut enables file storage and transmission on Nostr relays using the kind 666 event structure. Shut is the first client to use kind 666. For now there is only a CLI version of Shut. It will soon be available on the web.
![shut](https://m.primal.net/NyYO.jpg)

## kind 666
kind 666 is a custom event type used for file storage and transmission.It allows users to store encoded files along with metadata such as file name, extension, and encoding type.

**A typical kind 666 event includes:**

id: Unique event ID (SHA256 hash)

pubkey: Event creator's public key

created_at: Timestamp of event creation

kind: 666

tags: Metadata such as name, extension, encoding.

content: Encoded file.

sig: Cryptographic signature for verification.


## Example
```
{
    "id": "abc123eventid",
    "pubkey": "b59f7b6a2d6...",
    "created_at": 1706000000,
    "kind": 666,
    "tags": [
        ["name", "document"],
        ["extension", "pdf"],
        ["encode", "base64"]
    ],
    "content": "BTC21MCHILL=",
    "sig": "3045022100e5b9..."
}
```