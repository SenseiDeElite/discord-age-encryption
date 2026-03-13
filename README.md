# Discord Age Encryption

A browser extension that adds end-to-end encrypted messaging to Discord direct messages. Messages are encrypted on your device before being sent — Discord's servers only ever see ciphertext.

> **Status:** v0.1.0 — personal/experimental use. Not audited.

---

## Features

- 🔒 **End-to-end encrypted** — only you and your contact can read messages;
- ✍️ **Signed messages** — every message is cryptographically signed, preventing tampering;
- 🔑 **Your keys, your device** — private keys never leave your machine;
- 🔐 **Passphrase protected** — your private key is encrypted at rest, unlocked per session;
- 👁️ **Works inside Discord** — no separate app, messages appear inline with a 🔒 badge.

---

## Cryptography

Encryption uses **[age](https://github.com/FiloSottile/typage)** (X25519 key agreement + ChaCha20-Poly1305), a modern and well-audited encryption format. Each message is also signed with an **Ed25519** signature, which guarantees that a message could only have been sent by the person who owns that keypair — any tampering or forgery is flagged immediately.

Your private key is stored encrypted on your device using age's scrypt passphrase protection. It is never uploaded anywhere.

**Wire format**

Encrypted messages are sent as plain text inside the Discord message box, prefixed with `[age]` so the extension can identify them. Each message embeds a short random ID, the encrypted ciphertext, and an Ed25519 signature — all in a single self-contained string. The recipient's extension decrypts and verifies the message inline, replacing the raw ciphertext with the plaintext and a 🔒 badge. Messages are encrypted to both the recipient and the sender, so both parties can read the conversation.

**Key fingerprints**

Each contact's public key is displayed as a BLAKE2b-512 fingerprint (powered by [noble hashes](https://github.com/paulmillr/noble-hashes)). You can verify a contact's key out-of-band by comparing fingerprints with them directly, or by computing the checksum yourself:

**Linux**

```bash
printf '%s' "age1…" | b2sum | awk '{s=toupper($1); for(i=1;i<=length(s);i+=4) printf "%s%s", substr(s,i,4), (i+3)%32==0 ? "\n" : " "; print ""}'
```

**Cross-platform (Python)**

```python
python3 -c "
import hashlib, sys
h = hashlib.blake2b(sys.argv[1].encode(), digest_size=64).hexdigest().upper()
rows = [' '.join(h[i:i+4] for i in range(j, j+32, 4)) for j in range(0, len(h), 32)]
print('\n'.join(rows))
" "age1…"
```

**Limitations**

> ⚠️ **No forward secrecy.** If your private key is ever compromised, past messages encrypted to it could be read. Keep your passphrase strong and your private key export safe.

> ⚠️ **Not post-quantum secure.** The algorithms used (X25519, Ed25519, ChaCha20-Poly1305) are not resistant to attacks from a sufficiently powerful quantum computer. A future quantum adversary that recorded your encrypted messages today could potentially decrypt them later. age does support post-quantum algorithms, but the resulting ciphertext is so large that even a single-character message exceeds Discord's 2000 character limit, making it impractical for this use case.

---

## Installation

## Chromium

1. Clone or manually download this repository: `git clone https://github.com/SenseiDeElite/discord-age-encryption.git`
3. Open Chromium and navigate to `chrome://extensions`
4. Enable **Developer mode** (toggle in the top right)
5. Click **Load unpacked** and select the repository folder

---

## Getting started

**First time setup**

1. Click the extension icon in your toolbar
2. Choose a strong passphrase (at least 20 characters, mixed case, numbers, and symbols)
3. Click **Generate keypair** — your keys are created and stored locally
4. Click **My public key** (🔑) and copy it to share with your contact

**Adding a contact**

1. Open the direct message with your contact in Discord
2. Click **Add contact** in the extension
3. Paste their public key and give them a name — the channel ID fills in automatically if you're already in the direct message.
4. Click **Save contact**

Both sides need to have added each other before encrypted messaging works.

**Sending messages**

Once a contact is added and enabled, just type and press **Enter** as normal — the extension intercepts the message, encrypts it, and sends it. Received encrypted messages are decrypted and shown inline with a 🔒 badge.

---

## Key management

- **Lock** (🔒) — clears the session. Your key stays saved but you'll need your passphrase to unlock again next session.
- **Export private key** — requires passphrase re-entry. Save the exported blob somewhere safe (a password manager or encrypted vault). Anyone who has it can read your messages and impersonate you.
- **Regenerate keypair** — creates a new keypair. All previous encrypted messages become permanently unreadable and all contacts are disabled. Use only if your key is compromised.

---

## License

GNU General Public License v3.0 — see `LICENSE`.

See `THIRD_PARTY_NOTICES` for full third-party license texts.

This extension is not affiliated with or endorsed by Discord Inc.
