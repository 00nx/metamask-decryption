# MetaMask Decrypt CLI

A local Node.js command-line tool for recovering and decrypting MetaMask vault data from supported Chrome, Chromium, Microsoft Edge, and Brave profiles.

> **Use only on wallets and devices you own or are explicitly authorized to recover.** Decrypted output may contain wallet recovery phrases and other highly sensitive data.

## Features

- **Automatic profile discovery** — checks supported browser profiles, not just `Default`.
- **Password-list support** — accepts one password or a text file of candidate passwords.
- **Concurrent processing** — uses Node.js worker threads to process vaults and password attempts in parallel.
- **MetaMask-compatible cryptography** — uses PBKDF2-HMAC-SHA-256 and AES-256-GCM through Node's built-in crypto module.
- **Useful output by default** — a verbose mode is available for troubleshooting.
- **No third-party runtime dependencies** — requires Node.js 20 or newer.

## Requirements

- [Node.js 20+](https://nodejs.org/) (includes `npm`)
- Git, if cloning the repository

Check your installation:

```bash
node --version
npm --version
```

The Node.js version should be `v20.0.0` or newer.

## Installation

### Option 1: Clone with Git

Replace the example repository URL with this project's actual GitHub URL.

```bash
git clone https://github.com/00nx/metamask-decryption/.git
cd metamask-decryption
npm i
```

### Option 2: Download the ZIP

1. Open the repository page on GitHub.
2. Select **Code → Download ZIP**.
3. Extract the ZIP archive.
4. Open a terminal in the extracted project folder and run:

```bash
npm i
```

This project uses Node.js built-in modules and does not currently declare external runtime dependencies; `npm i` is still a convenient setup step.

## Quick start

### 1. Prepare your password input

By default, the CLI reads candidate passwords from a `passwords.txt` file in the project directory. Put **one password per line**:

```text
# Lines beginning with # are comments
first candidate password
another candidate password
```

Blank lines and lines beginning with `#` are ignored. Keep this file private and do not commit it to a public repository.

### 2. Start the scan

```bash
npm run start
```

With no path specified, the CLI searches the supported browser profile locations on the current machine and uses `passwords.txt` as its password list.

### 3. Run with verbose diagnostics

```bash
npm run verbose
```

Verbose mode includes profile locations, source files, attempt counts, and full keyring data. The project currently defines `verbose` rather than a `debug` npm script.

## Usage examples

Run these commands from the project directory.

```bash
# Scan supported browser profiles using ./passwords.txt
npm run start

# Try one password against discovered profiles
npm run start -- "your-password"

# Use a password-list file against discovered profiles
npm run start -- "passwords.txt"

# Search one browser's User Data directory (Windows example)
node src/cli.js "passwords.txt" "C:\Users\YOUR_USER\AppData\Local\Google\Chrome\User Data"

# Read one vault/storage file
node src/cli.js "your-password" "./000003.log"

# Print only recovered mnemonic phrases
node src/cli.js "your-password" --mnemonic-only

# Save results to a JSON file
node src/cli.js "passwords.txt" --output results.json

# Print full diagnostic output
npm run verbose
```

**Important:** `npm run start` with no arguments expects `passwords.txt` to exist. To provide a single password directly, pass it after `--`, as shown above.

## Command-line options

| Option | Description |
| --- | --- |
| `-p, --password <value>` | Use one password candidate. |
| `-P, --passwords <file>` | Read candidates from a password-list file. |
| `-f, --file <path>` | Specify a vault file, profile directory, or browser `User Data` directory. |
| `-w, --workers <number>` | Set the worker count. Defaults to an automatic value based on available CPU cores. |
| `-o, --output <file>` | Write successful results to a JSON file. |
| `-v, --verbose` | Show profile paths, source files, attempts, and full keyrings. |
| `--mnemonic-only` | Print only mnemonic phrases. |
| `--json` | Print the full results as JSON. |
| `-h, --help` | Show help. |
| `-V, --version` | Show the installed project version. |

You can also run `node src/cli.js --help` to see the CLI's built-in usage information.

## How decryption works

MetaMask stores wallet keyring data in an encrypted **vault**. This project locates the relevant extension storage in supported browser profiles, then extracts vault fields such as the encrypted `data`, initialization vector (`iv`), salt, and—when available—key-derivation metadata.

For each candidate password, the program derives a 256-bit key with **PBKDF2-HMAC-SHA-256**, using the vault's salt and iteration count. If the vault does not specify iteration metadata, the code falls back to the legacy value of 10,000 iterations. It then uses **AES-256-GCM** with the vault's IV to decrypt the payload. The GCM authentication tag is verified during decryption, so a wrong password or altered ciphertext fails authentication rather than producing valid keyring data.

When decryption succeeds, the plaintext is parsed as JSON and the keyring structures are returned. The CLI can display selected fields or write the results to JSON. Password checks are distributed across Node.js worker threads, and processing for a profile stops once that profile is successfully decrypted. The tool also handles several storage layouts encountered while extracting vault data from browser LevelDB `.log` and `.ldb` files.

## Library API

The implementation can also be imported from JavaScript as an ES module:

```js
import {
  loadVaults,
  loadPasswords,
  crackAll,
  decryptVault,
  extractVault,
} from './src/index.js'

const vaults = loadVaults().filter((item) => item.vault)
const { passwords } = loadPasswords('passwords.txt')
const results = await crackAll(vaults, passwords)

console.log(results.map((result) => ({
  profile: result.profile,
  decrypted: Boolean(result.keyrings),
})))
```

## Security and privacy

- The tool performs its vault-processing logic locally and does not need to send vaults or passwords to a remote service.
- Successful output can expose wallet recovery phrases, keyring contents, and password candidates. Treat terminal output and generated JSON files as secrets.
- Do not upload vault files, password lists, or decrypted results to issue trackers, chats, or public repositories.
- Use the tool only for wallets you own or have clear authorization to recover. A successful decryption gives access to sensitive wallet material; store or dispose of recovered data securely.

## Troubleshooting

- **`Password file not found`** — create `passwords.txt` in the project folder or provide a password/list file explicitly.
- **No profiles found** — confirm MetaMask is installed in a supported browser profile, or pass the relevant profile directory or vault file path.
- **No password match** — check that the candidate password list is correct and that the selected vault file belongs to the intended wallet.
- **Unknown option / argument parsing issues** — run `node src/cli.js --help` and pass npm script arguments after `--`.

## License

ISC. See the `LICENSE` file in the repository, if present.
