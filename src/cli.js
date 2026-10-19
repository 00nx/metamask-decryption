
import fs from 'node:fs'
import path from 'node:path'
import {
  loadVaults,
  loadPasswords,
  crackAll,
  defaultWorkers,
  extractMnemonic,
} from './index.js'

const VERSION = JSON.parse(
  fs.readFileSync(new URL('../package.json', import.meta.url), 'utf8')
).version

const color = process.stdout.isTTY && !process.env.NO_COLOR
const paint = (code, text) => (color ? `\x1b[${code}m${text}\x1b[0m` : text)
const bold = (text) => paint(1, text)
const dim = (text) => paint(2, text)
const red = (text) => paint(31, text)
const green = (text) => paint(32, text)
const yellow = (text) => paint(33, text)
const cyan = (text) => paint(36, text)

function usage(code = 0) {
  const out = code === 0 ? console.log : console.error
  out(`
metamask-decrypt v${VERSION}

  Decrypt MetaMask vaults from all Chrome/Chromium/Edge/Brave profiles.

Usage
  node src/cli.js [password] [path]
  npm run start -- [password] [path]
  npm run verbose

Arguments
  password          Single password, password list file, or omitted (passwords.txt)
  path              Vault file, profile dir, or browser "User Data" dir

Flags
  -p, --password <str>     Force a single password
  -P, --passwords <file>   Force a password list file
  -f, --file <path>        Vault file or directory
  -w, --workers <n>        Total worker count (default: auto)
  -o, --output <path>      Write decrypted results as JSON
  -v, --verbose            Show every profile, path, and full keyrings
      --mnemonic-only      Print only mnemonics (one per line)
      --json               Print full results as JSON
  -h, --help               Help
  -V, --version            Version

Examples
  npm run start -- "my-password"
  npm run start -- passwords.txt
  npm run verbose
`)
  process.exit(code)
}

function parseArgs(argv) {
  const args = {
    passwordInput: null,
    passwordSingle: false,
    passwordList: false,
    vaultPath: null,
    workers: undefined,
    output: null,
    mnemonicOnly: false,
    json: false,
    verbose: false,
  }
  const positional = []

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]
    if (arg === '-h' || arg === '--help') usage(0)
    else if (arg === '-V' || arg === '--version') {
      console.log(VERSION)
      process.exit(0)
    } else if (arg === '-p' || arg === '--password') {
      args.passwordInput = argv[++i]
      args.passwordSingle = true
    } else if (arg === '-P' || arg === '--passwords') {
      args.passwordInput = argv[++i]
      args.passwordList = true
    } else if (arg === '-f' || arg === '--file') {
      args.vaultPath = argv[++i]
    } else if (arg === '-w' || arg === '--workers') {
      args.workers = Number(argv[++i])
    } else if (arg === '-o' || arg === '--output') {
      args.output = argv[++i]
    } else if (arg === '-v' || arg === '--verbose') {
      args.verbose = true
    } else if (arg === '--mnemonic-only') {
      args.mnemonicOnly = true
    } else if (arg === '--json') {
      args.json = true
    } else if (arg.startsWith('-')) {
      throw new Error(`Unknown option: ${arg}`)
    } else {
      positional.push(arg)
    }
  }

  if (args.passwordInput == null) {
    if (positional[0] != null) args.passwordInput = positional[0]
    if (args.vaultPath == null && positional[1] != null) {
      args.vaultPath = positional[1]
    }
  } else if (args.vaultPath == null && positional[0] != null) {
    args.vaultPath = positional[0]
  }

  return args
}

function label(vault) {
  return [vault.browser, vault.profile].filter(Boolean).join(' / ')
}

function countAccounts(keyrings) {
  let total = 0
  let found = false

  for (const keyring of keyrings) {
    if (Array.isArray(keyring?.data?.accounts)) {
      total += keyring.data.accounts.length
      found = true
    } else if (Number.isFinite(keyring?.data?.numberOfAccounts)) {
      total += keyring.data.numberOfAccounts
      found = true
    }
  }

  return found ? total : null
}

function resultJson(results) {
  return results.map(
    ({ browser, profile, source, password, attempts, keyrings }) => ({
      browser,
      profile,
      source,
      password,
      attempts,
      keyrings,
    })
  )
}

function printMinimal(result, say) {
  say(`${green('✔')} ${bold(label(result))}`)

  if (result.password) say(`  ${cyan('password')}  ${result.password}`)

  for (const keyring of result.keyrings) {
    if (keyring?.data?.mnemonic != null) {
      say(`  ${cyan('mnemonic')}  ${keyring.data.mnemonic}`)
    }
  }

  const accounts = countAccounts(result.keyrings)
  if (accounts != null && accounts > 0) {
    say(`  ${cyan('accounts')}  ${accounts}`)
  }

  say('')
}

function printVerbose(result, say) {
  say(`${green('✔')} ${bold(label(result))}`)
  say(`  ${cyan('dir')}       ${result.dir}`)
  say(`  ${cyan('source')}    ${result.source}`)
  if (result.password) say(`  ${cyan('password')}  ${result.password}`)
  say(`  ${cyan('attempts')}  ${result.attempts}`)
  say(`  ${cyan('keyrings')}`)
  for (const line of JSON.stringify(result.keyrings, null, 2).split('\n')) {
    say(`    ${line}`)
  }
  say('')
}

function printResults(results, args, say) {
  if (args.mnemonicOnly) {
    for (const result of results) {
      const mnemonic = extractMnemonic(result.keyrings)
      if (mnemonic) console.log(mnemonic)
    }
    return
  }

  if (args.json) {
    console.log(JSON.stringify(resultJson(results), null, 2))
    return
  }

  for (const result of results) {
    if (args.verbose) printVerbose(result, say)
    else printMinimal(result, say)
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2))
  const quiet = args.json || args.mnemonicOnly
  const say = quiet ? console.error : console.log

  const passwords = args.passwordSingle
    ? { passwords: [args.passwordInput], source: 'cli', single: true }
    : loadPasswords(args.passwordInput, { list: args.passwordList })
  if (!passwords.passwords.length || passwords.passwords[0] == null) {
    throw new Error('No password provided')
  }

  const discovered = loadVaults(args.vaultPath)
  if (!discovered.length) {
    throw new Error(
      'No MetaMask profiles found. Pass a profile or vault path as the second argument.'
    )
  }

  const vaults = discovered.filter((item) => item.vault)
  if (args.verbose && !quiet) {
    say(`${bold('Discovered')} ${discovered.length} profile${discovered.length === 1 ? '' : 's'}`)
    for (const item of discovered) {
      say(`  ${label(item)}${item.vault ? '' : dim('  (no vault)')}`)
      say(`    ${item.dir}`)
      if (item.source) say(`    ${item.source}`)
    }
    say('')
    say(
      `${bold('Passwords')} ${passwords.passwords.length} (${passwords.single ? 'cli' : path.basename(passwords.source)})`
    )
    say(
      `${bold('Workers')}   ${args.workers > 0 ? args.workers : defaultWorkers()}`
    )
    say('')
  }

  if (!vaults.length) {
    say(yellow('No MetaMask vaults found.'))
    for (const item of discovered) {
      say(`  ${dim('–')} ${label(item)}  ${dim('no vault')}`)
    }
    process.exitCode = 1
    return
  }

  const showProgress = process.stderr.isTTY && !quiet
  const started = Date.now()

  const results = await crackAll(vaults, passwords.passwords, {
    workers: args.workers,
    onProgress: showProgress
      ? (done, total) => {
          process.stderr.write(`\rTrying passwords ${done}/${total}`)
        }
      : undefined,
  })

  if (showProgress) process.stderr.write('\r' + ' '.repeat(32) + '\r')

  const byDir = new Map(results.map((result) => [result.dir, result]))

  for (const item of discovered) {
    if (byDir.has(item.dir)) continue

    if (!item.vault) {
      if (!args.verbose && !quiet) {
        say(`${dim('–')} ${label(item)}  ${dim('no vault')}`)
      }
    } else {
      say(`${red('✘')} ${label(item)}  ${yellow('no match')}`)
    }
  }

  if (args.output) {
    const outPath = path.resolve(args.output)
    fs.writeFileSync(outPath, JSON.stringify(resultJson(results), null, 2))
    say(dim(`Wrote ${outPath}`))
  }

  printResults(results, args, say)

  const seconds = ((Date.now() - started) / 1000).toFixed(2)
  say(
    dim(
      `Decrypted ${results.length}/${vaults.length} vault${vaults.length === 1 ? '' : 's'} in ${seconds}s`
    )
  )
}

main().catch((error) => {
  console.error(error?.message ?? String(error))
  process.exit(1)
})
