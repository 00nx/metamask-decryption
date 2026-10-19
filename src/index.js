/**
 * MetaMask vault toolkit: extract, decrypt, discover browser profiles, and
 * crack passwords across every profile with a worker pool.
 */

import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { createDecipheriv, pbkdf2Sync } from 'node:crypto'
import { Worker } from 'node:worker_threads'

export const METAMASK_EXT_ID = 'nkbihfbeogaeaoehlefnkodbefgpgknn'
export const LEGACY_ITERATIONS = 10_000

const KEY_LEN = 32
const GCM_TAG_LEN = 16
const MAX_WORKERS = 32
const WORKER_URL = new URL('./worker.js', import.meta.url)
const GENERIC = Symbol('generic')

/* ── decryption ─────────────────────────────────────────────────────────── */

export function isVault(vault) {
  return (
    vault != null &&
    typeof vault === 'object' &&
    ['data', 'iv', 'salt'].every((key) => typeof vault[key] === 'string')
  )
}

export function isCleartext(vault) {
  return Boolean(vault?.data?.mnemonic)
}

export function getIterations(vault) {
  const n = vault?.keyMetadata?.params?.iterations
  return Number.isFinite(n) && n > 0 ? n : LEGACY_ITERATIONS
}

/** Decrypt a vault. Throws on a wrong password or malformed payload. */
export function decryptVault(password, vault) {
  if (isCleartext(vault)) return [vault]

  const data = Buffer.from(vault.data, 'base64')
  if (data.length <= GCM_TAG_LEN) throw new Error('Invalid vault ciphertext')

  const key = pbkdf2Sync(
    password,
    Buffer.from(vault.salt, 'base64'),
    getIterations(vault),
    KEY_LEN,
    'sha256'
  )
  const tag = data.subarray(data.length - GCM_TAG_LEN)
  const body = data.subarray(0, data.length - GCM_TAG_LEN)

  let plain
  try {
    const decipher = createDecipheriv(
      'aes-256-gcm',
      key,
      Buffer.from(vault.iv, 'base64')
    )
    decipher.setAuthTag(tag)
    plain = Buffer.concat([decipher.update(body), decipher.final()])
  } catch {
    throw new Error('Incorrect password')
  }

  const keyrings = JSON.parse(plain.toString('utf8'))
  if (!Array.isArray(keyrings)) throw new Error('Unexpected decrypted payload')
  return keyrings.map((keyring) =>
    keyring?.data && 'mnemonic' in keyring.data
      ? {
          ...keyring,
          data: {
            ...keyring.data,
            mnemonic: decodeMnemonic(keyring.data.mnemonic),
          },
        }
      : keyring
  )
}

export function tryDecrypt(password, vault) {
  try {
    return decryptVault(password, vault)
  } catch {
    return null
  }
}

function decodeMnemonic(mnemonic) {
  return typeof mnemonic === 'string'
    ? mnemonic
    : Buffer.from(mnemonic).toString('utf8')
}

export function extractMnemonic(keyrings) {
  for (const keyring of keyrings ?? []) {
    if (keyring?.data?.mnemonic != null) {
      return decodeMnemonic(keyring.data.mnemonic)
    }
  }
  return null
}

/* ── vault extraction ───────────────────────────────────────────────────── */

export function extractVault(text) {
  const direct = parseJson(text)
  if (direct && (isVault(direct) || isCleartext(direct))) return direct

  const seed = text.match(/\{"wallet-seed":"([^"}]*)"\}/)
  if (seed) {
    const mnemonic = seed[1].replace(/\\n*/, '')
    const wallet = text.match(/"wallet":("{[ -~]*\\"version\\":2}")/)
    const extra = wallet ? parseJson(parseJson(wallet[1])) : null
    return { data: { mnemonic, ...(extra ?? {}) } }
  }

  const linux = text.match(/"KeyringController":\{"vault":("{[^{}]*}")/)
  if (linux) {
    const vault = parseJson(parseJson(linux[1]))
    if (vault) return vault
  }

  for (const regex of [
    /"KeyringController":(\{"vault":".*?=\\"\}"\})/,
    /"KeyringController":(\{.*?"vault":".*?=\\"\}"\})/,
  ]) {
    const match = text.match(regex)
    if (!match) continue
    try {
      return parseEscapedVault(match[1])
    } catch {
      // try the next format
    }
  }

  return extractWindowsVault(text) ?? extractGenericVault(text)
}

function parseEscapedVault(fragment) {
  const data = fragment.match(/\\"data\\":\\"([A-Za-z0-9+/=]*)/u)?.[1]
  const iv = fragment.match(/,\\"iv\\":\\"([A-Za-z0-9+/]{10,40}=*)/u)?.[1]
  const salt = fragment.match(/,\\"salt\\":\\"([A-Za-z0-9+/]{10,100}=*)\\"/u)?.[1]
  if (!data || !iv || !salt) throw new Error('Incomplete vault')

  const vault = { data, iv, salt }
  const metaAt = fragment.indexOf('keyMetadata')
  if (metaAt >= 0) {
    const open = fragment.indexOf('{', metaAt)
    const meta = open >= 0 ? findBalancedObject(fragment, open) : null
    if (meta) {
      const parsed = parseJson(meta.replaceAll('\\', ''))
      if (parsed) vault.keyMetadata = parsed
    }
  }
  return vault
}

function findBalancedObject(text, start) {
  let depth = 0
  for (let i = start; i < text.length; i++) {
    if (text[i] === '{') depth++
    else if (text[i] === '}' && --depth === 0) return text.slice(start, i + 1)
  }
  return null
}

function extractWindowsVault(text) {
  const fragmentRe = /Keyring[0-9][^}]*(\{[^{}]*\\"\})/gu
  const dataRe = /\\"[^":,is]*\\":\\"([A-Za-z0-9+/=]*)/u
  const ivRe = /\\"iv.{1,4}[^A-Za-z0-9+/]{1,10}([A-Za-z0-9+/]{10,40}=*)/u
  const saltRe = /,\\"salt.{1,4}[^A-Za-z0-9+/]{1,10}([A-Za-z0-9+/]{10,100}=*)/u

  for (const match of text.matchAll(fragmentRe)) {
    const body = match[1]
    const data = body.match(dataRe)?.[1]
    const iv = body.match(ivRe)?.[1]
    const salt = body.match(saltRe)?.[1]
    if (data && iv && salt) return { data, iv, salt }
  }

  const splitRe = /KeyringController[\s\S]*?"vault":"((?:[^"\\]|\\.)*)"/g
  for (const match of text.matchAll(splitRe)) {
    const inner = parseJson(`"${match[1]}"`)
    if (typeof inner !== 'string') continue
    const vault = parseJson(inner)
    if (isVault(vault)) return vault
  }

  return null
}

/**
 * Last resort: LevelDB block boundaries can split the "KeyringController"
 * prefix away from the vault body, so scan for the vault fragment itself.
 */
function extractGenericVault(text) {
  const windowSize = 200_000
  const maxTries = 200
  let fallback = null
  let at = text.indexOf('vault')

  for (let tries = 0; at >= 0 && tries < maxTries; tries++) {
    const open = text.indexOf('{', at)
    if (open < 0) break
    const window = text.slice(open, open + windowSize)

    let vault = null
    try {
      vault = parseEscapedVault(window)
    } catch {
      const json = findJsonObject(window, 0)
      if (json) vault = parseJson(json)
    }

    if (isVault(vault)) {
      Object.defineProperty(vault, GENERIC, { value: true })
      if (vault.keyMetadata) return vault
      fallback ??= vault
    }

    at = text.indexOf('vault', at + 5)
  }

  return fallback
}

function findJsonObject(text, start) {
  let depth = 0
  let inString = false
  let escaped = false

  for (let i = start; i < text.length; i++) {
    const char = text[i]
    if (inString) {
      if (escaped) escaped = false
      else if (char === '\\') escaped = true
      else if (char === '"') inString = false
      continue
    }
    if (char === '"') inString = true
    else if (char === '{') depth++
    else if (char === '}' && --depth === 0) return text.slice(start, i + 1)
  }
  return null
}

function parseJson(text) {
  try {
    return JSON.parse(text)
  } catch {
    return null
  }
}

/* ── browser profile discovery ──────────────────────────────────────────── */

export function browserRoots() {
  const home = os.homedir()
  const local = process.env.LOCALAPPDATA

  if (process.platform === 'win32') {
    if (!local) return []
    return [
      path.join(local, 'Google', 'Chrome', 'User Data'),
      path.join(local, 'Google', 'Chrome Beta', 'User Data'),
      path.join(local, 'Google', 'Chrome Dev', 'User Data'),
      path.join(local, 'Google', 'Chrome SxS', 'User Data'),
      path.join(local, 'Chromium', 'User Data'),
      path.join(local, 'Microsoft', 'Edge', 'User Data'),
      path.join(local, 'Microsoft', 'Edge Beta', 'User Data'),
      path.join(local, 'Microsoft', 'Edge Dev', 'User Data'),
      path.join(local, 'Microsoft', 'Edge SxS', 'User Data'),
      path.join(local, 'BraveSoftware', 'Brave-Browser', 'User Data'),
      path.join(local, 'BraveSoftware', 'Brave-Browser-Beta', 'User Data'),
      path.join(local, 'BraveSoftware', 'Brave-Browser-Nightly', 'User Data'),
    ]
  }

  if (process.platform === 'darwin') {
    const base = path.join(home, 'Library', 'Application Support')
    return [
      path.join(base, 'Google', 'Chrome'),
      path.join(base, 'Google', 'Chrome Beta'),
      path.join(base, 'Google', 'Chrome Dev'),
      path.join(base, 'Google', 'Chrome Canary'),
      path.join(base, 'Chromium'),
      path.join(base, 'Microsoft Edge'),
      path.join(base, 'Microsoft Edge Beta'),
      path.join(base, 'Microsoft Edge Dev'),
      path.join(base, 'Microsoft Edge Canary'),
      path.join(base, 'BraveSoftware', 'Brave-Browser'),
      path.join(base, 'BraveSoftware', 'Brave-Browser-Beta'),
      path.join(base, 'BraveSoftware', 'Brave-Browser-Nightly'),
    ]
  }

  const base = path.join(home, '.config')
  return [
    path.join(base, 'google-chrome'),
    path.join(base, 'google-chrome-beta'),
    path.join(base, 'google-chrome-unstable'),
    path.join(base, 'chromium'),
    path.join(base, 'microsoft-edge'),
    path.join(base, 'microsoft-edge-beta'),
    path.join(base, 'microsoft-edge-dev'),
    path.join(base, 'BraveSoftware', 'Brave-Browser'),
    path.join(base, 'BraveSoftware', 'Brave-Browser-Beta'),
    path.join(base, 'BraveSoftware', 'Brave-Browser-Nightly'),
  ]
}

/**
 * Find every MetaMask vault on the machine, across all browser profiles.
 * @returns {{ browser: string, profile: string, dir: string, source: string, vault: object }[]}
 */
export function loadVaults(input) {
  if (!input) return browserRoots().flatMap(discoverRoot)

  const resolved = path.resolve(input)
  const stat = statOrNull(resolved)
  if (!stat) throw new Error(`Path not found: ${resolved}`)

  if (stat.isFile()) {
    const vault = readVaultFile(resolved)
    if (!vault) throw new Error(`No MetaMask vault in ${resolved}`)
    return [
      {
        browser: null,
        profile: path.basename(resolved),
        dir: path.dirname(resolved),
        source: resolved,
        vault,
      },
    ]
  }

  const profiles = discoverRoot(resolved)
  if (profiles.length) return profiles

  const extDir = path.join(
    resolved,
    'Local Extension Settings',
    METAMASK_EXT_ID
  )
  const dir = isDir(extDir) ? extDir : resolved
  const found = readVaultDir(dir)
  if (!found) throw new Error(`No MetaMask vault in ${resolved}`)

  return [
    {
      browser: null,
      profile: path.basename(resolved),
      dir,
      source: found.source,
      vault: found.vault,
    },
  ]
}

function discoverRoot(root) {
  let entries
  try {
    entries = fs.readdirSync(root, { withFileTypes: true })
  } catch {
    return []
  }

  const found = []
  for (const entry of entries) {
    if (!entry.isDirectory()) continue
    const dir = path.join(
      root,
      entry.name,
      'Local Extension Settings',
      METAMASK_EXT_ID
    )
    if (!isDir(dir)) continue
    const vault = readVaultDir(dir)
    found.push({
      browser: browserName(root),
      profile: entry.name,
      dir,
      source: vault?.source ?? null,
      vault: vault?.vault ?? null,
    })
  }
  return found
}

function browserName(root) {
  const base = path.basename(root)
  return base === 'User Data' ? path.basename(path.dirname(root)) : base
}

function readVaultDir(dir) {
  const specific = []
  const generic = []

  for (const file of listVaultFiles(dir)) {
    const vault = readVaultFile(file)
    if (!vault) continue
    const entry = { vault, source: file }
    if (vault[GENERIC]) generic.push(entry)
    else specific.push(entry)
  }

  return pickVault(specific) ?? pickVault(generic)
}

function pickVault(entries) {
  return entries.find((entry) => entry.vault.keyMetadata) ?? entries[0] ?? null
}

function listVaultFiles(dir) {
  let entries
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true })
  } catch {
    return []
  }

  return entries
    .filter((entry) => entry.isFile() && /\.(log|ldb)$/i.test(entry.name))
    .map((entry) => {
      const file = path.join(dir, entry.name)
      const stat = statOrNull(file)
      return stat && stat.size > 0 ? { file, mtime: stat.mtimeMs } : null
    })
    .filter(Boolean)
    .sort((a, b) => b.mtime - a.mtime)
    .map((item) => item.file)
}

function readVaultFile(file) {
  try {
    const vault = extractVault(fs.readFileSync(file, 'utf8'))
    return vault && (isVault(vault) || isCleartext(vault)) ? vault : null
  } catch {
    return null
  }
}

/* ── passwords ──────────────────────────────────────────────────────────── */

/**
 * @param {string|null|undefined} input  password, file path, or nothing
 * @param {{ list?: boolean, cwd?: string }} [opts]
 * @returns {{ passwords: string[], source: string, single: boolean }}
 */
export function loadPasswords(input, opts = {}) {
  const cwd = opts.cwd ?? process.cwd()

  if (input == null || input === '') {
    return readPasswordFile(path.resolve(cwd, 'passwords.txt'))
  }

  if (opts.list) return readPasswordFile(path.resolve(cwd, input))

  const resolved = path.resolve(cwd, input)
  if (isFile(resolved)) return readPasswordFile(resolved)

  return { passwords: [input], source: 'cli', single: true }
}

function readPasswordFile(file) {
  if (!isFile(file)) throw new Error(`Password file not found: ${file}`)

  const passwords = [
    ...new Set(
      fs
        .readFileSync(file, 'utf8')
        .split(/\r?\n/)
        .map((line) => line.trim())
        .filter((line) => line.length > 0 && !line.startsWith('#'))
    ),
  ]

  if (!passwords.length) throw new Error(`Password file is empty: ${file}`)
  return { passwords, source: file, single: false }
}

/* ── concurrent cracking ────────────────────────────────────────────────── */

export function defaultWorkers() {
  const cores =
    typeof os.availableParallelism === 'function'
      ? os.availableParallelism()
      : os.cpus().length
  return Math.max(1, Math.min(cores - 1, MAX_WORKERS))
}

/**
 * Try every password against every vault. Tasks are interleaved by password so
 * all profiles progress concurrently. Workers stop as soon as a profile is
 * decrypted.
 *
 * @param {object[]} vaults
 * @param {string[]} passwords
 * @param {{ workers?: number, onProgress?: (done: number, total: number) => void }} [opts]
 * @returns {Promise<object[]>}
 */
export async function crackAll(vaults, passwords, opts = {}) {
  const list = [
    ...new Set(
      passwords.filter((password) => typeof password === 'string' && password)
    ),
  ]
  if (!list.length) throw new Error('No passwords to try')

  const results = new Map()
  const pending = []

  vaults.forEach((item, index) => {
    if (isCleartext(item.vault)) {
      results.set(index, {
        ...item,
        password: null,
        keyrings: [item.vault],
        attempts: 0,
      })
    } else if (isVault(item.vault)) {
      pending.push(index)
    }
  })

  if (!pending.length) {
    return vaults.map((_, index) => results.get(index)).filter(Boolean)
  }

  const solved = new Set()
  const attempts = new Map(pending.map((index) => [index, 0]))
  const total = list.length * pending.length
  let done = 0

  // Interleave by password so every profile progresses concurrently.
  const taskAt = (position) => ({
    index: pending[position % pending.length],
    password: list[Math.floor(position / pending.length)],
  })

  const record = (task, keyrings) => {
    const count = attempts.get(task.index) + 1
    attempts.set(task.index, count)
    if (!keyrings || solved.has(task.index)) return

    solved.add(task.index)
    results.set(task.index, {
      ...vaults[task.index],
      password: task.password,
      keyrings,
      attempts: count,
    })
  }

  const requested =
    Number.isInteger(opts.workers) && opts.workers > 0
      ? opts.workers
      : defaultWorkers()
  const workerCount = Math.max(1, Math.min(requested, total))

  if (workerCount === 1) {
    for (let position = 0; position < total; position++) {
      const task = taskAt(position)
      if (solved.has(task.index)) continue
      done++
      record(task, tryDecrypt(task.password, vaults[task.index].vault))
      opts.onProgress?.(done, total)
      if (solved.size === pending.length) break
    }
    return vaults.map((_, index) => results.get(index)).filter(Boolean)
  }

  const vaultMap = Object.fromEntries(
    pending.map((index) => [index, vaults[index].vault])
  )

  await new Promise((resolve, reject) => {
    const pool = []
    const busy = new Map()
    let next = 0
    let settled = false

    const finish = (error) => {
      if (settled) return
      settled = true
      for (const worker of pool) {
        worker.removeAllListeners()
        worker.terminate().catch(() => {})
      }
      error ? reject(error) : resolve()
    }

    const feed = (worker) => {
      while (next < total) {
        const task = taskAt(next++)
        if (solved.has(task.index)) continue
        busy.set(worker, task)
        worker.postMessage({
          type: 'try',
          id: task.index,
          password: task.password,
        })
        return
      }
    }

    const onMessage = (worker, message) => {
      if (settled) return
      const task = busy.get(worker)
      if (!task) return

      busy.delete(worker)
      done++
      record(task, message.keyrings)
      opts.onProgress?.(done, total)

      if (solved.size === pending.length) return finish()
      feed(worker)
      if (busy.size === 0) finish()
    }

    for (let i = 0; i < workerCount; i++) {
      let worker
      try {
        worker = new Worker(WORKER_URL)
      } catch (error) {
        finish(error)
        return
      }

      pool.push(worker)
      worker.on('message', (message) => onMessage(worker, message))
      worker.on('error', finish)
      worker.on('exit', (code) => {
        if (!settled && code !== 0) {
          finish(new Error(`Worker exited with code ${code}`))
        }
      })
      worker.postMessage({ type: 'init', vaults: vaultMap })
    }

    for (const worker of pool) feed(worker)
  })

  return vaults.map((_, index) => results.get(index)).filter(Boolean)
}

/* ── fs helpers ─────────────────────────────────────────────────────────── */

function statOrNull(file) {
  try {
    return fs.statSync(file)
  } catch {
    return null
  }
}

function isFile(file) {
  return statOrNull(file)?.isFile() ?? false
}

function isDir(file) {
  return statOrNull(file)?.isDirectory() ?? false
}
