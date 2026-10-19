import { parentPort } from 'node:worker_threads'
import { tryDecrypt } from './index.js'

let vaults = null

parentPort.on('message', (message) => {
  if (message.type === 'init') {
    vaults = message.vaults
    return
  }

  parentPort.postMessage({
    keyrings: tryDecrypt(message.password, vaults[message.id]),
  })
})
