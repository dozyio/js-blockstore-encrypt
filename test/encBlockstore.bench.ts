import crypto from 'crypto'
import fs from 'fs'
import os from 'os'
import path from 'path'
import { FsBlockstore } from 'blockstore-fs'
import { CID } from 'multiformats/cid'
import { bench, beforeAll, afterAll } from 'vitest'
import { EncBlockstore } from '../src/index.js'

const sampleData = crypto.randomBytes(1024 * 1024) // 1MB of random data
const password = 'strong-password-is-strong'
const masterSalt = crypto.randomBytes(16)
const testCid = CID.parse('bafkreigh2akiscaildc6en5ynpwp45fucjk64o4uqa5fmsrzc4i4vqveae')

let tempDirUnencrypted: string
let tempDirEncrypted: string
let fsBlockstore: FsBlockstore
let fsBlockstoreEnc: FsBlockstore
let encBlockstore: EncBlockstore

beforeAll(async () => {
  // Create separate temporary directories
  tempDirUnencrypted = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'fs-blockstore-unenc-'))

  tempDirEncrypted = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'fs-blockstore-enc-'))

  // Initialize FsBlockstore for unencrypted tests
  fsBlockstore = new FsBlockstore(tempDirUnencrypted)

  // Initialize FsBlockstore for encrypted tests
  fsBlockstoreEnc = new FsBlockstore(tempDirEncrypted)
  encBlockstore = new EncBlockstore(fsBlockstoreEnc)

  // Initialize EncBlockstore
  await encBlockstore.init(password, masterSalt)
  await encBlockstore.open()

  // Seed data into the unencrypted FsBlockstore
  await fsBlockstore.put(testCid, sampleData)

  // Seed data into the encrypted EncBlockstore
  await encBlockstore.put(testCid, sampleData)
})

afterAll(async () => {
  try {
    await encBlockstore.close()
    await fsBlockstoreEnc.close()
    await fsBlockstore.close()
  } finally {
    if (tempDirUnencrypted !== '') {
      await fs.promises.rm(tempDirUnencrypted, { recursive: true, force: true })
    }
    if (tempDirEncrypted !== '') {
      await fs.promises.rm(tempDirEncrypted, { recursive: true, force: true })
    }
  }
})

bench('EncBlockstore#put', async () => {
  await encBlockstore.put(testCid, sampleData)
}, { time: 5000 })

bench('EncBlockstore#get', async () => {
  await encBlockstore.get(testCid)
}, { time: 5000 })

bench('FsBlockstore#put', async () => {
  await fsBlockstore.put(testCid, sampleData)
}, { time: 5000 })

bench('FsBlockstore#get', async () => {
  await fsBlockstore.get(testCid)
}, { time: 5000 })
