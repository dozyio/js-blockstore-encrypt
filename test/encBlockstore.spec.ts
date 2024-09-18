// EncBlockstore.test.ts

import { CID } from 'multiformats/cid'
import * as raw from 'multiformats/codecs/raw'
import { sha256 } from 'multiformats/hashes/sha2'
import { describe, it, expect, beforeEach } from 'vitest'
import { EncBlockstore, type EncBlockstoreInit } from '../src/'
import { MockBlockstore } from './__mocks__/MockBlockstore'

/**
 * Generates a random CID using SHA-256 and the 'raw' codec.
 *
 * @returns A randomly generated CID.
 */
async function generateRandomCID (): Promise<CID> {
  const randomData = globalThis.crypto.getRandomValues(new Uint8Array(32))
  const hash = await sha256.digest(randomData)
  return CID.createV1(raw.code, hash)
}

describe('EncBlockstore', () => {
  let mockStore: MockBlockstore
  let encStore: EncBlockstore

  const password = '🔥strong-password🔥'
  const masterSalt = globalThis.crypto.getRandomValues(new Uint8Array(16)) // 128-bit salt

  beforeEach(async () => {
    mockStore = new MockBlockstore()
    const init: EncBlockstoreInit = {
      pbkdf2Iterations: 210000,
      pbkdf2hash: 'SHA-512',
      putManyConcurrency: 50,
      getManyConcurrency: 50,
      deleteManyConcurrency: 50
    }
    encStore = new EncBlockstore(mockStore, init)
    await encStore.init(password, masterSalt)
  })

  it('should put and get a single block correctly', async () => {
    const originalData = new TextEncoder().encode('Hello, World!')
    const cid = await generateRandomCID()

    await encStore.put(cid, originalData)

    const retrievedData = await encStore.get(cid)
    expect(retrievedData).toEqual(originalData)
  })

  it('should handle multiple puts and gets correctly', async () => {
    const dataMap = new Map<string, Uint8Array>()
    const cids: CID[] = []

    // Generate multiple CIDs and data
    for (let i = 0; i < 10; i++) {
      const data = new TextEncoder().encode(`Data block ${i}`)
      const cid = await generateRandomCID()
      cids.push(cid)
      dataMap.set(cid.toString(), data)
    }

    // Put all blocks
    for (const [cidStr, data] of dataMap.entries()) {
      const cid = CID.parse(cidStr)
      await encStore.put(cid, data)
    }

    // Get all blocks and verify
    for (const [cidStr, originalData] of dataMap.entries()) {
      const cid = CID.parse(cidStr)
      const retrievedData = await encStore.get(cid)
      expect(retrievedData).toEqual(originalData)
    }
  })

  it('should delete a block correctly', async () => {
    const data = new TextEncoder().encode('Block to delete')
    const cid = await generateRandomCID()

    await encStore.put(cid, data)
    expect(await encStore.has(cid)).toBe(true)

    await encStore.delete(cid)
    expect(await encStore.has(cid)).toBe(false)

    await expect(encStore.get(cid)).rejects.toThrow('Key not found')
  })

  it('should handle putMany and getMany correctly', async () => {
    const blocks: Array<{ cid: CID, block: Uint8Array }> = []

    // Create multiple blocks
    for (let i = 0; i < 20; i++) {
      const data = new TextEncoder().encode(`Bulk data ${i}`)
      const cid = await generateRandomCID()
      blocks.push({ cid, block: data })
    }

    // Put many blocks
    const putCids: CID[] = []
    for await (const cid of encStore.putMany(blocks.map(b => ({ cid: b.cid, block: b.block })))) {
      putCids.push(cid)
    }

    expect(putCids.length).toBe(blocks.length)

    // Get many blocks
    const getPairs: Array<{ cid: CID, block: Uint8Array }> = []
    for await (const pair of encStore.getMany(putCids)) {
      getPairs.push(pair)
    }

    expect(getPairs.length).toBe(blocks.length)

    // Verify all blocks
    for (let i = 0; i < blocks.length; i++) {
      expect(getPairs[i].cid.toString()).toBe(putCids[i].toString())
      expect(getPairs[i].block).toEqual(blocks[i].block)
    }
  })

  it('should handle deleteMany correctly', async () => {
    const blocks: Array<{ cid: CID, block: Uint8Array }> = []

    // Create multiple blocks
    for (let i = 0; i < 10; i++) {
      const data = new TextEncoder().encode(`Delete data ${i}`)
      const cid = await generateRandomCID()
      blocks.push({ cid, block: data })
    }

    // Put all blocks
    for (const { cid, block } of blocks) {
      await encStore.put(cid, block)
    }

    // Verify they exist
    for (const { cid } of blocks) {
      expect(await encStore.has(cid)).toBe(true)
    }

    // Delete many blocks
    const deleteCids = blocks.map((b) => b.cid)
    for await (const cid of encStore.deleteMany(deleteCids)) {
      expect(cid).toBeDefined()
    }

    // Verify deletion
    for (const { cid } of blocks) {
      expect(await encStore.has(cid)).toBe(false)
    }
  })

  it('should retrieve all blocks using getAll correctly', async () => {
    // Since getAll is not supported, expect it to throw an error
    await expect(async () => {
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      for await (const _ of encStore.getAll()) {
        // No-op
      }
    }).rejects.toThrow('not supported')
  })

  it('should correctly report the existence of a key with has()', async () => {
    const data = new TextEncoder().encode('Existence check')
    const cid = await generateRandomCID()

    expect(await encStore.has(cid)).toBe(false)

    await encStore.put(cid, data)
    expect(await encStore.has(cid)).toBe(true)
  })

  it('should throw an error when getting a non-existent key', async () => {
    const cid = await generateRandomCID()

    await expect(encStore.get(cid)).rejects.toThrow('Key not found')
  })

  it('should handle encryption and decryption correctly', async () => {
    const data = new TextEncoder().encode('Sensitive Data')
    const cid = await generateRandomCID()

    await encStore.put(cid, data)

    // Compute the storage CID
    const storageCID = await encStore.computeStorageCID(cid)

    // Directly access the underlying store to ensure data is encrypted
    const storedData = await mockStore.get(storageCID)
    expect(storedData).not.toEqual(data) // Encrypted data should differ

    // Decrypt and verify
    const decryptedData = await encStore.get(cid)
    expect(decryptedData).toEqual(data)
  })

  it('should handle incorrect password decryption attempts gracefully', async () => {
    const data = new TextEncoder().encode('Another Sensitive Data')
    const cid = await generateRandomCID()

    await encStore.put(cid, data)

    // Create a new EncBlockstore with a different password but the same underlying blockstore
    const wrongPassword = '🍤wrong-password🍤'

    const wrongPasswordStore = new EncBlockstore(mockStore)
    await wrongPasswordStore.init(wrongPassword, masterSalt)

    // Attempt to decrypt with the wrong password and master salt
    await expect(wrongPasswordStore.get(cid)).rejects.toThrow('Key not found')
  })

  it('should handle incorrect salt decryption attempts gracefully', async () => {
    const data = new TextEncoder().encode('Another Sensitive Data')
    const cid = await generateRandomCID()

    await encStore.put(cid, data)

    // Create a new EncBlockstore with a different master salt but the same underlying blockstore
    const wrongMasterSalt = globalThis.crypto.getRandomValues(new Uint8Array(16)) // Different master salt

    const wrongPasswordStore = new EncBlockstore(mockStore)
    await wrongPasswordStore.init(password, wrongMasterSalt)

    // Attempt to decrypt with the wrong password and master salt
    await expect(wrongPasswordStore.get(cid)).rejects.toThrow('Key not found')
  })
})
