import { CID } from 'multiformats/cid'
import { sha256 } from 'multiformats/hashes/sha2'
import { describe, it, expect, beforeEach } from 'vitest'
import { MockBlockstore } from '../__mocks__/MockBlockstore'
import { EncBlockstore, EncBlockstoreInit } from '../src/'

async function generateCID (data: Uint8Array): Promise<CID> {
  const hash = await sha256.digest(data)
  return CID.create(1, 0x55, hash) // 0x55 is the codec for 'raw'
}

describe('EncBlockstore', () => {
  let mockStore: MockBlockstore
  let encStore: EncBlockstore
  const password = 'test-password'

  beforeEach(async () => {
    mockStore = new MockBlockstore()
    encStore = new EncBlockstore(mockStore)
    await encStore.init(password)
  })

  it('should put and get a single block correctly', async () => {
    const originalData = new TextEncoder().encode('Hello, World!')
    const cid = CID.parse('bafkreigh2akiscaildcxxl6oj4u34k26rk7jvl54b3sxxmxewx4s7ee73a')

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
      const cid = await generateCID(data)
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
    const cid = CID.parse('bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku')

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
      const cid = await generateCID(data)
      blocks.push({ cid, block: data })
    }

    // Put many blocks
    const putCids: CID[] = []
    for await (const cid of encStore.putMany(blocks)) {
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
      expect(getPairs[i].cid.toString()).toBe(blocks[i].cid.toString())
      expect(getPairs[i].block).toEqual(blocks[i].block)
    }
  })

  it('should handle deleteMany correctly', async () => {
    const blocks: Array<{ cid: CID, block: Uint8Array }> = []

    // Create multiple blocks
    for (let i = 0; i < 10; i++) {
      const data = new TextEncoder().encode(`Delete data ${i}`)
      const cid = await generateCID(data)
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
    const blocks: Array<{ cid: CID, block: Uint8Array }> = []

    // Create multiple blocks
    for (let i = 0; i < 15; i++) {
      const data = new TextEncoder().encode(`GetAll data ${i}`)
      const cid = await generateCID(data)
      blocks.push({ cid, block: data })
    }

    // Put all blocks
    for (const { cid, block } of blocks) {
      await encStore.put(cid, block)
    }

    // Retrieve all blocks
    const retrievedBlocks: Array<{ cid: CID, block: Uint8Array }> = []
    for await (const pair of encStore.getAll()) {
      retrievedBlocks.push(pair)
    }

    expect(retrievedBlocks.length).toBe(blocks.length)

    // Verify all blocks
    for (const { cid, block } of blocks) {
      const found = retrievedBlocks.find((pair) => pair.cid.toString() === cid.toString())
      expect(found).toBeDefined()
      expect(found?.block).toEqual(block)
    }
  })

  it('should correctly report the existence of a key with has()', async () => {
    const data = new TextEncoder().encode('Existence check')
    const cid = CID.parse('bafkreigh2akiscaildcxxl6oj4u34k26rk7jvl54b3sxxmxewx4s7ee73a')

    expect(await encStore.has(cid)).toBe(false)

    await encStore.put(cid, data)
    expect(await encStore.has(cid)).toBe(true)
  })

  it('should throw an error when getting a non-existent key', async () => {
    const cid = CID.parse('bafkreigh2akiscaildcxxl6oj4u34k26rk7jvl54b3sxxmxewx4s7ee73a')

    await expect(encStore.get(cid)).rejects.toThrow('Key not found')
  })

  it('should handle encryption and decryption correctly', async () => {
    const data = new TextEncoder().encode('Sensitive Data')
    const cid = CID.parse('bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku')

    await encStore.put(cid, data)

    // Directly access the underlying store to ensure data is encrypted
    const storedData = await mockStore.get(cid)
    expect(storedData).not.toEqual(data) // Encrypted data should differ

    // Decrypt and verify
    const decryptedData = await encStore.get(cid)
    expect(decryptedData).toEqual(data)
  })

  it('should handle incorrect password decryption attempts gracefully', async () => {
    const data = new TextEncoder().encode('Another Sensitive Data')
    const cid = await generateCID(data)

    await encStore.put(cid, data)

    // Create a new EncBlockstore with a different password but the same underlying blockstore

    const wrongPasswordStore = new EncBlockstore(mockStore)
    await wrongPasswordStore.init('wrong-password')

    // Attempt to decrypt with the wrong password
    await expect(wrongPasswordStore.get(cid)).rejects.toThrow()
  })
})
