// __mocks__/MockBlockstore.ts

import { type Blockstore, type Pair } from 'interface-blockstore'
import { type AwaitIterable } from 'interface-store'
import { CID } from 'multiformats/cid'

export class MockBlockstore implements Blockstore {
  private readonly store = new Map<string, Uint8Array>()

  /**
   * Stores a block under the given key.
   *
   * @param key - The CID under which to store the data.
   * @param value - The data to store.
   * @returns The CID under which the data is stored.
   */
  async put (key: CID, value: Uint8Array): Promise<CID> {
    const cid = key
    this.store.set(cid.toString(), value)
    return cid
  }

  /**
   * Retrieves a block by its key.
   *
   * @param key - The CID of the block to retrieve.
   * @returns The stored data.
   * @throws If the key does not exist.
   */
  async get (key: CID): Promise<Uint8Array> {
    const data = this.store.get(key.toString())
    if (data === undefined) {
      throw new Error('Key not found')
    }
    return data
  }

  /**
   * Deletes a block by its key.
   *
   * @param key - The CID of the block to delete.
   */
  async delete (key: CID): Promise<void> {
    this.store.delete(key.toString())
  }

  /**
   * Checks if a block exists by its key.
   *
   * @param key - The CID of the block to check.
   * @returns True if the block exists, false otherwise.
   */
  async has (key: CID): Promise<boolean> {
    return this.store.has(key.toString())
  }

  /**
   * Stores multiple blocks.
   *
   * @param source - An iterable of pairs containing CIDs and data.
   * @returns An iterable of the CIDs under which the data was stored.
   */
  async * putMany (source: AwaitIterable<Pair>): AsyncIterable<CID> {
    for await (const pair of source) {
      const cid = pair.cid
      const block = pair.block
      await this.put(cid, block)
      yield cid
    }
  }

  /**
   * Retrieves multiple blocks.
   *
   * @param source - An iterable of CIDs.
   * @returns An iterable of pairs containing CIDs and data.
   */
  async * getMany (source: AwaitIterable<CID>): AsyncIterable<Pair> {
    for await (const key of source) {
      const block = await this.get(key)
      yield { cid: key, block }
    }
  }

  /**
   * Deletes multiple blocks.
   *
   * @param source - An iterable of CIDs.
   * @returns An iterable of the CIDs that were deleted.
   */
  async * deleteMany (source: AwaitIterable<CID>): AsyncIterable<CID> {
    for await (const key of source) {
      await this.delete(key)
      yield key
    }
  }

  /**
   * Retrieves all blocks.
   *
   * @returns An iterable of pairs containing CIDs and data.
   */
  async * getAll (): AsyncIterable<Pair> {
    for (const [key, value] of this.store.entries()) {
      const cid = CID.parse(key)
      yield { cid, block: value }
    }
  }

  // Implement open and close as no-ops
  async open (): Promise<void> { }
  async close (): Promise<void> { }
}
