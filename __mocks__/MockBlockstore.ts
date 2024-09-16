// __mocks__/MockBlockstore.ts

import { type Blockstore, type Pair } from 'interface-blockstore'
import { type AwaitIterable } from 'interface-store'
import { CID } from 'multiformats/cid'

export class MockBlockstore implements Blockstore {
  private readonly store = new Map<string, Uint8Array>()

  async put (key: CID, val: Uint8Array): Promise<CID> {
    this.store.set(key.toString(), val)
    return key
  }

  async get (key: CID): Promise<Uint8Array> {
    const data = this.store.get(key.toString())
    if (data === undefined) {
      throw new Error('Key not found')
    }
    return data
  }

  async delete (key: CID): Promise<void> {
    this.store.delete(key.toString())
  }

  async has (key: CID): Promise<boolean> {
    return this.store.has(key.toString())
  }

  async * putMany (source: AwaitIterable<Pair>): AsyncIterable<CID> {
    for await (const pair of source) {
      await this.put(pair.cid, pair.block)
      yield pair.cid
    }
  }

  async * getMany (source: AwaitIterable<CID>): AsyncIterable<Pair> {
    for await (const key of source) {
      const block = await this.get(key)
      yield { cid: key, block }
    }
  }

  async * deleteMany (source: AwaitIterable<CID>): AsyncIterable<CID> {
    for await (const key of source) {
      await this.delete(key)
      yield key
    }
  }

  async * getAll (): AsyncIterable<Pair> {
    for (const [key, value] of this.store.entries()) {
      yield { cid: CID.parse(key), block: value }
    }
  }

  // Implement open and close as no-ops if needed
  async open (): Promise<void> { }
  async close (): Promise<void> { }
}
