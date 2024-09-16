/**
 * @packageDocumentation
 *
 * A Blockstore wrapper that stores encrypted blocks. Keys are not encrypted.
 * Blocks are encrypted at rest.
 *
 * @example
 *
 * ```js
 * import { EncryptedBlockstore } from 'blockstore-enc'
 * import { FsBlockstore } from 'blockstore-fs'
 *
 * try {
 *   const store = new EncBlockstore(new FsBlockstore('path/to/store'))
 *   await store.init(password)
 * } catch (err) {
 *   console.error(err)
 * }
 * ```
 */

import map from 'it-map'
import parallelBatch from 'it-parallel-batch'
import { type CID } from 'multiformats/cid'
import type { Blockstore, Pair } from 'interface-blockstore'
import type { AwaitIterable } from 'interface-store'

interface OpenCloserBlockstore extends Blockstore<any> {
  open(): Promise<void>
  close(): Promise<void>
}

export interface EncBlockstoreInit {
  /**
   * The number of PBKDF2 iterations to use.
   * https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2
   * default: 210000 for SHA-512
   */
  pbkdf2Iterations?: number

  /**
   * The hash algorithm to use for PBKDF2.
   * default: 'SHA-512'
   */
  hash?: 'SHA-512' | 'SHA-256'

  /**
   * How many blocks to put in parallel when `.putMany` is called.
   * default: 50
   */
  putManyConcurrency?: number

  /**
   * How many blocks to read in parallel when `.getMany` is called.
   * default: 50
   */
  getManyConcurrency?: number

  /**
   * How many blocks to delete in parallel when `.deleteMany` is called.
   * default: 50
   */
  deleteManyConcurrency?: number
}

/**
 * A blockstore backed by the file system
 */
export class EncBlockstore implements Blockstore {
  private readonly blockstore: Blockstore
  private keyMaterial!: CryptoKey
  private readonly AES_GCM_IV_LENGTH: number = 12
  private readonly putManyConcurrency: number
  private readonly getManyConcurrency: number
  private readonly deleteManyConcurrency: number
  private readonly pbkdf2Iterations: number
  private readonly hash: 'SHA-256' | 'SHA-512'

  constructor (blockstore: Blockstore, init: EncBlockstoreInit = {}) {
    this.blockstore = blockstore
    this.deleteManyConcurrency = init.deleteManyConcurrency ?? 50
    this.getManyConcurrency = init.getManyConcurrency ?? 50
    this.putManyConcurrency = init.putManyConcurrency ?? 50
    this.pbkdf2Iterations = init.pbkdf2Iterations ?? 210000
    this.hash = init.hash ?? 'SHA-512'
  }

  async init (password: string): Promise<void> {
    this.keyMaterial = await this.newKeyMaterial(password)
  }

  private async newKeyMaterial (password: string): Promise<CryptoKey> {
    return globalThis.crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(password),
      { name: 'PBKDF2' },
      false,
      ['deriveBits', 'deriveKey']
    )
  }

  /*
  Given some key material and some random salt
  derive an AES-GCM key using PBKDF2.
  */
  private async getKey (salt: Uint8Array): Promise<CryptoKey> {
    return globalThis.crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt,
        iterations: this.pbkdf2Iterations,
        hash: this.hash
      },
      this.keyMaterial,
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    )
  }

  private isOpenCloserBlockstore (blockstore: Blockstore<any>): blockstore is OpenCloserBlockstore {
    return typeof (blockstore as OpenCloserBlockstore).open === 'function' && typeof (blockstore as OpenCloserBlockstore).close === 'function'
  }

  async open (): Promise<void> {
    if (this.isOpenCloserBlockstore(this.blockstore)) {
      return this.blockstore.open()
    }
  }

  async close (): Promise<void> {
    if (this.isOpenCloserBlockstore(this.blockstore)) {
      return this.blockstore.close()
    }
  }

  async put (key: CID, val: Uint8Array): Promise<CID> {
    if (this.keyMaterial === undefined || this.keyMaterial === null) {
      throw new Error('Key material not initialized')
    }

    const encKey = await this.getKey(new TextEncoder().encode(key.toString()))
    const iv = globalThis.crypto.getRandomValues(new Uint8Array(this.AES_GCM_IV_LENGTH))
    const ciphertextBuffer = await globalThis.crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv
      },
      encKey,
      val
    )

    const combined = new Uint8Array(iv.length + ciphertextBuffer.byteLength)
    combined.set(iv, 0)
    combined.set(new Uint8Array(ciphertextBuffer), iv.length)

    return this.blockstore.put(key, combined)
  }

  async * putMany (source: AwaitIterable<Pair>): AsyncIterable<CID> {
    yield * parallelBatch(
      map(source, ({ cid, block }) => {
        return async () => {
          await this.put(cid, block)

          return cid
        }
      }),
      this.putManyConcurrency
    )
  }

  async get (key: CID): Promise<Uint8Array> {
    if (this.keyMaterial === undefined || this.keyMaterial === null) {
      throw new Error('Key material not initialized')
    }

    const encFile = await this.blockstore.get(key)

    const iv = encFile.slice(0, this.AES_GCM_IV_LENGTH)
    const ciphertext = encFile.slice(this.AES_GCM_IV_LENGTH)

    const encKey = await this.getKey(new TextEncoder().encode(key.toString()))

    const plaintextBuffer = await globalThis.crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv
      },
      encKey,
      ciphertext
    )

    return new Uint8Array(plaintextBuffer)
  }

  async * getMany (source: AwaitIterable<CID>): AsyncIterable<Pair> {
    yield * parallelBatch(
      map(source, key => {
        return async () => {
          return {
            cid: key,
            block: await this.get(key)
          }
        }
      }),
      this.getManyConcurrency
    )
  }

  async delete (key: CID): Promise<void> {
    return this.blockstore.delete(key)
  }

  async * deleteMany (source: AwaitIterable<CID>): AsyncIterable<CID> {
    yield * parallelBatch(
      map(source, key => {
        return async () => {
          await this.delete(key)

          return key
        }
      }),
      this.deleteManyConcurrency
    )
  }

  async has (key: CID): Promise<boolean> {
    return this.blockstore.has(key)
  }

  async * getAll (): AsyncIterable<Pair> {
    const encryptedPairs = this.blockstore.getAll()

    const decryptFunctions: AsyncIterable<() => Promise<Pair>> = map(encryptedPairs, ({ cid, block: encryptedBlock }) => {
      return async () => {
        const iv = encryptedBlock.slice(0, this.AES_GCM_IV_LENGTH)
        const ciphertext = encryptedBlock.slice(this.AES_GCM_IV_LENGTH)

        const encKey = await this.getKey(new TextEncoder().encode(cid.toString()))

        const plaintextBuffer = await globalThis.crypto.subtle.decrypt(
          {
            name: 'AES-GCM',
            iv
          },
          encKey,
          ciphertext
        )

        const decryptedBlock = new Uint8Array(plaintextBuffer)

        return { cid, block: decryptedBlock }
      }
    })

    yield * parallelBatch(decryptFunctions, this.getManyConcurrency)
  }
}
