/**
 * @packageDocumentation
 *
 * EncBlockstore provides a encrypted wrapper around any existing Blockstore implementation.
 * Ensures that both CIDs and data blocks are encrypted at rest.
 *
 * @example
 *
 * ```js
 * import { EncBlockstore } from 'blockstore-enc'
 * import { FsBlockstore } from 'blockstore-fs'
 *
 * try {
 *   const password = 'strong-password-is-strong' // Must be at least 16 bytes long
 *   const salt = crypto.getRandomValues(new Uint8Array(16)) // Must be at least 16 bytes long
 *   const store = new EncBlockstore(new FsBlockstore('path/to/store'))
 *   await store.init(password, salt)
 *   await store.open()
 * } catch (err) {
 *   console.error(err)
 * }
 * ```
 */

import map from 'it-map'
import parallelBatch from 'it-parallel-batch'
import { CID } from 'multiformats/cid'
import * as raw from 'multiformats/codecs/raw'
import { sha256 } from 'multiformats/hashes/sha2'
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
  pbkdf2hash?: 'SHA-512' | 'SHA-256'

  /**
   * The length of the salt to use for PBKDF2.
   * default: 16 (16 bytes, 128 bits)
   */
  saltByteLength?: number

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

export class EncBlockstore implements Blockstore {
  private readonly blockstore: Blockstore
  private masterKey?: CryptoKey
  private encKey?: CryptoKey
  private macKey?: CryptoKey
  private readonly AES_GCM_IV_LENGTH: number = 12
  private readonly putManyConcurrency: number
  private readonly getManyConcurrency: number
  private readonly deleteManyConcurrency: number
  private readonly pbkdf2Iterations: number
  private readonly pbkdf2hash: 'SHA-256' | 'SHA-512'
  private readonly saltByteLength: number

  constructor (blockstore: Blockstore, init: EncBlockstoreInit = {}) {
    this.blockstore = blockstore
    this.deleteManyConcurrency = init.deleteManyConcurrency ?? 50
    this.getManyConcurrency = init.getManyConcurrency ?? 50
    this.putManyConcurrency = init.putManyConcurrency ?? 50
    this.pbkdf2Iterations = init.pbkdf2Iterations ?? 210000
    this.pbkdf2hash = init.pbkdf2hash ?? 'SHA-512'
    this.saltByteLength = init.saltByteLength ?? 16
  }

  /**
   * Initializes the encryption and MAC keys. Must be called before using the blockstore.
   *
   * @param password - The password to derive the master key from.
   * @param masterSalt - The master salt used for key derivation.
   */
  public async init (password: string, masterSalt: Uint8Array): Promise<void> {
    if (password.length < 16) {
      throw new Error('password must be provided and at least 16 bytes long')
    }

    if (masterSalt.length < 16) {
      throw new Error('Master salt must be provided and at least 16 bytes long')
    }

    // Derive the master key using PBKDF2 with the provided master salt
    this.masterKey = await this.deriveMasterKey(password, masterSalt)

    // Derive encryption and MAC keys using HKDF
    this.encKey = await this.deriveHKDF(this.masterKey, 'encryption')
    this.macKey = await this.deriveHKDF(this.masterKey, 'mac')
  }

  /**
   * Derives the master key from the password and master salt using PBKDF2.
   *
   * @param password - The password to derive the key from.
   * @param salt - The master salt.
   * @returns The derived master CryptoKey.
   */
  private async deriveMasterKey (password: string, salt: Uint8Array): Promise<CryptoKey> {
    const keyMaterial = await globalThis.crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(password),
      { name: 'PBKDF2' },
      false,
      ['deriveBits']
    )

    const derivedBits = await globalThis.crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt,
        iterations: this.pbkdf2Iterations,
        hash: this.pbkdf2hash
      },
      keyMaterial,
      256
    )

    const masterKey = await globalThis.crypto.subtle.importKey(
      'raw',
      new Uint8Array(derivedBits),
      { name: 'HKDF' },
      false,
      ['deriveKey']
    )

    return masterKey
  }

  /**
   * Derives a CryptoKey using HKDF from the master key.
   *
   * @param masterKey - The master CryptoKey.
   * @param info - Contextual information for key derivation ('encryption' or 'mac').
   * @returns The derived CryptoKey.
   */
  private async deriveHKDF (masterKey: CryptoKey, info: string): Promise<CryptoKey> {
    if (info === 'mac') {
      return globalThis.crypto.subtle.deriveKey(
        {
          name: 'HKDF',
          hash: 'SHA-256',
          salt: new Uint8Array(0), // Empty salt for HKDF expansion
          info: new TextEncoder().encode(info)
        },
        masterKey,
        { name: 'HMAC', hash: 'SHA-256', length: 256 },
        false,
        ['sign', 'verify']
      )
    } else if (info === 'encryption') {
      return globalThis.crypto.subtle.deriveKey(
        {
          name: 'HKDF',
          hash: 'SHA-256',
          salt: new Uint8Array(0), // Empty salt for HKDF expansion
          info: new TextEncoder().encode(info)
        },
        masterKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
      )
    } else {
      throw new Error(`Unknown info parameter: ${info}`)
    }
  }

  /**
   * Computes the storage CID by applying HMAC to the original CID using the macKey
   * and then hashing the resulting value. Unlike standard CIDs, the storage CID does not
   * directly correspond to a hash of the encrypted block. Instead, it serves as a consistent
   * mapping to the original CID, enabling seamless get and put operations.
   *
   * @param cid - The original CID.
   * @returns A new CID derived from the HMAC of the original CID.
   */
  private async computeStorageCID (cid: CID): Promise<CID> {
    if (this.macKey === undefined || this.macKey === null) {
      throw new Error('blockstore not initialized')
    }

    const cidBytes = cid.bytes
    const signature = await globalThis.crypto.subtle.sign(
      {
        name: 'HMAC',
        hash: 'SHA-256'
      },
      this.macKey,
      cidBytes
    )
    const hmacResult = new Uint8Array(signature)
    const hash = await sha256.digest(hmacResult)
    return CID.createV1(raw.code, hash)
  }

  private isOpenCloserBlockstore (blockstore: Blockstore<any>): blockstore is OpenCloserBlockstore {
    return typeof (blockstore as OpenCloserBlockstore).open === 'function' &&
      typeof (blockstore as OpenCloserBlockstore).close === 'function'
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

  /**
   * Stores an encrypted block under the original CID.
   * The encrypted data (salt, IV, ciphertext) is stored under a storage CID derived from the original CID.
   *
   * @param key - The original CID.
   * @param val - The plaintext data to encrypt and store.
   * @returns The original CID.
   */
  async put (key: CID, val: Uint8Array): Promise<CID> {
    if (this.encKey === undefined || this.encKey === null || this.macKey === undefined || this.macKey === null) {
      throw new Error('blockstore not initialized')
    }

    // Compute storage CID
    const storageCID = await this.computeStorageCID(key)

    // Generate per-block salt for HKDF
    const salt = globalThis.crypto.getRandomValues(new Uint8Array(this.saltByteLength))

    // Derive per-block encryption key using HKDF with masterKey and per-block salt
    const encKey = await this.deriveEncKey(salt)

    // Generate IV
    const iv = globalThis.crypto.getRandomValues(new Uint8Array(this.AES_GCM_IV_LENGTH))

    // Encrypt the plaintext
    const ciphertextBuffer = await globalThis.crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv
      },
      encKey,
      val
    )

    const ciphertext = new Uint8Array(ciphertextBuffer)

    // Combine salt, IV, and ciphertext
    const combined = new Uint8Array(salt.length + iv.length + ciphertext.length)
    combined.set(salt, 0)
    combined.set(iv, salt.length)
    combined.set(ciphertext, salt.length + iv.length)

    // Store the encrypted data under storage CID
    await this.blockstore.put(storageCID, combined)

    // Return the original CID
    return key
  }

  /**
   * Derives the per-block encryption key using HKDF with the master key and per-block salt.
   *
   * @param salt - The per-block salt.
   * @returns The derived per-block CryptoKey.
   */
  private async deriveEncKey (salt: Uint8Array): Promise<CryptoKey> {
    if (this.masterKey === undefined || this.masterKey === null) {
      throw new Error('blockstore not initialized')
    }

    return globalThis.crypto.subtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt, // Use per-block salt as HKDF salt
        info: new TextEncoder().encode('encryption') // Contextual info
      },
      this.masterKey, // Use masterKey as the base key
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    )
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

  /**
   * Retrieves and decrypts a block by its original CID.
   *
   * @param key - The original CID.
   * @returns The decrypted plaintext data.
   */
  async get (key: CID): Promise<Uint8Array> {
    if (this.encKey === undefined || this.encKey === null || this.macKey === undefined || this.macKey === null) {
      throw new Error('blockstore not initialized')
    }

    // Compute storage CID
    const storageCID = await this.computeStorageCID(key)

    // Retrieve the encrypted data
    let combined: Uint8Array
    try {
      combined = await this.blockstore.get(storageCID)
    } catch (err) {
      throw new Error('Key not found')
    }

    if (combined.length < this.saltByteLength + this.AES_GCM_IV_LENGTH) {
      throw new Error('Encrypted data is corrupted or incomplete')
    }

    // Extract per-block salt, IV, and ciphertext
    const salt = combined.slice(0, this.saltByteLength)
    const iv = combined.slice(this.saltByteLength, this.saltByteLength + this.AES_GCM_IV_LENGTH)
    const ciphertext = combined.slice(this.saltByteLength + this.AES_GCM_IV_LENGTH)

    // Derive per-block encryption key
    const encKey = await this.deriveEncKey(salt)

    // Decrypt the ciphertext
    let decryptedBuffer: ArrayBuffer
    try {
      decryptedBuffer = await globalThis.crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv
        },
        encKey,
        ciphertext
      )
    } catch (err) {
      throw new Error('Decryption failed')
    }

    return new Uint8Array(decryptedBuffer)
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

  /**
   * Deletes a block by its original CID.
   *
   * @param key - The original CID.
   */
  async delete (key: CID): Promise<void> {
    if (this.macKey === undefined || this.macKey === null) {
      throw new Error('blockstore not initialized')
    }

    // Compute storage CID
    const storageCID = await this.computeStorageCID(key)

    // Delete the encrypted data
    await this.blockstore.delete(storageCID)
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

  /**
   * Checks if a block exists by its original CID.
   *
   * @param key - The original CID.
   * @returns A boolean indicating existence.
   */
  async has (key: CID): Promise<boolean> {
    if (this.macKey === undefined || this.macKey === null) {
      throw new Error('blockstore not initialized')
    }

    const storageCID = await this.computeStorageCID(key)

    return this.blockstore.has(storageCID)
  }

  /**
   * Retrieves and decrypts all blocks in the blockstore.
   * Note: Due to the one-way CID mapping, getAll is not supported.
   *
   * @throws Always throws 'not supported' error.
   */
  async * getAll (): AsyncIterable<Pair> {
    // Dummy yield to satisfy TypeScript's requirement
    yield * []

    throw new Error('not supported')
  }
}
