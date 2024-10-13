/**
 * @packageDocumentation
 *
 * EncBlockstore provides a encrypted wrapper around any existing Blockstore implementation.
 * Ensures that both CIDs and data blocks are encrypted at rest.
 * Blocks are encrypted using AES_256_GCM.
 * CIDS are encrypted using AES_256_GCM_SIV.
 *
 * @example
 *
 * ```js
 * import { EncBlockstore } from 'blockstore-enc'
 * import { FsBlockstore } from 'blockstore-fs'
 *
 * try {
 *   const password = 'strong-password-is-strong' // Must be at least 16 bytes long
 *   const blockMasterSalt = crypto.getRandomValues(new Uint8Array(16)) // Must be at least 16 bytes long
 *   const cidMasterSalt = crypto.getRandomValues(new Uint8Array(16)) // Must be at least 16 bytes long
 *   const store = new EncBlockstore(password, blockMasterSalt, cidMasterSalt, new FsBlockstore('path/to/store'))
 *   await store.open()
 * } catch (err) {
 *   console.error(err)
 * }
 * ```
 */

import { siv } from '@noble/ciphers/aes'
import { NotFoundError, type AwaitIterable } from 'interface-store'
import map from 'it-map'
import parallelBatch from 'it-parallel-batch'
import { CID } from 'multiformats/cid'
import * as raw from 'multiformats/codecs/raw'
import { decode } from 'multiformats/hashes/digest'
import * as hasher from 'multiformats/hashes/hasher'
import type { Blockstore, Pair } from 'interface-blockstore'

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

type DeriveInfo = 'block-encryption' | 'cid-encryption' | 'cid-nonce'

export class EncBlockstore implements Blockstore {
  public readonly blockstore: Blockstore
  private readonly password: Uint8Array
  private readonly blockMasterSalt: Uint8Array
  private readonly cidMasterSalt: Uint8Array
  private masterKey?: CryptoKey
  private blockEncKey?: CryptoKey
  private cidEncKey?: Uint8Array
  private cidNonce?: Uint8Array
  // private macKey?: CryptoKey
  private readonly AES_GCM_IV_LENGTH: number = 12 // 96 bit
  private readonly AES_SIV_KEY_LENGTH: number = 256 // bits
  private readonly AES_SIV_NONCE_LENGTH: number = 96 // bits
  private readonly putManyConcurrency: number
  private readonly getManyConcurrency: number
  private readonly deleteManyConcurrency: number
  private readonly pbkdf2Iterations: number
  private readonly pbkdf2hash: 'SHA-256' | 'SHA-512'
  private readonly saltByteLength: number

  constructor (password: string | Uint8Array, blockMasterSalt: string | Uint8Array, cidMasterSalt: string | Uint8Array, blockstore: Blockstore, init: EncBlockstoreInit = {}) {
    this.blockstore = blockstore
    this.deleteManyConcurrency = init.deleteManyConcurrency ?? 50
    this.getManyConcurrency = init.getManyConcurrency ?? 50
    this.putManyConcurrency = init.putManyConcurrency ?? 50
    this.pbkdf2Iterations = init.pbkdf2Iterations ?? 210000
    this.pbkdf2hash = init.pbkdf2hash ?? 'SHA-512'
    this.saltByteLength = init.saltByteLength ?? 16 // 128 bit

    if (typeof password === 'string') {
      this.password = new TextEncoder().encode(password)
    } else {
      this.password = password
    }

    if (typeof blockMasterSalt === 'string') {
      this.blockMasterSalt = new TextEncoder().encode(blockMasterSalt)
    } else {
      this.blockMasterSalt = blockMasterSalt
    }

    if (typeof cidMasterSalt === 'string') {
      this.cidMasterSalt = new TextEncoder().encode(cidMasterSalt)
    } else {
      this.cidMasterSalt = cidMasterSalt
    }
  }

  /**
   * Initializes the encryption and MAC keys.
   *
   * @throws If the password or master salt are not provided or are too short.
   */
  private async init (): Promise<void> {
    if (this.password.length < 16) {
      throw new Error('password must be provided and at least 16 bytes long')
    }

    if (this.blockMasterSalt.length < 16) {
      throw new Error('blockMasterSalt must be provided and at least 16 bytes long')
    }

    if (this.cidMasterSalt.length < 16) {
      throw new Error('cidMasterSalt must be provided and at least 16 bytes long')
    }

    // Derive the master key using PBKDF2 with the provided block master salt
    this.masterKey = await this.deriveMasterKey(this.password, this.blockMasterSalt, this.pbkdf2Iterations, this.pbkdf2hash)

    // Derive block encryption using HKDF
    this.blockEncKey = await this.deriveHKDFKey(this.masterKey, 'block-encryption')

    // Derive CID key material
    this.cidEncKey = await this.deriveHKDFKeyMaterial(this.masterKey, this.cidMasterSalt, 'cid-encryption', this.AES_SIV_KEY_LENGTH)

    // Derive CID nonce
    // The same nonce is used for all CIDs
    // See https://datatracker.ietf.org/doc/html/rfc8452
    // Nonce misuse-resistant AEADs do not suffer from this problem.  For
    // this class of AEADs, encrypting two messages with the same nonce only
    // discloses whether the messages were equal or not. This is the
    // minimum amount of information that a deterministic algorithm can leak
    // in this situation
    this.cidNonce = await this.deriveHKDFKeyMaterial(this.masterKey, this.cidMasterSalt, 'cid-nonce', this.AES_SIV_NONCE_LENGTH)
  }

  /**
   * Derives the master key from the password and block master salt using PBKDF2 and HKDF.
   *
   * @returns The derived master CryptoKey.
   */
  private async deriveMasterKey (password: Uint8Array, salt: Uint8Array, iterations: number, hash: string): Promise<CryptoKey> {
    const keyMaterial = await globalThis.crypto.subtle.importKey(
      'raw',
      password,
      { name: 'PBKDF2' },
      false,
      ['deriveBits']
    )

    const derivedBits = await globalThis.crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt,
        iterations,
        hash
      },
      keyMaterial,
      256
    )

    const masterKey = await globalThis.crypto.subtle.importKey(
      'raw',
      new Uint8Array(derivedBits),
      { name: 'HKDF' },
      false,
      ['deriveKey', 'deriveBits']
    )

    return masterKey
  }

  private async deriveHKDFKeyMaterial (
    masterKey: CryptoKey,
    salt: Uint8Array,
    info: DeriveInfo,
    bitsLength: number
  ): Promise<Uint8Array> {
    if (info !== 'cid-encryption' && info !== 'cid-nonce') {
      throw new Error(`Unknown info parameter: ${info}`)
    }

    const derivedBits = await globalThis.crypto.subtle.deriveBits(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt,
        info: new TextEncoder().encode(info)
      },
      masterKey,
      bitsLength
    )

    return new Uint8Array(derivedBits)
  }

  /**
   * Derives a CryptoKey using HKDF from the master key.
   *
   * @param masterKey - The master CryptoKey.
   * @param info - Contextual information for key derivation ('block-encryption').
   * @returns The derived CryptoKey.
   */
  private async deriveHKDFKey (masterKey: CryptoKey, info: DeriveInfo): Promise<CryptoKey> {
    if (info !== 'block-encryption') {
      throw new Error(`Unknown info parameter: ${info}`)
    }

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
  }

  /**
   * Derives the per-block encryption key using HKDF with the master key and per-block salt.
   *
   * @param masterKey - The master CryptoKey.
   * @param salt - The per-block salt.
   * @returns The derived per-block CryptoKey.
   */
  private async deriveBlockEncKey (masterKey: CryptoKey, salt: Uint8Array): Promise<CryptoKey> {
    return globalThis.crypto.subtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt, // Use per-block salt as HKDF salt
        info: new TextEncoder().encode('block-encryption')
      },
      masterKey, // Use masterKey as the base key
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    )
  }

  /**
   * Computes the storage CID by encrypting the original CID's multihash digest
   * with the AES_256_GCM_SIV cipher.
   * See https://datatracker.ietf.org/doc/html/rfc8452
   * Unlike standard CIDs, the storage CID is not a hash of the content, but an
   * encrypted version of the original CID. It serves as a consistent mapping to
   * the original CID, enabling seamless get and put operations.
   *
   * @param cid - The original CID
   * @returns encrypted CID
   */
  private async encryptCID (cid: CID): Promise<CID> {
    if (
      this.cidEncKey === undefined || this.cidEncKey === null ||
      this.cidNonce === undefined || this.cidNonce === null
    ) {
      throw new Error('blockstore not initialized')
    }

    const stream = siv(this.cidEncKey, this.cidNonce)
    const ciphertext = stream.encrypt(cid.multihash.bytes)

    // rawHasher doesn't hash the data, it just returns the encrypted CID as a
    // MultihashDigest.
    // See https://github.com/multiformats/multicodec/blob/master/README.md#reserved-code-ranges
    const rawHasher = hasher.from({
      name: 'aes-gsm-siv-256',
      code: 0x3FFFFF, // Private Use hasher
      // code: 0x2001, // Private Use hasher

      encode: (input) => input
    })

    const hash = await rawHasher.digest(ciphertext)
    // const hash = identity.digest(ciphertext)

    const newCID = CID.createV1(raw.code, hash)
    console.log('encryptCID original', cid)
    console.log('encryptCID original bytes', cid.bytes)
    console.log('encryptCID', newCID)
    console.log('encryptCID bytes', newCID.bytes)

    // console.log('encryptCID version', newCID.version)
    // console.log('encryptCID code', newCID.code)
    // console.log('encryptCID multihash', newCID.multihash)

    return newCID
  }

  private async decryptCID (cid: CID): Promise<CID> {
    if (
      this.cidEncKey === undefined || this.cidEncKey === null ||
      this.cidNonce === undefined || this.cidNonce === null
    ) {
      throw new Error('blockstore not initialized')
    }

    // Extract ciphertext from storageCID's multihash digest
    const ciphertext = cid.multihash.digest

    // Decrypt the ciphertext
    const stream = siv(this.cidEncKey, this.cidNonce)
    let plaintext: Uint8Array
    try {
      plaintext = stream.decrypt(ciphertext)
    } catch (err) {
      throw new Error('Failed to decrypt storage CID')
    }

    return CID.createV1(raw.code, decode(plaintext))
  }

  /**
   * Checks if the blockstore has open and close methods
   *
   * @param blockstore - The blockstore to check
   * @returns True if the blockstore has open and close methods, false otherwise
   */
  private isOpenCloserBlockstore (blockstore: Blockstore<any>): blockstore is OpenCloserBlockstore {
    return typeof (blockstore as OpenCloserBlockstore).open === 'function' &&
      typeof (blockstore as OpenCloserBlockstore).close === 'function'
  }

  /**
   * Checks if the blockstore is queryable
   *
   * @param blockstore - The blockstore to check
   * @returns True if the blockstore is queryable, false otherwise
   */
  private isGetAllBlockstore (
    blockstore: Blockstore<any>
  ): blockstore is Blockstore<any> & {
    getAll(): AsyncIterable<Pair>
  } {
    return typeof (blockstore as any).getAll === 'function'
  }

  /**
   * Opens the encrypted blockstore.
   *
   * @throws If the password or master salt are not provided or are too short.
   */
  async open (): Promise<void> {
    await this.init()

    if (this.isOpenCloserBlockstore(this.blockstore)) {
      return this.blockstore.open()
    }
  }

  /**
   * Closes the encrypted blockstore.
   */
  async close (): Promise<void> {
    if (this.isOpenCloserBlockstore(this.blockstore)) {
      return this.blockstore.close()
    }
  }

  /**
   * Stores an encrypted block.
   * The salt, IV, & ciphertext is stored under an encrypted CID derived from the original CID.
   *
   * @param key - The original CID.
   * @param val - The plaintext data to encrypt and store.
   * @returns The original CID.
   */
  async put (key: CID, val: Uint8Array): Promise<CID> {
    if (
      this.masterKey === undefined || this.masterKey === null ||
      this.blockEncKey === undefined || this.blockEncKey === null ||
      this.cidEncKey === undefined || this.cidEncKey === null ||
      this.cidNonce === undefined || this.cidNonce === null
    ) {
      throw new Error('blockstore not initialized')
    }

    // Compute storage CID
    // console.log('put orig cid', key)
    const storageCID = await this.encryptCID(key)
    // console.log('put enc cid', storageCID)

    // Generate per-block salt for HKDF
    const salt = globalThis.crypto.getRandomValues(new Uint8Array(this.saltByteLength))

    // Derive per-block encryption key using HKDF with masterKey and per-block salt
    const blockEncKey = await this.deriveBlockEncKey(this.masterKey, salt)

    // Generate per-block IV
    const iv = globalThis.crypto.getRandomValues(new Uint8Array(this.AES_GCM_IV_LENGTH))

    // Encrypt the plaintext
    const ciphertextBuffer = await globalThis.crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv
      },
      blockEncKey,
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
   * Stores multiple blocks under their original CIDs.
   *
   * @param source - An iterable of Pairs containing the original CIDs and their plaintext data.
   * @returns An iterable of the original CIDs.
   * @throws If the blockstore is not initialized.
   */
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
   * @throws If the blockstore is not initialized.
   */
  async get (key: CID): Promise<Uint8Array> {
    if (
      !this.cidEncKey ||
      !this.cidNonce ||
      !this.masterKey
    ) {
      throw new Error('blockstore not initialized')
    }

    // Compute storage CID
    const storageCID = await this.encryptCID(key)

    // Retrieve the encrypted data
    let encryptedData: Uint8Array
    try {
      encryptedData = await this.blockstore.get(storageCID)
    } catch (err) {
      throw new NotFoundError(String(err))
    }

    // Decrypt the data block
    return this.decryptDataBlock(encryptedData)
  }

  private async decryptDataBlock (encryptedData: Uint8Array): Promise<Uint8Array> {
    if (this.masterKey === undefined || this.masterKey === null) {
      throw new Error('blockstore not initialized')
    }

    if (encryptedData.length < this.saltByteLength + this.AES_GCM_IV_LENGTH) {
      throw new Error('Encrypted data is corrupted or incomplete')
    }

    // Extract per-block salt, IV, and ciphertext
    const salt = encryptedData.slice(0, this.saltByteLength)
    const iv = encryptedData.slice(this.saltByteLength, this.saltByteLength + this.AES_GCM_IV_LENGTH)
    const ciphertext = encryptedData.slice(this.saltByteLength + this.AES_GCM_IV_LENGTH)

    // Derive per-block encryption key
    const blockEncKey = await this.deriveBlockEncKey(this.masterKey, salt)

    // Decrypt the ciphertext
    let decryptedBuffer: ArrayBuffer
    try {
      decryptedBuffer = await globalThis.crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv
        },
        blockEncKey,
        ciphertext
      )
    } catch (err) {
      throw new Error('Decryption failed')
    }

    return new Uint8Array(decryptedBuffer)
  }

  /**
   * Retrieves multiple blocks by their original CIDs.
   *
   * @param source - An iterable of CIDs.
   * @returns An iterable of Pairs containing the original CIDs and their decrypted plaintext data.
   * @throws If the blockstore is not initialized.
   */
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
    if (
      this.cidEncKey === undefined || this.cidEncKey === null ||
      this.cidNonce === undefined || this.cidNonce === null
    ) {
      throw new Error('blockstore not initialized')
    }

    // Compute storage CID
    const storageCID = await this.encryptCID(key)

    // Delete the encrypted data
    await this.blockstore.delete(storageCID)
  }

  /**
   * Deletes multiple blocks by their original CIDs.
   *
   * @param source - An iterable of CIDs.
   * @returns An iterable of CIDs.
   * @throws If the blockstore is not initialized.
   */
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
   * @throws If the blockstore is not initialized.
   */
  async has (key: CID): Promise<boolean> {
    if (
      this.cidEncKey === undefined || this.cidEncKey === null ||
      this.cidNonce === undefined || this.cidNonce === null
    ) {
      throw new Error('blockstore not initialized')
    }

    const storageCID = await this.encryptCID(key)

    return this.blockstore.has(storageCID)
  }

  /**
   * Retrieves and decrypts all blocks in the blockstore.
   * Note: Due to the one-way CID mapping, getAll is not supported.
   *
   * @throws Always throws 'not supported' error.
   */
  // async * getAll (): AsyncIterable<Pair> {
  //   // Dummy yield to satisfy TypeScript's requirement
  //   yield * []
  //
  // }
  async * getAll (): AsyncIterable<Pair> {
    if (
      this.cidEncKey === undefined || this.cidEncKey === null ||
      this.cidNonce === undefined || this.cidNonce === null ||
      this.masterKey === undefined || this.masterKey === null
    ) {
      throw new Error('blockstore not initialized')
    }

    if (!this.isGetAllBlockstore(this.blockstore)) {
      throw new Error('not supported')
    }

    for await (const { cid, block } of this.blockstore.getAll()) {
      // Decrypt the storage CID to get the original CID
      const originalCID = await this.decryptCID(cid)

      // Decrypt the data block
      const decryptedBlock = await this.decryptDataBlock(block)

      yield { cid: originalCID, block: decryptedBlock }
    }
  }
}
