# blockstore-enc

A JS/TS transparent encrypted wrapper around any existing Blockstore implementation.

## Features

* Data Security: Encrypts blocks to ensure privacy and security. CIDs are stored as secure hashes.
* Compatibility: Works with any Blockstore implementation conforming to the `interface-blockstore` specification.
* Strong Cryptography:
    * Uses AES-GCM for block encryption.
    * Uses HMAC-SHA256 for CID hashing.
    * Master key is derived from a password using PBKDF2.
    * Derives encryption and MAC keys from a master key using HKDF.

## Installation

```sh
npm install blockstore-enc
```

Or with Yarn:

```sh
yarn add blockstore-enc
```

## Usage

```js
import { EncBlockstore } from 'blockstore-enc';
import { FsBlockstore } from 'blockstore-fs';
import fs from 'fs';

(async () => {
  try {
    const password = 'strong-password-is-strong'; // Must be at least 16 bytes long

    // Generate or retrieve the master salt (must be at least 16 bytes)
    // If initializing for the first time, generate and store this salt securely.
    // If reopening an existing store, retrieve the salt from storage.
    let masterSalt;

    const saltFile = 'path/to/saltfile';

    if (fs.existsSync(saltFile)) {
      masterSalt = fs.readFileSync(saltFile);
    } else {
      masterSalt = crypto.getRandomValues(new Uint8Array(16));
      fs.writeFileSync(saltFile, Buffer.from(masterSalt));
    }

    const store = new EncBlockstore(new FsBlockstore('path/to/store'));
    await store.init(password, masterSalt);
    await store.open();

    // Use the store as you would use any Blockstore
    const someCid = /* your CID */;
    const someData = /* your data as Uint8Array */;
    await store.put(someCid, someData);

    const data = await store.get(someCid);
    console.log('Retrieved data:', data);
  } catch (err) {
    console.error(err);
  }
})();
```

## API

### Class: `EncBlockstore`

#### Constructor

```js
new EncBlockstore(blockstore: Blockstore, init?: EncBlockstoreInit)
```

Creates a new instance of EncBlockstore wrapping the provided blockstore.

* blockstore: The underlying Blockstore to wrap.
* init (optional): Initialization options.

#### Methods

```js
init(password: string, masterSalt: Uint8Array): Promise<void>
```

Initializes the encryption and MAC keys. Must be called before using the blockstore.
* password: The password to derive the master key from. Must be at least 16 bytes long.
* masterSalt: The master salt used for key derivation. Must be at least 16 bytes long.

```js
open(): Promise<void>
```

Opens the underlying blockstore.

```js
close(): Promise<void>
```

Closes the underlying blockstore.

```js
put(key: CID, val: Uint8Array): Promise<CID>
```

Encrypts and stores a block under the original CID.

* `key`: The original CID.
* `val`: The plaintext data to encrypt and store.
* *Returns*: The original CID.

```js
get(key: CID): Promise<Uint8Array>
```

Retrieves and decrypts a block by its original CID.

* `key`: The original CID.
* *Returns*: The decrypted plaintext data.

Deletes a block by its original CID.

* `key`: The original CID.

```js
has(key: CID): Promise<boolean>
```

Checks if a block exists by its original CID.

* `key`: The original CID.
* *Returns*: A boolean indicating existence.

```js
putMany(source: AwaitIterable<Pair>): AsyncIterable<CID>
```

Stores multiple blocks in parallel.

* `source`: An iterable of { cid, block } pairs.
* *Returns*: An async iterable of CIDs.

```js
getMany(source: AwaitIterable<CID>): AsyncIterable<Pair>
```

Retrieves multiple blocks in parallel.

* ```source```: An iterable of CIDs.
* *Returns*: An async iterable of `{ cid, block }` pairs.

```js
deleteMany(source: AwaitIterable<CID>): AsyncIterable<CID>
```

Deletes multiple blocks in parallel.

* `source`: An iterable of CIDs.
* *Returns*: An async iterable of deleted CIDs.

### Initialization Options (`EncBlockstoreInit`)
You can configure the behavior of the `EncBlockstore` using the `init` parameter.

* `pbkdf2Iterations` (number): The number of PBKDF2 iterations to use. Default: `210000` for SHA-512.
* `pbkdf2hash` ('SHA-512' | 'SHA-256'): The hash algorithm to use for PBKDF2. Default: `'SHA-512'`.
* `saltByteLength` (number): The length of the salt to use for PBKDF2. Default: `16` bytes.
* `putManyConcurrency` (number): How many blocks to put in parallel when `.putMany` is called. Default: `50`.
* `getManyConcurrency` (number): How many blocks to read in parallel when `.getMany` is called. Default: `50`.
* `deleteManyConcurrency` (number): How many blocks to delete in parallel when `.deleteMany` is called. Default: `50`.

## Cryptography Details
* **Key Derivation**:
    * Uses PBKDF2 to derive a master key from the password and master salt.
    * Default PBKDF2 settings: 210,000 iterations and SHA-512 hash function.
* **Key Expansion**:
    * Uses HKDF with SHA-256 to derive separate encryption and MAC keys from the master key.
    * The encryption key is used for per-block key derivation.
* **Per-block Encryption**:
    * For each block, a unique per-block salt is generated.
    * Uses HKDF with the per-block salt to derive a per-block encryption key.
    * The block data is encrypted using AES-GCM with a random IV.
    * The salt and IV are stored alongside the encrypted data.
* **CID Hashing**:
    * The original CID is transformed using HMAC-SHA256 with the MAC key to compute a storage CID.
    * The storage CID serves as a mapping to the original CID - it is **not** a content addressed hash of the encrypted block.
    * The storage CID is used to store and retrieve the encrypted block.

## Security Considerations
* Password and Salt:
    * The security of the encrypted blockstore depends critically on the secrecy of the password and the master salt.
    * **If either is compromised, the encrypted data may be at risk.**
    * **If either is lost, the data cannot be recovered.**

## Limitations
* No `getAll` Support:
    * Due to the one-way mapping of CIDs, the getAll() method is not supported.

* Performance Overhead:
    * Encryption and decryption operations introduce computational overhead.
