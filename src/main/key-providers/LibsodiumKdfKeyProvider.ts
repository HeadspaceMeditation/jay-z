import { crypto_kdf_derive_from_key, crypto_secretbox_KEYBYTES } from "libsodium-wrappers"
import { DecryptDataKeyResult, GenerateDataKeyResult, KeyMetadata } from "main"
import { KeyProvider } from "./KeyProvider"

export interface LibsodiumKdfKeyProviderProps {
  keyProvider: KeyProvider
  numKeysToDerivePerDataKey: number
}

/** This KeyProvider caches a data key from another KeyProvider (e.g. KmsKeyProvider) and uses Libsodium's crypto_kdf_derive_from_key
 *  function to derive new data keys @param numKeysToDerivePerDataKey times before requesting a new data key.
 *
 *  This is useful when you want to use a KeyProvider like KmsKeyProvider that incurs network hops, and you want to
 *  amoritize the cost of those network requests.
 * */
export class LibsodiumKdfKeyProvider implements KeyProvider {
  private keyProvider: KeyProvider
  private key?: Promise<GenerateDataKeyResult>
  private keyId: number = 1
  private numKeysToDerivePerDataKey: number

  constructor(props: LibsodiumKdfKeyProviderProps) {
    this.keyProvider = props.keyProvider
    this.numKeysToDerivePerDataKey = props.numKeysToDerivePerDataKey
  }

  async generateDataKey(): Promise<GenerateDataKeyResult> {
    if (this.key === undefined || this.keyId >= this.numKeysToDerivePerDataKey) {
      this.key = this.keyProvider.generateDataKey()
      this.keyId = 1
    } else {
      this.keyId += 1
    }

    const key = await this.key
    const derivedKey = this.deriveKey(key.plaintextKey, this.keyId)
    const result = {
      plaintextKey: derivedKey,
      encryptedKey: key.encryptedKey, // since keys are derived, we return the original key's cipherText
      metadata: { keyId: this.keyId.toString() }
    }

    return result
  }

  async decryptDataKey(encryptedDataKey: Uint8Array, metadata?: KeyMetadata): Promise<DecryptDataKeyResult> {
    const key = await this.keyProvider.decryptDataKey(encryptedDataKey)
    const keyId = metadata ? parseInt(metadata.keyId) : 1 // the default keyId of 1 supports legacy use-cases
    const derivedKey = this.deriveKey(key.plaintextKey, keyId)
    return { plaintextKey: derivedKey }
  }

  private deriveKey(key: Uint8Array, keyId: number): Uint8Array {
    return crypto_kdf_derive_from_key(
      crypto_secretbox_KEYBYTES,
      keyId,
      "__jayz__", // encryption context: must be 8 chars, per https://libsodium.gitbook.io/doc/key_derivation
      key
    )
  }
}
