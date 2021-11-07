import { crypto_kdf_KEYBYTES, randombytes_buf, ready } from "libsodium-wrappers"
import { DecryptDataKeyResult, GenerateDataKeyResult, KeyProvider } from "../../main/key-providers"

/** Key provider that counts the number of times it was called to generate data keys (for testing) */
export class CountingKeyProvider implements KeyProvider {
  public keysIssued = 0

  async generateDataKey(): Promise<GenerateDataKeyResult> {
    await ready
    const key = randombytes_buf(crypto_kdf_KEYBYTES)
    this.keysIssued += 1
    return {
      encryptedKey: key,
      plaintextKey: key
    }
  }

  async decryptDataKey(encryptedDataKey: Uint8Array): Promise<DecryptDataKeyResult> {
    return { plaintextKey: encryptedDataKey.slice(0) }
  }
}
