import {
  crypto_kdf_KEYBYTES,
  from_base64,
  randombytes_buf,
  ready,
  to_base64
} from "libsodium-wrappers"
import {
  DecryptDataKeyResult,
  GenerateDataKeyResult,
  KeyProvider
} from "./KeyProvider"

/** A DataKeyProvider that uses a single, fixed key. This is intended for testing  */
export class FixedKeyProvider implements KeyProvider {
  static async forLibsodium(): Promise<FixedKeyProvider> {
    await ready
    const key = randombytes_buf(crypto_kdf_KEYBYTES)
    return new FixedKeyProvider(to_base64(key))
  }

  constructor(private dataKey: string) {}

  async generateDataKey(): Promise<GenerateDataKeyResult> {
    return {
      plaintextKey: from_base64(this.dataKey),
      encryptedKey: from_base64(this.dataKey)
    }
  }

  async decryptDataKey(key: Uint8Array): Promise<DecryptDataKeyResult> {
    return { plaintextKey: key }
  }
}
