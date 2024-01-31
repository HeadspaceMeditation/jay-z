import {
  crypto_kdf_KEYBYTES,
  from_base64,
  randombytes_buf,
  ready,
  to_base64
} from "libsodium-wrappers"
import { DataKey, DataKeyProvider } from "./DataKeyProvider"

/** A DataKeyProvider that uses a single, fixed key. This is intended for testing  */
export class FixedDataKeyProvider implements DataKeyProvider {
  static async forLibsodium(): Promise<FixedDataKeyProvider> {
    await ready
    const key = randombytes_buf(crypto_kdf_KEYBYTES)
    return new FixedDataKeyProvider(to_base64(key))
  }

  constructor(private dataKey: string) {}

  async generateDataKey(): Promise<DataKey> {
    return {
      encryptedDataKey: from_base64(this.dataKey),
      dataKey: from_base64(this.dataKey)
    }
  }

  async decryptDataKey(encryptedDataKey: Uint8Array): Promise<Uint8Array> {
    return encryptedDataKey
  }
}
