import { KMS } from "aws-sdk"
import { crypto_kdf_KEYBYTES } from "libsodium-wrappers"
import { DataKey, DataKeyProvider } from "./DataKeyProvider"

/** A KeyProvider that uses an AWS KMS CMK to generate data keys */
export class KMSDataKeyProvider implements DataKeyProvider {
  constructor(private keyId: string, private kms: KMS = new KMS({})) {}

  async generateDataKey(): Promise<DataKey> {
    const result = await this.kms
      .generateDataKey({
        KeyId: this.keyId,
        NumberOfBytes: crypto_kdf_KEYBYTES
      })
      .promise()

    const dataKey = result.Plaintext as Uint8Array
    const encryptedDataKey = result.CiphertextBlob as Uint8Array

    return {
      dataKey,
      encryptedDataKey
    }
  }

  async decryptDataKey(encryptedDataKey: Uint8Array): Promise<Uint8Array> {
    const result = await this.kms
      .decrypt({
        KeyId: this.keyId,
        CiphertextBlob: encryptedDataKey
      })
      .promise()

    return result.Plaintext as Uint8Array
  }
}
