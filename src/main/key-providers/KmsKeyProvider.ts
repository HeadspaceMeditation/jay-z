import { KMS } from "aws-sdk"
import { crypto_kdf_KEYBYTES } from "libsodium-wrappers"
import {
  DecryptDataKeyResult,
  GenerateDataKeyResult,
  KeyProvider
} from "./DataKeyProvider"

/** A KeyProvider that uses an AWS KMS CMK to generate data keys */
export class KmsKeyProvider implements KeyProvider {
  constructor(private keyId: string, private kms: KMS = new KMS()) {}

  async generateDataKey(): Promise<GenerateDataKeyResult> {
    const result = await this.kms
      .generateDataKey({
        KeyId: this.keyId,
        NumberOfBytes: crypto_kdf_KEYBYTES
      })
      .promise()

    const plaintextKey = result.Plaintext as Uint8Array
    const encryptedKey = result.CiphertextBlob as Uint8Array
    return { plaintextKey, encryptedKey }
  }

  async decryptDataKey(
    encryptedDataKey: Uint8Array
  ): Promise<DecryptDataKeyResult> {
    const result = await this.kms
      .decrypt({
        KeyId: this.keyId,
        CiphertextBlob: encryptedDataKey
      })
      .promise()

    return { plaintextKey: result.Plaintext as Uint8Array }
  }
}
