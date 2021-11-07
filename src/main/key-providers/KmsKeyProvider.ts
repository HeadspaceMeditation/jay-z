import {
  DecryptCommand,
  GenerateDataKeyCommand,
  KMSClient
} from "@aws-sdk/client-kms"
import { crypto_kdf_KEYBYTES } from "libsodium-wrappers"
import {
  DecryptDataKeyResult,
  GenerateDataKeyResult,
  KeyProvider
} from "./KeyProvider"

/** A KeyProvider that uses an AWS KMS CMK to generate data keys */
export class KmsKeyProvider implements KeyProvider {
  constructor(
    private keyId: string,
    private kms: KMSClient = new KMSClient({})
  ) {}

  async generateDataKey(): Promise<GenerateDataKeyResult> {
    const command = new GenerateDataKeyCommand({
      KeyId: this.keyId,
      NumberOfBytes: crypto_kdf_KEYBYTES
    })
    const result = await this.kms.send(command)
    const plaintextKey = result.Plaintext as Uint8Array
    const encryptedKey = result.CiphertextBlob as Uint8Array
    return { plaintextKey, encryptedKey }
  }

  async decryptDataKey(
    encryptedDataKey: Uint8Array
  ): Promise<DecryptDataKeyResult> {
    const command = new DecryptCommand({
      KeyId: this.keyId,
      CiphertextBlob: encryptedDataKey
    })
    const result = await this.kms.send(command)
    return { plaintextKey: result.Plaintext as Uint8Array }
  }
}
