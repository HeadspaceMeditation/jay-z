import { DecryptCommand, GenerateDataKeyCommand, KMSClient } from "@aws-sdk/client-kms"
import { crypto_kdf_KEYBYTES } from "libsodium-wrappers"
import { DataKey, DataKeyProvider } from "./DataKeyProvider"

/** A KeyProvider that uses an AWS KMS CMK to generate data keys */
export class KMSDataKeyProvider implements DataKeyProvider {
  constructor(private keyId: string, private kms: KMSClient = new KMSClient({})) {}

  async generateDataKey(): Promise<DataKey> {
    const command = new GenerateDataKeyCommand({
      KeyId: this.keyId,
      NumberOfBytes: crypto_kdf_KEYBYTES
    })
    const result = await this.kms.send(command)

    const dataKey = result.Plaintext as Uint8Array
    const encryptedDataKey = result.CiphertextBlob as Uint8Array

    return {
      dataKey,
      encryptedDataKey
    }
  }

  async decryptDataKey(encryptedDataKey: Uint8Array): Promise<Uint8Array> {
    const command = new DecryptCommand({
      KeyId: this.keyId,
      CiphertextBlob: encryptedDataKey
    })
    const result = await this.kms.send(command)

    return result.Plaintext as Uint8Array
  }
}
