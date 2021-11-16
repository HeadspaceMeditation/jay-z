import {
  crypto_secretbox_easy,
  crypto_secretbox_NONCEBYTES,
  crypto_secretbox_open_easy,
  randombytes_buf
} from "libsodium-wrappers"
import { KeyProvider } from "main"
import { isLegacyJayZItem, LegacyEncryptedJayZItem, MetadataVersion } from "."
import { DecryptProps, DecryptResult, Encryptor, EncryptProps, EncryptResult } from "./Encryptor"
import { deserialize, serialize } from "./serialization"

enum LibsodiumEncryptorVersion {
  v0 = "v0_libsodium"
}

export interface LibsodiumEncryptorProps {
  keyProvider: KeyProvider
}

export class LibsodiumEncryptor implements Encryptor {
  readonly version = LibsodiumEncryptorVersion.v0
  constructor(private props: LibsodiumEncryptorProps) {}

  async encrypt<T, U extends keyof T>(props: EncryptProps<T, U>): Promise<EncryptResult<T, U>> {
    const { item } = props
    const plaintextFields = { ...item } as Omit<T, U>
    const fieldsToEncrypt = {} as Pick<T, U>

    props.fieldsToEncrypt.forEach((fieldName) => {
      delete (plaintextFields as any)[fieldName]
      const fieldValue = item[fieldName]
      if (fieldValue !== undefined) {
        fieldsToEncrypt[fieldName] = fieldValue
      }
    })

    const nonce = randombytes_buf(crypto_secretbox_NONCEBYTES)
    const key = await this.props.keyProvider.generateDataKey()
    const encryptedFields = crypto_secretbox_easy(serialize(fieldsToEncrypt), nonce, key.plaintextKey)
    return {
      encryptedItem: {
        ...plaintextFields,
        __jayz__metadata: {
          metadataVersion: MetadataVersion.V1,
          encryptedDataKey: key.encryptedKey,
          keyId: key.metadata?.keyId,
          nonce,
          encryptorId: this.version,
          encryptedFields
        }
      }
    }
  }

  async decrypt<T, U extends keyof T>(props: DecryptProps<T, U>): Promise<DecryptResult<T>> {
    const { item } = props
    if (isLegacyJayZItem(item)) {
      return this.legacyDecrypt(item)
    } else {
      const { __jayz__metadata, ...plaintextFields } = item
      const { encryptedDataKey, encryptedFields, keyId, nonce } = __jayz__metadata
      const { plaintextKey } = await this.props.keyProvider.decryptDataKey(
        encryptedDataKey,
        keyId ? { keyId } : undefined
      )
      const jsonBytes = crypto_secretbox_open_easy(encryptedFields, nonce, plaintextKey)
      return {
        decryptedItem: {
          ...plaintextFields,
          ...deserialize(jsonBytes)
        }
      }
    }
  }

  private async legacyDecrypt<T, U extends keyof T>(item: LegacyEncryptedJayZItem<T, U>): Promise<DecryptResult<T>> {
    const { __jayz__metadata, ...plaintextFields } = item
    const { encryptedDataKey, encryptedFieldNames, keyId, nonce } = __jayz__metadata
    const { plaintextKey } = await this.props.keyProvider.decryptDataKey(
      encryptedDataKey,
      keyId ? { keyId } : undefined
    )

    const decryptedItem: { [P in keyof T]: T[P] } = {
      ...plaintextFields
    } as any

    encryptedFieldNames.forEach((fieldName) => {
      const cipherText = item[fieldName]
      if (cipherText) {
        const jsonBytes = crypto_secretbox_open_easy(cipherText, nonce, plaintextKey)
        decryptedItem[fieldName] = deserialize(jsonBytes)
      }
    })

    return { decryptedItem }
  }
}
