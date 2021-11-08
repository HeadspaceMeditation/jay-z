import {
  crypto_secretbox_easy,
  crypto_secretbox_NONCEBYTES,
  crypto_secretbox_open_easy,
  randombytes_buf
} from "libsodium-wrappers"
import { KeyProvider } from "main"
import {
  DecryptProps,
  DecryptResult,
  Encryptor,
  EncryptProps,
  EncryptResult,
  ItemWithEncryptedFields
} from "./Encryptor"
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
    const { item, fieldsToEncrypt } = props
    const key = await this.props.keyProvider.generateDataKey()
    const nonce = randombytes_buf(crypto_secretbox_NONCEBYTES)

    const encryptedFields: {
      [K in U]: Uint8Array
    } = {} as ItemWithEncryptedFields<T, U>

    fieldsToEncrypt.forEach((fieldName) => {
      const fieldValue = item[fieldName]
      if (fieldValue !== undefined && fieldValue !== null) {
        encryptedFields[fieldName] = crypto_secretbox_easy(serialize(fieldValue), nonce, key.plaintextKey)
      }
    })

    const encryptedItem = {
      ...item,
      ...encryptedFields,
      __jayz__metadata: {
        encryptedDataKey: key.encryptedKey,
        keyId: key.metadata?.keyId,
        nonce,
        version: this.version,
        encryptedFieldNames: fieldsToEncrypt
      }
    }

    return { encryptedItem }
  }

  async decrypt<T, U extends keyof T>(props: DecryptProps<T, U>): Promise<DecryptResult<T>> {
    const { __jayz__metadata, ...plaintextFields } = props.item
    const { encryptedDataKey, keyId, nonce, encryptedFieldNames } = __jayz__metadata

    const decryptedItem: { [P in keyof T]: T[P] } = {
      ...plaintextFields
    } as any

    const { plaintextKey } = await this.props.keyProvider.decryptDataKey(
      encryptedDataKey,
      keyId ? { keyId } : undefined
    )

    encryptedFieldNames.forEach((fieldName) => {
      const cipherText = props.item[fieldName]
      if (cipherText) {
        const jsonBytes = crypto_secretbox_open_easy(cipherText, nonce, plaintextKey)
        decryptedItem[fieldName] = deserialize(jsonBytes)
      }
    })

    return { decryptedItem }
  }
}
