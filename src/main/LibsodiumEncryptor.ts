import {
  crypto_kdf_derive_from_key,
  crypto_secretbox_easy,
  crypto_secretbox_KEYBYTES,
  crypto_secretbox_NONCEBYTES,
  crypto_secretbox_open_easy,
  memzero,
  randombytes_buf,
} from "libsodium-wrappers"
import {
  DecryptParams,
  DecryptResult,
  Encryptor,
  EncryptParams,
  EncryptResult,
  LegacyDecryptParams
} from "./Encryptor"
import { EncryptionScheme, itemToEncrypt, KeyType } from "./types"
import { deserialize, serialize } from "./serialization"


export class LibsodiumEncryptor implements Encryptor {
  public readonly scheme = EncryptionScheme.V0_LIBSODIUM

  encrypt<T, K extends keyof T>(
    params: EncryptParams<T, K>
  ): EncryptResult<T, K> {
    const { item, fieldsToEncrypt, dataKey } = params
    const plaintextFields = { ...item } as Omit<T, K>
    const nonce = randombytes_buf(crypto_secretbox_NONCEBYTES)
    const encryptionKey = this.deriveKey(dataKey, KeyType.ENCRYPTION)

    const itemToEncrypt: itemToEncrypt<T, K> = {} as itemToEncrypt<T, K>
    fieldsToEncrypt.forEach((fieldName) => {
      const fieldValue = item[fieldName]
      if (fieldValue !== undefined && fieldValue !== null) {
        itemToEncrypt[fieldName] = fieldValue
        delete (plaintextFields as any)[fieldName]
      }
    })

    const encryptedFields = crypto_secretbox_easy(
      serialize(itemToEncrypt),
      nonce,
      encryptionKey
    )

    memzero(encryptionKey)

    return { plaintextFields, nonce, encryptedFields }
  }

  decrypt<T, K extends keyof T>(params: DecryptParams<T, K> | LegacyDecryptParams<T,K>): DecryptResult<T> {
    const { encryptedItem, nonce, dataKey } = params
    const encryptedFields = (params as DecryptParams<T, K>).encryptedFields
  
    if (!encryptedFields) {
      return this.legacyDecrypt(params as LegacyDecryptParams<T, K>)
    }

    const decryptionKey = this.deriveKey(dataKey, KeyType.ENCRYPTION)

    const jsonBytes = crypto_secretbox_open_easy(encryptedFields, nonce, decryptionKey)
    const fieldValues = deserialize(jsonBytes)

    memzero(decryptionKey)
    return {
      decryptedItem: {
        ...encryptedItem,
        ...fieldValues
      }
    }
  }

  private legacyDecrypt<T, K extends keyof T>(params: LegacyDecryptParams<T, K>): DecryptResult<T> {
    const { encryptedItem, fieldsToDecrypt, nonce, dataKey } = params
    const decryptionKey = this.deriveKey(dataKey, KeyType.ENCRYPTION)

    const decryptedItem: { [P in keyof T]: T[P] } = {
      ...encryptedItem
    } as any

    fieldsToDecrypt.forEach((fieldName) => {
      const cipherText = encryptedItem[fieldName]
      if (cipherText) {
        const jsonBytes = crypto_secretbox_open_easy(
          cipherText,
          nonce,
          decryptionKey
        )
        decryptedItem[fieldName] = deserialize(jsonBytes)
      }
    })

    memzero(decryptionKey)
    return { decryptedItem }
  }

  private deriveKey(dataKey: Uint8Array, keyType: KeyType): Uint8Array {
    const key = crypto_kdf_derive_from_key(
      crypto_secretbox_KEYBYTES,
      keyType,
      "__jayz__", // encryption context: must be 8 chars, per https://libsodium.gitbook.io/doc/key_derivation
      dataKey
    )

    return key
  }
}
