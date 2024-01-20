import { memzero, ready } from "libsodium-wrappers"
import { DataKey, DataKeyProvider } from "./DataKeyProvider"
import { Encryptor } from "./Encryptor"
import { LibsodiumEncryptor } from "./LibsodiumEncryptor"
import { EncryptedItemMetadataV1, EncryptedJayZItem, EncryptedJayZItemV1, LegacyEncryptedItemMetadata, MetadataVersion } from "./types"

export type JayZConfig = {
  keyProvider: DataKeyProvider
  encryptor?: Encryptor
  maxUsesPerDataKey?: number
}

export type EncryptItemRequest<T, K extends keyof T> = {
  item: T
  fieldsToEncrypt: readonly K[]
}

export class JayZ {
  public readonly ready = ready
  private keyProvider: DataKeyProvider
  private encryptor: Encryptor = new LibsodiumEncryptor()
  private maxUsesPerDataKey: number
  private currentDataKey?: Promise<DataKey>
  private currentDataKeyUsesRemaining: number

  constructor(config: JayZConfig) {
    this.keyProvider = config.keyProvider
    this.encryptor =
      config.encryptor !== undefined
        ? config.encryptor
        : new LibsodiumEncryptor()
    this.maxUsesPerDataKey = config.maxUsesPerDataKey || 1
    this.currentDataKeyUsesRemaining = this.maxUsesPerDataKey
  }

  async encryptItem<T, K extends keyof T>(
    itemToEncrypt: EncryptItemRequest<T, K>
  ): Promise<EncryptedJayZItemV1<T, K>> {
    const { item, fieldsToEncrypt } = itemToEncrypt
    const { dataKey, encryptedDataKey } = await this.getNextDataKey()
    const { plaintextFields, nonce, encryptedFields } = this.encryptor.encrypt({
      item,
      fieldsToEncrypt,
      dataKey
    })

    const __jayz__metadata: EncryptedItemMetadataV1 = {
      encryptedDataKey,
      nonce,
      scheme: this.encryptor.scheme,
      encryptedFields,
      metadataVersion: MetadataVersion.V1
    }

    return {
      ...plaintextFields,
      __jayz__metadata
    }
  }

  encryptItems<T, K extends keyof T>(
    itemsToEncrypt: EncryptItemRequest<T, K>[]
  ): Promise<EncryptedJayZItem<T, K>[]> {
    if (itemsToEncrypt.length === 0) {
      return Promise.resolve([])
    }

    const items = itemsToEncrypt.map((item) => this.encryptItem(item))
    return Promise.all(items)
  }

  async decryptItem<T, K extends keyof T>(
    itemToDecrypt: EncryptedJayZItem<T, K>
  ): Promise<T> {
    const {
      nonce,
      encryptedDataKey,
    } = itemToDecrypt.__jayz__metadata

    const encryptedFields = (itemToDecrypt.__jayz__metadata as EncryptedItemMetadataV1).encryptedFields
    const encryptedFieldNames = (itemToDecrypt.__jayz__metadata as LegacyEncryptedItemMetadata<T, K>).encryptedFieldNames

    const encryptedItem = { ...itemToDecrypt }
    delete (encryptedItem as any).__jayz__metadata

    const dataKey = await this.keyProvider.decryptDataKey(encryptedDataKey)
    const { decryptedItem } = this.encryptor.decrypt<T, K>({
      encryptedItem,
      fieldsToDecrypt: encryptedFieldNames,
      dataKey,
      nonce,
      encryptedFields
    })

    memzero(dataKey)
    return decryptedItem
  }

  decryptItems<T, K extends keyof T>(
    itemsToDecrypt: EncryptedJayZItem<T, K>[]
  ): Promise<T[]> {
    if (itemsToDecrypt.length === 0) {
      return Promise.resolve([])
    }

    const itemPromises = itemsToDecrypt.map((item) => this.decryptItem(item))
    return Promise.all(itemPromises)
  }

  private getNextDataKey(): Promise<DataKey> {
    if (
      this.currentDataKey !== undefined &&
      this.currentDataKeyUsesRemaining > 0
    ) {
      this.currentDataKeyUsesRemaining -= 1
      return this.currentDataKey
    } else {
      this.currentDataKey = this.keyProvider.generateDataKey()
      this.currentDataKeyUsesRemaining = this.maxUsesPerDataKey - 1
      return this.currentDataKey
    }
  }
}
