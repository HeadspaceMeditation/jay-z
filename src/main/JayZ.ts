import { memzero } from "libsodium-wrappers"
import { Encryptor, LibsodiumEncryptor } from "./encryptors"
import {
  GenerateDataKeyResult,
  KeyProvider
} from "./key-providers/DataKeyProvider"
import { EncryptedItemMetadata, EncryptedJayZItem } from "./types"

export interface JayZProps {
  keyProvider: KeyProvider
  encryptor?: Encryptor
  maxUsesPerDataKey?: number
}

export interface EncryptItemProps<T, U extends keyof T> {
  item: T
  fieldsToEncrypt: U[]
}

export class JayZ {
  private keyProvider: KeyProvider
  private encryptor: Encryptor = new LibsodiumEncryptor()
  private maxUsesPerDataKey: number
  private currentDataKey?: Promise<GenerateDataKeyResult>
  private currentDataKeyUsesRemaining: number

  constructor(config: JayZProps) {
    this.keyProvider = config.keyProvider
    this.encryptor =
      config.encryptor !== undefined
        ? config.encryptor
        : new LibsodiumEncryptor()
    this.maxUsesPerDataKey = config.maxUsesPerDataKey || 1
    this.currentDataKeyUsesRemaining = this.maxUsesPerDataKey
  }

  async encryptItem<T, U extends keyof T>(
    itemToEncrypt: EncryptItemProps<T, U>
  ): Promise<EncryptedJayZItem<T, U>> {
    const { item, fieldsToEncrypt } = itemToEncrypt
    const { plaintextKey, encryptedKey } = await this.getNextDataKey()
    const { encryptedItem, nonce } = this.encryptor.encrypt({
      item,
      fieldsToEncrypt,
      key: plaintextKey
    })

    const __jayz__metadata: EncryptedItemMetadata<T, U> = {
      encryptedDataKey: encryptedKey,
      nonce,
      version: this.encryptor.version,
      encryptedFieldNames: fieldsToEncrypt
    }

    return {
      ...encryptedItem,
      __jayz__metadata
    }
  }

  async encryptItems<T, U extends keyof T>(
    itemsToEncrypt: EncryptItemProps<T, U>[]
  ): Promise<EncryptedJayZItem<T, U>[]> {
    if (itemsToEncrypt.length === 0) {
      return []
    }

    const items = itemsToEncrypt.map((item) => this.encryptItem(item))
    return Promise.all(items)
  }

  async decryptItem<T, U extends keyof T>(
    itemToDecrypt: EncryptedJayZItem<T, U>
  ): Promise<T> {
    const { nonce, encryptedDataKey, encryptedFieldNames } =
      itemToDecrypt.__jayz__metadata

    const encryptedItem = { ...itemToDecrypt }
    delete (encryptedItem as any).__jayz__metadata

    const { plaintextKey } = await this.keyProvider.decryptDataKey(
      encryptedDataKey
    )
    const { decryptedItem } = this.encryptor.decrypt<T, U>({
      item: encryptedItem,
      fieldsToDecrypt: encryptedFieldNames,
      key: plaintextKey,
      nonce
    })

    memzero(plaintextKey)
    return decryptedItem
  }

  async decryptItems<T, U extends keyof T>(
    itemsToDecrypt: EncryptedJayZItem<T, U>[]
  ): Promise<T[]> {
    if (itemsToDecrypt.length === 0) {
      return []
    }

    const itemPromises = itemsToDecrypt.map((item) => this.decryptItem(item))
    return Promise.all(itemPromises)
  }

  private getNextDataKey(): Promise<GenerateDataKeyResult> {
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
