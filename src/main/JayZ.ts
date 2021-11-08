import { EncryptedJayZItem, Encryptor } from "./encryptors"

export interface JayZProps {
  encryptor: Encryptor
}

export interface EncryptItemProps<T, U extends keyof T> {
  item: T
  fieldsToEncrypt: U[]
}

export class JayZ {
  private encryptor: Encryptor

  constructor(props: JayZProps) {
    this.encryptor = props.encryptor
  }

  async encryptItem<T, U extends keyof T>(itemToEncrypt: EncryptItemProps<T, U>): Promise<EncryptedJayZItem<T, U>> {
    const { item, fieldsToEncrypt } = itemToEncrypt
    const { encryptedItem } = await this.encryptor.encrypt({ item, fieldsToEncrypt })
    return encryptedItem
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

  async decryptItem<T, U extends keyof T>(item: EncryptedJayZItem<T, U>): Promise<T> {
    const { decryptedItem } = await this.encryptor.decrypt<T, U>({ item })
    return decryptedItem
  }

  async decryptItems<T, U extends keyof T>(itemsToDecrypt: EncryptedJayZItem<T, U>[]): Promise<T[]> {
    if (itemsToDecrypt.length === 0) {
      return []
    }

    const itemPromises = itemsToDecrypt.map((item) => this.decryptItem(item))
    return Promise.all(itemPromises)
  }
}
