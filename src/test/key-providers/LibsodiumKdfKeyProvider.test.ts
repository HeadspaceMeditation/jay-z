import { ready } from "libsodium-wrappers"
import { FixedKeyProvider, LibsodiumKdfKeyProvider, LibsodiumKdfKeyProviderProps } from "../../main/key-providers"
import { CountingKeyProvider } from "./CountingKeyProvider"

describe("LibsodiumKdfKeyProvider", () => {
  beforeAll(async () => await ready)

  it("should derive a data key from another key provider", async () => {
    const { sourceKeyProvider, kdfKeyProvider } = await setup()
    const sourceKey = await sourceKeyProvider.generateDataKey()
    const derivedKey = await kdfKeyProvider.generateDataKey()

    expect(derivedKey.plaintextKey).not.toEqual(sourceKey.plaintextKey)
    expect(derivedKey.encryptedKey).toEqual(sourceKey.encryptedKey) // since we derive keys, we leave the encrypted version as is
    expect(derivedKey.metadata?.keyId).toEqual("1")
  })

  it("should derive multiple data keys from another key provider", async () => {
    const { kdfKeyProvider } = await setup()
    const derivedKey1 = await kdfKeyProvider.generateDataKey()
    const derivedKey2 = await kdfKeyProvider.generateDataKey()

    expect(derivedKey1.plaintextKey).not.toEqual(derivedKey2.plaintextKey)
    expect(derivedKey1.encryptedKey).toEqual(derivedKey2.encryptedKey) // since keys are derived they use the same encrypted version
    expect(derivedKey1.metadata?.keyId).toEqual("1")
    expect(derivedKey2.metadata?.keyId).toEqual("2")
  })

  it("should decrypt encrypted data keys returned by key provider", async () => {
    const { kdfKeyProvider } = await setup()
    const derivedKey1 = await kdfKeyProvider.generateDataKey()
    const decryptedKey1 = await kdfKeyProvider.decryptDataKey(derivedKey1.encryptedKey, derivedKey1.metadata)

    const derivedKey2 = await kdfKeyProvider.generateDataKey()
    const decryptedKey2 = await kdfKeyProvider.decryptDataKey(derivedKey2.encryptedKey, derivedKey2.metadata)

    expect(decryptedKey1.plaintextKey).toEqual(derivedKey1.plaintextKey)
    expect(decryptedKey2.plaintextKey).toEqual(derivedKey2.plaintextKey)
    expect(decryptedKey1.plaintextKey).not.toEqual(derivedKey2.plaintextKey)
  })

  it("should decrypt a legacy format encrypted data key that has no metadata", async () => {
    const { kdfKeyProvider } = await setup()
    const derivedKey = await kdfKeyProvider.generateDataKey()
    const decryptedKey = await kdfKeyProvider.decryptDataKey(derivedKey.encryptedKey)
    expect(decryptedKey.plaintextKey).toEqual(derivedKey.plaintextKey)
  })

  it("should reuse data key from source until numKeysToDerivePerDataKey threshold reached", async () => {
    const counter = new CountingKeyProvider()
    const { kdfKeyProvider } = await setup({ keyProvider: counter, numKeysToDerivePerDataKey: 2 })

    await Promise.all([
      kdfKeyProvider.generateDataKey(),
      kdfKeyProvider.generateDataKey(),
      kdfKeyProvider.generateDataKey()
    ])

    expect(counter.keysIssued).toEqual(2)
  })
})

async function setup(props?: Partial<LibsodiumKdfKeyProviderProps>) {
  const sourceKeyProvider = await FixedKeyProvider.forLibsodium()
  const kdfKeyProvider = new LibsodiumKdfKeyProvider({
    keyProvider: sourceKeyProvider,
    numKeysToDerivePerDataKey: 100,
    ...props
  })

  return { sourceKeyProvider, kdfKeyProvider }
}
