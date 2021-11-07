import to_json from "fast-json-stable-stringify"
import { from_string, to_string } from "libsodium-wrappers"

/** Serializes a TS object to a byte array */
export function serialize(obj: any): Uint8Array {
  const json = to_json(obj)
  return from_string(json)
}

/** Deserializes a byte array to a TS object */
export function deserialize(bytes: Uint8Array): any {
  const json = JSON.parse(to_string(bytes))
  return convertJsonBuffers(json)
}
/** If an object that contains a Buffer value is serialized to json, then derserialized
 the binary field comes back as a JsonBuffer (see type below) instead of a Buffer/Uint8Array

 This function recursively converts any binary fields on  a deserialized object to Buffers
  */
function convertJsonBuffers(obj: any): any {
  if (isJsonBuffer(obj)) {
    return Buffer.from(obj)
  } else if (typeof obj === "object") {
    Object.keys(obj).forEach((key) => {
      obj[key] = convertJsonBuffers(obj[key])
    })
  }

  return obj
}

interface JsonBuffer {
  data: Array<number>
  type: "Buffer"
}

function isJsonBuffer(obj: any): obj is JsonBuffer {
  return obj !== undefined && obj.data instanceof Array && obj.type === "Buffer"
}
