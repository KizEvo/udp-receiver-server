import lora from 'lora-packet'
import { exec } from 'child_process'

const hexStringToByteArray = (string) => {
  if (string.length % 2 !== 0) {
    throw new Error('Invalid string input length')
  }
  const byteArray = []
  for (let i = 0; i < string.length; i += 2) {
    const hexPair = string.substring(i, i + 2)
    const byte = parseInt(hexPair, 16)
    byteArray.push(byte)
  }
  return Buffer.from(byteArray)
}

// @param msg raw string data received from gateway usually in Base64 format
// @retval [payloadDecrypted, package] Unencrypted payload and the package info (which contain DevAddr, MIC, FCnt..)
export const decryptLoraRawData = (data, nwkskeyHexString, appkeyHexString) => {
  const nwkskey = Buffer.from(nwkskeyHexString, 'hex')
  const appkey = Buffer.from(appkeyHexString, 'hex')
  const packet = lora.fromWire(Buffer.from(data, 'base64'))

  console.log(
    'calculated MIC =' + lora.calculateMIC(packet, nwkskey).toString('hex')
  )
  // verify MIC success
  if (lora.verifyMIC(packet, nwkskey)) {
    console.log('MIC is correct!')
    const payloadDecrypted = lora.decrypt(packet, appkey, nwkskey)
    return [payloadDecrypted, packet]
  }
  console.log('MIC is INCORRECT!!!')
  return [null, null]
}

// @param msg raw string data received from gateway usually in Base64 format
export const decryptLoraRawDataAsconMac = async (
  data,
  nwkskeyHexString,
  appkeyHexString
) => {
  return new Promise((resolve, reject) => {
    // Pass Base64 package to C program
    const command = `./asconmacav12/out "${data}"`
    const info = []
    exec(command, (error, stdout) => {
      if (error) {
        console.error(`Error: ${error.message}`)
        resolve([null, null])
      }
      const lines = stdout.trim().split('\n')
      for (let i = 0; i < lines.length; i++) {
        info.push(hexStringToByteArray(lines[i]))
      }
      resolve([info, info[0]])
    })
  })
}
