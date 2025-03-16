import lora from 'lora-packet'
import { exec } from 'child_process'
import fs from 'fs'

const hexStringToByteArray = (string) => {
  if (string.length % 2 !== 0) {
    console.error('Invalid string input length:', string.length, string)
    return
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
    let command
    if (process.platform === 'win32') {
      console.log('OS is Window')
      if (fs.existsSync('.\\asconmacav12\\out.exe')) {
        console.log('Found .exe, use it')
        command = '.\\asconmacav12\\out.exe'
      } else {
        console.log('Cannot find .exe, use the default one')
        command = '.\\asconmacav12\\out'
      }
    } else {
      /* Assuming this is Linux */
      console.log('OS IS NOT Window, use the default one')
      command = './asconmacav12/out'
    }
    command += ` "${data}" "${appkeyHexString}" "${nwkskeyHexString}"`
    const info = []
    exec(command, (error, stdout) => {
      if (error) {
        console.error(`Error: ${error.message}`, stdout.trim())
        resolve([null, null])
      }
      const lines = stdout.trim().split('\n')
      for (let i = 0; i < lines.length; i++) {
        lines[i] = lines[i].replace(/[\n\r]+/g, '')
        info.push(hexStringToByteArray(lines[i]))
      }
      resolve([info, info[0]])
    })
  })
}
