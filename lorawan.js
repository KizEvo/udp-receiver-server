import lora from 'lora-packet'

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
