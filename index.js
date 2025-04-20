// Reference
// https://github.com/Lora-net/packet_forwarder/blob/master/PROTOCOL.TXT
//
// WHERE TO START ?
// The server.on('message') event is the main event which capture the UDP
// packet forwarder from the gateway then from there we process the data

import 'dotenv/config'
import dgram from 'dgram'
import crypto from 'crypto'
import express from 'express'
import path from 'path'
import { fileURLToPath } from 'url'
import { dirname } from 'path'
import { spawn } from 'child_process'

import {
  decryptLoraRawData,
  decryptLoraRawDataAsconMac,
  encryptLoraDataAsconMac,
  lorawanProcessJoinRequest,
  lorawanProcessJoinAccept,
} from './lorawan.js'

// Import the functions you need from the SDKs you need
import { initializeApp } from 'firebase/app'
import {
  getFirestore,
  doc,
  collection,
  setDoc,
  getDocs,
  getDoc,
  updateDoc,
  addDoc,
} from 'firebase/firestore'
import { getAuth, signInWithEmailAndPassword } from 'firebase/auth'

const __filename = fileURLToPath(import.meta.url)
const __dirname = dirname(__filename)

// Device info, get defined devices
const devicesInfo = new Map()

// Firebase configuration
const firebaseConfig = {
  apiKey: process.env.FB_API_KEY,
  authDomain: process.env.FB_AUTH_DOMAIN,
  projectId: process.env.FB_PROJECT_ID,
  storageBucket: process.env.FB_STORAGE_BUCKET,
  messagingSenderId: process.env.FB_MSG_SENDER_ID,
  appId: process.env.FB_APP_ID,
  measurementId: process.env.FB_MEASUREMENT_ID,
}

// Initialize Firebase
const firebaseApp = initializeApp(firebaseConfig)
const firebaseAuth = getAuth(firebaseApp)
const firebaseDb = getFirestore(firebaseApp)

const sensorDevColl = 'sensorDevCollection'

const SERVER_PORT = 1700

const UDP_PACKET_PROTOCOL_VERSION_OFFSET = 0
const UDP_PACKET_RANDOM_TOKEN_OFFSET = 1
const UDP_PACKET_TYPE_OFFSET = 3
const UDP_PACKET_GATEWAY_UID_OFFSET = 4
const UDP_PACKET_JSON_OBJ_OFFSET = 12

const ASCON_MAC_DATA_OFFSET = {
  PAYLOAD: 0,
  TIME_ELAPSED: 1,
  DEV_ADDR: 2,
  FCNT: 3,
  FPORT: 4,
  MHDR: 5,
}

const UDP_PACKET_TYPE = {
  PUSH_DATA: 0x00,
  PUSH_ACK: 0x01,
  PULL_DATA: 0x02,
  PULL_ACK: 0x04,
}
const UDP_PKT_FWD_STATES = {
  IDLE: 0x00,
  UPSTREAM: 0x01,
  DOWNSTREAM: 0x02,
  UNKNOWN: 0x3,
}

const FPORT_APP = {
  TEMP_HUMI_SENSOR: 0x01,
}

let udpPktFwdState = UDP_PKT_FWD_STATES.IDLE
let PULL_DATA_RECEIVED = false
let GW_PORT
let GW_ADDR

// Setup local devices Map
try {
  const devicesInfoQuerySnapshot = await getDocs(
    collection(firebaseDb, sensorDevColl)
  )
  devicesInfoQuerySnapshot.forEach((doc) => {
    const docData = doc.data()
    if (doc.id.length == 8) {
      const info = {
        appskey: docData.appskey,
        nwkskey: docData.nwkskey,
        downlink: 0,
      }
      devicesInfo.set(doc.id, { abp: info })
    } else {
      const { deviceData, deviceSessionData } = docData
      devicesInfo.set(doc.id, { otaa: { deviceData, deviceSessionData } })
    }
    console.log('Device:', doc.id, devicesInfo.get(doc.id))
  })
  console.log('Total available devices on startup', devicesInfo.size)
} catch (error) {
  console.error('[ERROR] Failed to get devices:', error.message)
}

// Admin global variable
let ADMIN_LOGGED_IN = false

// Initialize express (for admin page)
const app = express()
const appPort = 3030

// Content Header application/json
app.use(express.json())
// HTML form
app.use(express.urlencoded({ extended: true }))

app.get('/admin/login', (req, res) => {
  ADMIN_LOGGED_IN = false
  res.sendFile(path.join(__dirname, 'static', 'admin-login.html'))
})

app.post('/admin/dashboard', async (req, res) => {
  const { email, pwd } = req.body
  try {
    // Authenticate with Firebase
    if (!ADMIN_LOGGED_IN) {
      await signInWithEmailAndPassword(firebaseAuth, email, pwd)
    }
    ADMIN_LOGGED_IN = true
    res.sendFile(path.join(__dirname, 'static', 'admin-dashboard.html'))
  } catch (error) {
    console.error('[ERROR] Admin auth error:', error.message)
    res.status(401).send('Login failed, check email or password')
  }
})

app.post('/admin/provision-device', async (req, res) => {
  try {
    if (!ADMIN_LOGGED_IN) {
      throw new Error('User has not logged in')
    }
    res.sendFile(path.join(__dirname, 'static', 'admin-provision-device.html'))
  } catch (error) {
    console.error('[ERROR] Provision device:', error.message)
    res.status(401).send('Provision device failed')
  }
})

// Helper function to generate a random hex string
const generateRandomHex = (length) => {
  const characters = '0123456789ABCDEF'
  let result = ''
  for (let i = 0; i < length; i++) {
    result += characters.charAt(Math.floor(Math.random() * characters.length))
  }
  return result
}

app.post('/admin/create-new-device', async (req, res) => {
  try {
    if (!ADMIN_LOGGED_IN) {
      throw new Error('User has not logged in')
    }
    let { appkey, deveui, appeui } = req.body
    deveui = deveui.toUpperCase()
    appkey = appkey.toUpperCase()
    appeui = appeui.toUpperCase()
    // 'placeholder' only, do not use it before join-accept
    const appskey = ''
    const devaddr = ''
    const nwkskey = ''
    const downlink = 0
    const uplink = 0
    const created = Date.now()
    // Create document data
    const deviceSessionData = {
      appskey,
      devaddr,
      nwkskey,
      downlink,
      uplink,
      created: 0,
      joinAccept: false,
    }
    const deviceData = {
      appkey,
      deveui,
      appeui,
      created,
    }

    // Add devices to local Map
    devicesInfo.set(deveui, { otaa: { deviceData, deviceSessionData } })

    // Add document to sensorDevCollection using setDoc
    await setDoc(doc(firebaseDb, sensorDevColl, deveui), {
      deviceData,
      deviceSessionData,
    })

    // Respond with the stringified deviceData
    res.status(200).send(`<!DOCTYPE html>
                          <html>
                            <body>
                            <h1>New device created</h1>
                            <h2>Device session keys</h2>
                            ${JSON.stringify(deviceSessionData)}
                            <h2>Device keys</h2>
                            ${JSON.stringify(deviceData)}
                            </br>
                            </br>
                              <form action="/admin/dashboard" method="post">
                                <input type="submit" value="Return to dashboard" />
                              </form>
                            </body>
                          </html>`)
  } catch (error) {
    console.error('[ERROR] Admin create new device:', error.message)
    res.status(401).send('Unauthorized access')
  }
})

app.get('/admin/list-devices', async (req, res) => {
  try {
    if (!ADMIN_LOGGED_IN) {
      throw new Error('User has not logged in')
    }

    // Reference to the sensorDevCollection
    const devicesRef = collection(firebaseDb, sensorDevColl)
    const querySnapshot = await getDocs(devicesRef)

    // Build HTML string
    let string = '<!DOCTYPE html> <html> <body> <h1> Device list </h1> <ul>'
    querySnapshot.forEach((doc) => {
      const docData = doc.data()
      if (doc.id.length == 8) {
        string += `
        <ul>
          <li><b>ABP: ${doc.id}</b></li>
          <li>appskey: ${docData.appskey}</li>
          <li>devaddr: ${docData.devaddr}</li>
          <li>nwkskey: ${docData.nwkskey}</li>
          <li>created: ${docData.created}</li>
        </ul>
        </br>
      `
      } else {
        const { deviceData, deviceSessionData } = docData
        string += `
        <ul>
          <li><b>OTAA: ${doc.id}</b></li>
          <li>Device Info</li>
          <li>appkey: ${deviceData.appkey}</li>
          <li>appeui: ${deviceData.appeui}</li>
          <li>deveui: ${deviceData.deveui}</li>
          <li>created: ${deviceData.created}</li>
          </br>
          <li>Device Session Info</li>
          <li>appskey: ${deviceSessionData.appskey}</li>
          <li>nwkskey: ${deviceSessionData.nwkskey}</li>
          <li>devaddr: ${deviceSessionData.devaddr}</li>
          <li>downlink: ${deviceSessionData.downlink}</li>
          <li>uplink: ${deviceSessionData.uplink}</li>
          <li>joined: ${deviceSessionData.joinAccept}</li>
          <li>created: ${deviceSessionData.created}</li>
        </ul>
        </br>
      `
      }
    })
    string +=
      '</ul> <form action="/admin/dashboard" method="post"> <input type="submit" value="Return to dashboard" /> </form> </body></html>'
    res.status(200).send(string)
  } catch (error) {
    console.error('[ERROR] Admin list-devices:', error.message)
    res.status(401).send('Unauthorized access')
  }
})

let mostRecentDevice = []

app.get('/admin/reliability-test-start', async (req, res) => {
  let isError = false
  try {
    if (!ADMIN_LOGGED_IN) {
      throw new Error('User has not logged in')
    }
    const date = new Date()
    const dateString = date.toDateString().replaceAll(' ', '')
    const sensorDevMetaColl = 'sensorMetadataCollection' + dateString

    const devicesMetadataQuerySnapshot = await getDocs(
      collection(firebaseDb, sensorDevMetaColl)
    )
    console.log('Run reliability test, finding most recent device...')
    let mostRecentDeviceTimestamp = 0
    devicesMetadataQuerySnapshot.forEach((doc) => {
      const data = doc.data()
      if (mostRecentDeviceTimestamp < data.time_ms) {
        mostRecentDeviceTimestamp = data.time_ms
        mostRecentDevice = [doc.id, data, [], [], [], [], []]
      }
    })
    if (mostRecentDevice.length > 0) {
      console.log('Found:', mostRecentDevice[0])
    } else {
      throw new Error('Cannot found a running device')
    }
  } catch (error) {
    console.error('[ERROR] Reliability start:', error.message)
    isError = true
  }
  res.status(200).send(`<!DOCTYPE html>
                          <html>
                            <body>
                            <h1>${isError ? 'Failed' : 'Starting'}</h1>
                            </br>
                            </br>
                              <form action="/admin/dashboard" method="post">
                                <input type="submit" value="Return to dashboard" />
                              </form>
                            </body>
                          </html>`)
})

const findMissingPackages = (arr) => {
  // Check if array is empty or undefined
  if (!arr || arr.length === 0) {
    return []
  }

  let offset = arr[0]
  for (let i = 0; i < arr.length; i++) {
    arr[i] += 1 - offset
  }

  // Get the maximum number to know the full range
  const maxNum = Math.max(...arr)

  // Create a Set for O(1) lookup
  const numSet = new Set(arr)

  // Array to store missing numbers
  const missing = []

  // Check each number from 1 to maxNum
  for (let i = 1; i <= maxNum; i++) {
    if (!numSet.has(i)) {
      missing.push(i)
    }
  }

  return missing
}

app.get('/admin/reliability-test-end', async (req, res) => {
  let isError = false
  try {
    if (!ADMIN_LOGGED_IN) {
      throw new Error('User has not logged in')
    }
    console.log('End reliability test, find device under test...')
    const missedPackage = findMissingPackages(mostRecentDevice[4])
    if (mostRecentDevice.length >= 1) {
      console.log('====================== TEST SUMMARY ======================')
      console.log('Total package sent:', mostRecentDevice[3].length)
      console.log('Total failed package:', mostRecentDevice[2].length)
      console.log('Total missing package:', missedPackage.length)
      console.log(
        'Average LSNR:',
        mostRecentDevice[5].reduce((a, b) => a + b, 0) /
          mostRecentDevice[5].length
      )
      console.log(
        'Average RSSI:',
        mostRecentDevice[6].reduce((a, b) => a + b, 0) /
          mostRecentDevice[6].length
      )
    } else {
      throw new Error('Cannot found device under test')
    }
    // Start python plot
    const py = spawn('python', ['reltest.py'])
    py.stdin.write(
      JSON.stringify([
        mostRecentDevice[3],
        mostRecentDevice[2],
        missedPackage,
        mostRecentDevice[5],
        mostRecentDevice[6],
      ])
    )
    py.stdout.on('data', (data) => {
      console.log(data.toString())
    })
    py.stdin.end()
  } catch (error) {
    console.error('[ERROR] Reliability end :', error.message)
    isError = true
  }
  mostRecentDevice = []
  // Return result
  res.status(200).send(`<!DOCTYPE html>
                          <html>
                            <body>
                            <h1>${isError ? 'Failed' : 'Ending'}</h1>
                            </br>
                            </br>
                              <form action="/admin/dashboard" method="post">
                                <input type="submit" value="Return to dashboard" />
                              </form>
                            </body>
                          </html>`)
})

const processDownlinkMessage = async (dataInput, encrypt) => {
  try {
    if (!PULL_DATA_RECEIVED) {
      throw new Error("Data exchange hasn't been initialized by gateway")
    }
    let dataString
    let rfSize
    // Generate random token
    const randomToken = Buffer.from([
      Math.floor(Math.random() * 15),
      Math.floor(Math.random() * 15),
    ])
    // Encrypt data
    if (encrypt) {
      const { devaddr, data } = dataInput
      if (!devicesInfo.has(devaddr)) {
        throw new Error('Undefined device address')
      }
      const { otaa } = devicesInfo.get(devaddr)
      if (otaa) {
        throw new Error('Currently OTAA downlink by app is unsupported')
      }
      const { abp } = devicesInfo.get(devaddr)
      dataString = await encryptLoraDataAsconMac(
        data,
        abp.nwkskey,
        abp.appskey,
        devaddr,
        abp.downlink,
        200
      )
      // Update F_CNT for downlink
      abp.downlink = abp.downlink + 1
      devicesInfo.set(devaddr, { abp: abp })
      // 13 LoRaWAN protocol package
      rfSize = data.length + 13
      console.log('Downlink device', devaddr)
      console.log('Downlink f_cnt:', abp.downlink)
    } else {
      // Do not encrypt data, packet is prepared
      dataString = dataInput
      rfSize = dataString.length / 2 // Since input is in the format of hex string
    }
    const dataBuffer = Buffer.from(dataString, 'hex')
    const dataBase64 = dataBuffer.toString('base64')

    // Generate JSON string and receive data
    const json = `{"txpk":{"imme":true,"freq":921.4,"rfch":0,"powe":14,"modu":"LORA","datr":"SF7BW125","codr":"4/8","ipol":false,"prea":8,"size":${rfSize},"data":"${dataBase64}"}}`
    const prefix = Buffer.from([0x02, ...randomToken, 0x03])
    const jsonBuffer = Buffer.from(json, 'utf8')
    const msg = Buffer.concat([prefix, jsonBuffer])

    console.log('Downlink random token:', randomToken)
    console.log('Downlink data', JSON.parse(json))

    return msg
  } catch (error) {
    console.log('[ERROR] Process downlink message:', error.message)
  }
  return null
}

// Downlink
app.post('/client/downlink', async (req, res) => {
  try {
    console.log('Downstream initialized by application server')
    const msg = await processDownlinkMessage(req.body, 1)
    if (msg) {
      // Send data to gateway
      server.send(msg, GW_PORT, GW_ADDR)
      res.status(200).send('\nDownstream initialized success\n')
    }
  } catch (error) {
    console.error('[ERROR] Downlink:', error.message)
  }
  res.status(401).send('\nFailed to init downstream\n')
})

// Start express server
app.listen(appPort, () => {
  console.log(`Example app listening on port ${appPort}`)
})

const server = dgram.createSocket('udp4')

// @param packetType UDP_PACKET_TYPE object member
// @param randomToken The token received from client (2 bytes)
// @param port The client UDP opened port
// @param address the client address
const sendServerAck = (packetType, randomToken, port, address) => {
  // 0x02 protocol version
  const msg = Buffer.from([0x02, ...randomToken, packetType])
  server.send(msg, port, address)
  console.log('Sending ACK:')
  console.log(msg)
}

// Main entry of UDP package
server.on('message', (msg, rinfo) => {
  console.log('\nUDP package received')

  if (udpPktFwdState == UDP_PKT_FWD_STATES.IDLE) {
    // If current state is IDLE and receive new packet, we check if it's upstream or downstream
    if (msg[UDP_PACKET_TYPE_OFFSET] == UDP_PACKET_TYPE.PUSH_DATA) {
      udpPktFwdState = UDP_PKT_FWD_STATES.UPSTREAM
    } else if (msg[UDP_PACKET_TYPE_OFFSET] == UDP_PACKET_TYPE.PULL_DATA) {
      udpPktFwdState = UDP_PKT_FWD_STATES.DOWNSTREAM
      PULL_DATA_RECEIVED = true
      GW_ADDR = rinfo.address
      GW_PORT = rinfo.port
    } else {
      udpPktFwdState = UDP_PKT_FWD_STATES.UNKNOWN
    }
  }
  // Get random token from package
  let randomToken
  if (udpPktFwdState != UDP_PKT_FWD_STATES.UNKNOWN) {
    randomToken = Buffer.from([
      msg[UDP_PACKET_RANDOM_TOKEN_OFFSET],
      msg[UDP_PACKET_RANDOM_TOKEN_OFFSET + 1],
    ])
    console.log('Token: ')
    console.log(randomToken)
  }
  // Send ACK based on package type
  if (udpPktFwdState == UDP_PKT_FWD_STATES.UPSTREAM) {
    sendServerAck(
      UDP_PACKET_TYPE.PUSH_ACK,
      randomToken,
      rinfo.port,
      rinfo.address
    )
    console.log('Upstream package type')
  } else if (udpPktFwdState == UDP_PKT_FWD_STATES.DOWNSTREAM) {
    sendServerAck(
      UDP_PACKET_TYPE.PULL_ACK,
      randomToken,
      rinfo.port,
      rinfo.address
    )
    console.log('Downstream package type')
  } else {
    console.log('Unknown UDP packet forwarder type, check gateway')
  }
  // Process data
  networkServerProcessData(udpPktFwdState, msg)

  // Reset state
  udpPktFwdState = UDP_PKT_FWD_STATES.IDLE
})

function delay(time) {
  return new Promise((resolve) => setTimeout(resolve, time))
}

const processJoinAccept = async (
  loraNodeDevNonceStr,
  loraNodeDevEUIBeStr,
  appkey,
  rxpkInfo
) => {
  // rxpkInfo is used to read coding rate and data rate from device
  // so that it can set join-accept DLSettings correctly
  // This is unused for now
  try {
    console.log('Process join-accept message')
    if (!devicesInfo.has(loraNodeDevEUIBeStr)) {
      // Sanity check
      throw new Error('Device has not been provisioned yet:')
    }
    const data = {
      appNonce: generateRandomHex(6),
      devAddr: '0A' + generateRandomHex(6), // See NwkID for netID and DevAddr on OTAA
      devNonce: loraNodeDevNonceStr,
      dlSettings: '02', // RX1DROffset = 0 and RX2 is DR2
      rxDelay: '01', // Delay 1 second
      netId: '458C0A', // 7 LSB = 0A
    }
    const dataJoinAccept = await lorawanProcessJoinAccept(data, appkey)
    if (dataJoinAccept == null) {
      throw new Error('Failed to process join-accept message')
    }
    // Next step: store this info (local and db)
    const { otaa } = devicesInfo.get(loraNodeDevEUIBeStr)
    if (!otaa) {
      throw new Error('Device OTAA info is unvalid')
    }
    const { deviceData, deviceSessionData } = otaa
    deviceSessionData.nwkskey = dataJoinAccept[0].toString('hex').toUpperCase()
    deviceSessionData.appskey = dataJoinAccept[1].toString('hex').toUpperCase()
    deviceSessionData.created = Date.now()
    deviceSessionData.joinAccept = true
    deviceSessionData.devaddr = data.devAddr

    // Update local
    devicesInfo.set(loraNodeDevEUIBeStr, {
      otaa: { deviceData, deviceSessionData },
    })
    // Update db session field
    await updateDoc(doc(firebaseDb, sensorDevColl, loraNodeDevEUIBeStr), {
      deviceData: deviceData,
      deviceSessionData: deviceSessionData,
    })
    // Transmit frame to device
    const dataInput = dataJoinAccept[2].toString('hex').toUpperCase()
    const msg = await processDownlinkMessage(dataInput, 0)
    // Wait for device to set receive window
    console.log('Wait few seconds for device to set receive window')
    await new Promise((resolve) => setTimeout(resolve, 5000))
    if (msg) {
      // Send data to gateway
      server.send(msg, GW_PORT, GW_ADDR)
      console.log('Join-accept sent', dataInput, 'to gateway')
      return 1
    }
  } catch (error) {
    console.error('[ERROR] Join accept process:', error.message)
  }
  return 0
}

const processJoinRequest = async (dataBase64, loraPktHex) => {
  const resultData = {
    loraNodeDevNonceStr: null,
    loraNodeDevEUIBeStr: null,
    appkey: null,
  }
  try {
    console.log('Process join-request message')
    const loraNodeAppEUIArr = bufferLeToBe(
      Buffer.from(loraPktHex.slice(2, 18), 'hex'),
      8
    )
    const loraNodeDevEUIArr = bufferLeToBe(
      Buffer.from(loraPktHex.slice(18, 34), 'hex'),
      8
    )
    const loraNodeDevEUI = Buffer.from(loraNodeDevEUIArr)
      .toString('hex')
      .toUpperCase()
    const loraNodeAppEUI = Buffer.from(loraNodeAppEUIArr)
      .toString('hex')
      .toUpperCase()
    if (!devicesInfo.has(loraNodeDevEUI)) {
      throw new Error('Device has not been provisioned yet:')
    }
    const { otaa } = devicesInfo.get(loraNodeDevEUI)
    if (!otaa) {
      throw new Error('Device OTAA info is unvalid')
    }
    const { deviceData, deviceSessionData } = otaa
    if (deviceData.appeui != loraNodeAppEUI) {
      throw new Error('Device AppEUI does not match Network server AppEUI')
    }
    // Confirm MIC is correct
    const result = await lorawanProcessJoinRequest(
      dataBase64,
      deviceData.appkey
    )
    // Other logic to reject if any
    /* Waiting */
    if (!result) {
      throw new Error('Failed to confirm MIC')
    }
    const loraNodeDevNonceArr = bufferLeToBe(
      Buffer.from(loraPktHex.slice(34, 38), 'hex'),
      2
    )
    resultData.loraNodeDevNonceStr = Buffer.from(loraNodeDevNonceArr)
      .toString('hex')
      .toUpperCase()
    resultData.loraNodeDevEUIBeStr = loraNodeDevEUI
    resultData.appkey = deviceData.appkey
    return resultData
  } catch (error) {
    console.error('[ERROR] Process join request:', error.message)
  }
  return resultData
}

// @param state UDP_PKT_FWD_STATES object member
// @param buff The msg Buffer type
const networkServerProcessData = async (state, buff) => {
  console.log('Process LoRa package..')
  try {
    if (state == UDP_PKT_FWD_STATES.UPSTREAM) {
      const jsonObject = pushDataBuffToJsonObject(buff)
      console.log(jsonObject)
      if (!jsonObject.rxpk) {
        return
      }
      // rxpk may contain multiple RF package
      // so we loop through to check
      for (let i = 0; i < jsonObject.rxpk.length; i++) {
        const startTimer = Date.now()
        console.log('###### Decrypt package, start time in ms:', startTimer)
        // Create a buffer from the string
        const loraPktBase64 = jsonObject.rxpk[i].data
        const loraPktBuf = Buffer.from(loraPktBase64, 'base64')
        // Turn to hex string
        const loraPktHex = loraPktBuf.toString('hex')
        // Get LoRa MHDR
        const loraNodeMHDR = Buffer.from(loraPktHex.slice(0, 2), 'hex')[0]
        // Package is join-request
        if (loraNodeMHDR == 0) {
          const { loraNodeDevNonceStr, loraNodeDevEUIBeStr, appkey } =
            await processJoinRequest(loraPktBase64, loraPktHex)
          if (loraNodeDevEUIBeStr == null) {
            continue
          }
          // Join-request accepted, process with join-accept
          await processJoinAccept(
            loraNodeDevNonceStr,
            loraNodeDevEUIBeStr,
            appkey,
            jsonObject.rxpk[i]
          )
          continue
        }
        // Get LoRa node address
        let loraNodeAddressLittleEndian = loraPktHex.slice(2, 10).toUpperCase()
        if (loraNodeAddressLittleEndian.length % 2 !== 0) {
          throw new Error('Hex string must have an even length')
        }
        // Split the hex string into an array of 2-character chunks (bytes)
        const bytes = []
        for (let j = 0; j < loraNodeAddressLittleEndian.length; j += 2) {
          bytes.push(loraNodeAddressLittleEndian.slice(j, j + 2))
        }
        // Reverse the bytes to convert from little-endian to big-endian
        const loraNodeAddress = bytes.reverse().join('')
        if (!devicesInfo.has(loraNodeAddress)) {
          throw new Error(`Unknown device address ${loraNodeAddress}`)
        }
        const { otaa } = devicesInfo.get(loraNodeAddress)
        if (otaa) {
          throw new Error('Currently OTAA in unsupported')
        }
        const { abp } = devicesInfo.get(loraNodeAddress)
        const [data, packet] = await decryptLoraRawDataAsconMac(
          jsonObject.rxpk[i].data,
          abp.nwkskey,
          abp.appskey
        )
        const endTimer = Date.now()
        console.log('###### Finish, end time in ms:', endTimer)
        console.log('Time elapsed in ms:', endTimer - startTimer)
        const date = new Date()
        const dateString = date.toDateString().replaceAll(' ', '')
        const sensorDevMetaColl = 'sensorMetadataCollection' + dateString
        if (data == null) {
          console.log(`Failed to decrypt package inst ${i}`)
          // If test enabled, save failed package count
          if (
            mostRecentDevice.length >= 1 &&
            mostRecentDevice[0] === loraNodeAddress
          ) {
            mostRecentDevice[2].push(mostRecentDevice[3].length + 1)
          }
          // Check next package
          continue
        }

        console.log(`RF captured data inst ${i}:`)
        console.log(
          'Actual time elapsed in microsec:',
          data[ASCON_MAC_DATA_OFFSET.TIME_ELAPSED].readUInt32BE(0)
        )
        console.log('DevAddress:', data[ASCON_MAC_DATA_OFFSET.DEV_ADDR])
        console.log('FPort:', data[ASCON_MAC_DATA_OFFSET.FPORT])
        console.log('MHDR:', data[ASCON_MAC_DATA_OFFSET.MHDR])
        console.log('FCnt:', data[ASCON_MAC_DATA_OFFSET.FCNT])
        const data_packet = []
        const fport = data[ASCON_MAC_DATA_OFFSET.FPORT].readInt8()
        data_packet.push(...data[ASCON_MAC_DATA_OFFSET.PAYLOAD])
        const sensorDoc = {
          time_ms: Date.now(),
          fport: fport,
          dev_addr: loraNodeAddress,
          data: data_packet,
          data_size: data_packet.length,
        }
        // If test enabled, don't write to db
        if (
          mostRecentDevice.length >= 1 &&
          mostRecentDevice[0] === loraNodeAddress
        ) {
          if (data_packet.length < 5) {
            throw new Error(
              `[Test] Message size of ${data_packet.length} is invalid, the correct size is 5`
            )
          }
          // The upper two bytes are zero, format to test
          if (data_packet[4] == 0) {
            // Write time_elapsed of encryption process on MCU to local storage
            mostRecentDevice[3].push(
              (data_packet[2] << 16) | (data_packet[1] << 8) | data_packet[0]
            )
            const fcntByte = data[ASCON_MAC_DATA_OFFSET.FCNT]
            mostRecentDevice[4].push((fcntByte[0] << 8) | fcntByte[1])
            mostRecentDevice[5].push(jsonObject.rxpk[i].lsnr)
            mostRecentDevice[6].push(jsonObject.rxpk[i].rssi)
          } else {
            // Received invalid format, alert the user
            console.log(
              '[Test] Received incorrect test format or different device address',
              data_packet,
              loraNodeAddress
            )
          }
          console.log(
            '[Test] Store info to local storage success, encrypted data size tested:',
            data_packet[3]
          )
          console.log('[Test] Package count:', mostRecentDevice[3].length)
          // Check next package
          continue
        }
        // Write to firebase
        const id = crypto.randomBytes(16).toString('hex')
        const coll = 'sensorDataCollection' + fport + dateString
        const docRef = doc(firebaseDb, coll, id)
        await setDoc(docRef, sensorDoc)
        console.log('Document written with id and col:', id, coll)
        // Update device metadata
        const sensorDevMetadataDoc = {
          package_count: 1,
          time_ms: sensorDoc.time_ms,
        }
        const devicesMetadataQuerySnapshot = await getDocs(
          collection(firebaseDb, sensorDevMetaColl)
        )
        let pkt_count = 0
        devicesMetadataQuerySnapshot.forEach((doc) => {
          const data = doc.data()
          if (doc.id === loraNodeAddress) {
            pkt_count = data.package_count
            console.log('Found matching device metadata')
          }
        })
        // No device
        if (pkt_count <= 0) {
          const sensorDevMetadataRef = doc(
            firebaseDb,
            sensorDevMetaColl,
            loraNodeAddress
          )
          await setDoc(sensorDevMetadataRef, sensorDevMetadataDoc)
          console.log(
            'Create new device metadata with id and col:',
            loraNodeAddress,
            sensorDevMetaColl
          )
        } else {
          // Found a device
          await updateDoc(doc(firebaseDb, sensorDevMetaColl, loraNodeAddress), {
            package_count: pkt_count + 1,
            time_ms: sensorDoc.time_ms, // Update timestamp to check most recent active device
          })
          console.log(
            'Updated device metadata for doc id and col:',
            loraNodeAddress,
            sensorDevMetaColl
          )
        }
      }
    } else if ((state = UDP_PKT_FWD_STATES.DOWNSTREAM)) {
      console.log('No support for downstream data processing yet')
    } else {
      console.log('Unknown packet forwarder state for data processing')
    }
  } catch (error) {
    console.error('[ERROR] Process data:', error.message)
  }
}

const bufferLeToBe = (buffer, length) => {
  const result = []
  for (let i = 0; i < length; i++) {
    result.push(buffer[length - 1 - i])
  }
  return result
}

// @param buff The msg Buffer type
const pushDataBuffToJsonObject = (buff) => {
  const jsonObjectSize = buff.length - 12 // Ignore the first 12 bytes of upstream PUSH_DATA
  const jsonObjectBuff = Buffer.alloc(jsonObjectSize)
  buff.copy(jsonObjectBuff, 0, 12, 12 + jsonObjectSize) // json contents of buff starts at index 12 of PUSH_DATA
  const jsonObject = JSON.parse(jsonObjectBuff.toString())

  return jsonObject
}

server.bind(SERVER_PORT)
