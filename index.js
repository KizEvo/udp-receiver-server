// Reference
// https://github.com/Lora-net/packet_forwarder/blob/master/PROTOCOL.TXT
//
// WHERE TO START ?
// The server.on('message') event is the main event which capture the UDP
// packet forwarder from the gateway then from there we process the data

import 'dotenv/config'
import dgram from 'dgram'
import { decryptLoraRawData, decryptLoraRawDataAsconMac } from './lorawan.js'

// Import the functions you need from the SDKs you need
import { initializeApp } from 'firebase/app'
import {
  getFirestore,
  doc,
  collection,
  setDoc,
  getDoc,
  updateDoc,
  addDoc,
} from 'firebase/firestore'

// Device Address
const deviceAddresses = [process.env.DEVADDR1]

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
const firebaseDb = getFirestore(firebaseApp)
// Get date
const date = new Date()
const dateString = date.toDateString().replaceAll(' ', '')
// Get document reference
const firstId = 'collection-metadata'
const coll = 'sensorDataCollection' + dateString
const firstDocRef = doc(firebaseDb, coll, firstId)

// Set doc to collection
const firstDocument = {
  count: 0,
  sensorType: 'temperature-humidity',
}

let initialDoc = await getDoc(firstDocRef)
let initialDocData
if (!initialDoc.exists()) {
  console.log('First document or collection does not exist, creating one..')
  await setDoc(firstDocRef, firstDocument)
  console.log('Created first document successfully!')
  initialDoc = await getDoc(firstDocRef)
  initialDocData = initialDoc.data()
} else {
  initialDocData = initialDoc.data()
  console.log(
    `First document already exist!\nsensor data count: ${initialDocData.count}, type: ${initialDocData.sensorType}`
  )
  if (initialDocData.sensorType !== firstDocument.sensorType) {
    throw new Error(
      `Mismatch sensor type between database (${initialDocData.sensorType}) and current type (${firstDocument.sensorType})`
    )
  }
}

const SERVER_PORT = 1700

const UDP_PACKET_PROTOCOL_VERSION_OFFSET = 0
const UDP_PACKET_RANDOM_TOKEN_OFFSET = 1
const UDP_PACKET_TYPE_OFFSET = 3
const UDP_PACKET_GATEWAY_UID_OFFSET = 4
const UDP_PACKET_JSON_OBJ_OFFSET = 12

const ASCON_MAC_DATA_OFFSET = {
  PAYLOAD: 0,
  DEV_NUMB: 1,
  FCNT: 2,
  FPORT: 3,
  MHDR: 4,
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

let udpPktFwdState = UDP_PKT_FWD_STATES.IDLE

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

// @param state UDP_PKT_FWD_STATES object member
// @param buff The msg Buffer type
const networkServerProcessData = async (state, buff) => {
  console.log('Process LoRa package..')
  if (state == UDP_PKT_FWD_STATES.UPSTREAM) {
    const jsonObject = pushDataBuffToJsonObject(buff)
    console.log(jsonObject)
    if (!jsonObject.rxpk) {
      return
    }
    // rxpk may contain multiple RF package
    // so we loop through to check
    for (let i = 0; i < jsonObject.rxpk.length; i++) {
      const [data, packet] = await decryptLoraRawDataAsconMac(
        jsonObject.rxpk[i].data,
        process.env.NWKSKEY1,
        process.env.APPSKEY1
      )
      if (data != null) {
        console.log(`RF captured data inst ${i}:`)
        let sensorDoc = {
          dev_addr:
            deviceAddresses[
              data[ASCON_MAC_DATA_OFFSET.DEV_NUMB].readInt8() - 1
            ],
          temperature:
            parseFloat(data[ASCON_MAC_DATA_OFFSET.PAYLOAD][2]) +
            parseFloat(data[ASCON_MAC_DATA_OFFSET.PAYLOAD][3]) / 10.0,
          humidity:
            parseFloat(data[ASCON_MAC_DATA_OFFSET.PAYLOAD][0]) +
            parseFloat(data[ASCON_MAC_DATA_OFFSET.PAYLOAD][1]) / 10.0,
          inst: initialDocData.count,
        }
        initialDocData.count++
        await updateDoc(firstDocRef, initialDocData)
        let docRef = await addDoc(collection(firebaseDb, coll), sensorDoc)
        console.log('Document written with ID: ', docRef.id)
      } else {
        console.log(`Failed to decrypt package inst ${i}`)
      }
    }
  } else if ((state = UDP_PKT_FWD_STATES.DOWNSTREAM)) {
    console.log('No support for downstream data processing yet')
  } else {
    console.log('Unknown packet forwarder state for data processing')
  }
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
