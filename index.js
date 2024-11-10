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

const SERVER_PORT = 1700

const UDP_PACKET_PROTOCOL_VERSION_OFFSET = 0
const UDP_PACKET_RANDOM_TOKEN_OFFSET = 1
const UDP_PACKET_TYPE_OFFSET = 3
const UDP_PACKET_GATEWAY_UID_OFFSET = 4
const UDP_PACKET_JSON_OBJ_OFFSET = 12

const ASCON_MAC_DATA_OFFSET = {
  PAYLOAD: 0,
  DEV_NUMB: 1,
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
      const startTimer = Date.now()
      console.log('###### Decrypt package, start time in ms:', startTimer)
      const [data, packet] = await decryptLoraRawDataAsconMac(
        jsonObject.rxpk[i].data,
        process.env.NWKSKEY1,
        process.env.APPSKEY1
      )
      const endTimer = Date.now()
      console.log('###### Finish, end time in ms:', endTimer)
      console.log('Time elapsed in ms:', endTimer - startTimer)
      if (data == null) {
        console.log(`Failed to decrypt package inst ${i}`)
        continue
      }

      console.log(`RF captured data inst ${i}:`)
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
        dev_addr:
          deviceAddresses[data[ASCON_MAC_DATA_OFFSET.DEV_NUMB].readInt8() - 1],
        data: data_packet,
        data_size: data_packet.length,
      }
      const docRef = await addDoc(collection(firebaseDb, coll), sensorDoc)
      console.log('Document written with ID: ', docRef.id)
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
