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
const app = initializeApp(firebaseConfig)

const SERVER_PORT = 1700

const UDP_PACKET_PROTOCOL_VERSION_OFFSET = 0
const UDP_PACKET_RANDOM_TOKEN_OFFSET = 1
const UDP_PACKET_TYPE_OFFSET = 3
const UDP_PACKET_GATEWAY_UID_OFFSET = 4
const UDP_PACKET_JSON_OBJ_OFFSET = 12

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
        console.log(data)
        console.log(packet)
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
