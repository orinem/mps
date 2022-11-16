/*********************************************************************
 * Copyright (c) Intel Corporation 2022
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

/* Construct a Intel AMT MPS server object
    Note:
        Functionality has been modified for standalone operation only (Meshcentral services will not work with this code)
    Parameters:
        parent (mpsMicroservice): parent service invoking this module (provides eventing and wiring services)
        db: database for credential
        config: settings pertaining to the behaviour of this service
        certificates: certificates to use for TLS server creation
*/

/**
* @description Intel AMT MPS server object
* @author Ylian Saint-Hilaire
* @version v0.2.0c
*/

import { logger, messages } from '../logging'
import { Environment } from '../utils/Environment'
import { Server } from 'net'
import { createServer as tlsCreateServer, TLSSocket } from 'tls'
import { randomBytes } from 'crypto'
import APFProcessor from '../amt/APFProcessor'
import { CIRASocket, Device } from '../models/models'
import { certificatesType } from '../models/Config'
import { EventEmitter } from 'stream'
import { IDB } from '../interfaces/IDb'
import { ISecretManagerService } from '../interfaces/ISecretManagerService'
import { ConnectedDevice } from '../amt/ConnectedDevice'
import { MqttProvider } from '../utils/MqttProvider'
// 90 seconds max idle time, higher than the typical KEEP-ALIVE period of 60 seconds
const MAX_IDLE = 90000

const devices: {[key: string]: ConnectedDevice} = {}

export { devices }
export class MPSServer {
  certs: certificatesType
  server: Server
  events: EventEmitter
  db: IDB
  secrets: ISecretManagerService
  constructor (certs: certificatesType, db: IDB, secrets: ISecretManagerService) {
    this.certs = certs
    this.db = db
    this.secrets = secrets
    this.events = new EventEmitter()

    APFProcessor.APFEvents.on('userAuthRequest', this.onVerifyUserAuth.bind(this))
    APFProcessor.APFEvents.on('protocolVersion', this.onAPFProtocolVersion.bind(this))
    APFProcessor.APFEvents.on('disconnected', this.onAPFDisconnected.bind(this))

    // Creates a TLS server for secure connection
    this.server = tlsCreateServer(this.certs.mps_tls_config, this.onTLSConnection)

    this.server.on('error', (err) => {
      logger.error(`${messages.PORT_NOT_AVAILABLE} : ${Environment.Config.port}`)
      if (err) logger.error(JSON.stringify(err))
    })
  }

  listen (): void {
    this.server.listen(Environment.Config.port, this.listeningListener)
  }

  listeningListener (): void {
    logger.info(`${messages.SERVER_RUNNING_ON} ${Environment.Config.common_name}:${Environment.Config.port}.`)
  }

  onAPFDisconnected = async (nodeId: string): Promise<void> => {
    try {
      logger.silly(`onAPFDisconnected: ${nodeId}`)
      await this.handleDeviceDisconnect(nodeId)
    } catch (e) { }
    this.events.emit('disconnected', nodeId)
  }

  onAPFProtocolVersion = async (socket: CIRASocket): Promise<void> => {
    // Check if the device exits in db
    if (await this.db.devices.getById(socket.tag.SystemId) != null) {
      socket.tag.nodeid = socket.tag.SystemId
      // if (socket.tag.certauth) { // is this even used?
      //   devices[socket.tag.nodeid] = socket
      //   this.events.emit('connected', socket.tag.nodeid)
      // }
    } else {
      try {
        logger.warn(`${messages.MPS_DEVICE_NOT_ALLOWED} : ${socket.tag.nodeid}`)
        socket.end()
      } catch (e) { }
    }
  }

  onVerifyUserAuth = async (socket: CIRASocket, username: string, password: string): Promise<void> => {
    // Authenticate device connection using username and password
    try {
      const device = await this.db.devices.getById(socket.tag.SystemId)
      const pwd = await this.secrets.getSecretFromKey(`devices/${socket.tag.SystemId}`, 'MPS_PASSWORD')
      if (username === device?.mpsusername && password === pwd) {
        if (devices[socket.tag.SystemId]) {
          const oldConnectedDevice = devices[socket.tag.SystemId]
          if (oldConnectedDevice) {
            logger.silly(`${messages.MPS_CIRA_CLOSE_OLD_CONNECTION} for ${socket.tag.SystemId} with socketid ${oldConnectedDevice.ciraSocket.tag.id}`)
            try {
              logger.silly(`replacing connected device: ${JSON.stringify(oldConnectedDevice, null, '\t')}`)
            } catch (err) {
              logger.error(err)
            }
          }
          devices[socket.tag.SystemId].ciraSocket.end() // close old connection before adding new connection
          await this.handleDeviceDisconnect(socket.tag.SystemId) // delete and disconnect
        }
        logger.debug(`${messages.MPS_CIRA_AUTHENTICATION_SUCCESS} for: ${username}`)
        const cred = await this.secrets.getAMTCredentials(socket.tag.SystemId)

        devices[socket.tag.SystemId] = new ConnectedDevice(socket, cred[0], cred[1])
        this.events.emit('connected', socket.tag.SystemId)
        await this.handleDeviceConnect(socket.tag.SystemId)
        APFProcessor.SendUserAuthSuccess(socket) // Notify the auth success on the CIRA connection
      } else {
        logger.warn(`${messages.MPS_CIRA_AUTHENTICATION_FAILED} for: ${username}`)
        APFProcessor.SendUserAuthFail(socket)
      }
    } catch (err) {
      logger.error(err)
      APFProcessor.SendUserAuthFail(socket)
    }
  }

  onTLSConnection = (socket: TLSSocket): void => {
    logger.debug(messages.MPS_NEW_TLS_CONNECTION); // New TLS connection detected
    (socket as CIRASocket).tag = {
      id: randomBytes(16).toString('hex'),
      first: true,
      clientCert: socket.getPeerCertificate(true),
      accumulator: '',
      activetunnels: 0,
      boundPorts: [],
      // socket: socket,
      host: null,
      nextchannelid: 4,
      channels: {},
      nextsourceport: 0,
      nodeid: null
    }
    this.addHandlers(socket as CIRASocket)
  }

  addHandlers (socket: CIRASocket): void {
    socket.setEncoding('binary')
    socket.setTimeout(MAX_IDLE) // Setup the CIRA keep alive timer
    socket.on('timeout', this.onTimeout.bind(this, socket))
    socket.addListener('data', this.onDataReceived.bind(this, socket))
    socket.addListener('close', this.onClose.bind(this, socket))
    socket.addListener('error', this.onError.bind(this, socket))
  }

  onTimeout = async (socket: CIRASocket): Promise<void> => {
    logger.debug(messages.MPS_CIRA_TIMEOUT_DISCONNECTING)
    try {
      socket.end()
      // Delete and update status to disconnected if socket id's match
      if (devices[socket.tag.nodeid]?.ciraSocket?.tag.id === socket?.tag.id) {
        logger.silly(`${messages.MPS_CIRA_DISCONNECT} for ${socket.tag.nodeid} with socketid ${socket.tag.id}`)
        await this.handleDeviceDisconnect(socket.tag.nodeid)
      }
    } catch (err) {
      logger.error(`${messages.SOCKET_TIMEOUT}: ${err}`)
    }
  }

  onDataReceived = async (socket: CIRASocket, data: any): Promise<void> => {
    socket.tag.accumulator += data

    // Detect if this is an HTTPS request, if it is, return a simple answer and disconnect. This is useful for debugging access to the MPS port.
    if (socket.tag.first) {
      if (socket.tag.accumulator.length < 3) return
      // if (!socket.tag.clientCert.subject) { console.log("MPS Connection, no client cert: " + socket.remoteAddress); socket.write('HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nMeshCentral2 MPS server.\r\nNo client certificate given.'); socket.end(); return; }
      if (socket.tag.accumulator.substring(0, 3) === 'GET') {
        logger.debug(`${messages.MPS_HTTP_GET_CONNECTION}: ${socket.remoteAddress}`)
        socket.write('HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n<!DOCTYPE html><html><head><meta charset="UTF-8"></head><body>Intel Management Presence Server (MPS).<br />Intel&reg; AMT computers must connect here using CIRA.</body></html>')
        socket.end()
        return
      }
      logger.debug(messages.MPS_CIRA_NEW_TLS_CONNECTION)
      socket.tag.first = false
    }

    try {
      // Parse all of the APF data we can
      let length = 0
      do {
        length = await APFProcessor.processCommand(socket)
        if (length > 0) {
          socket.tag.accumulator = socket.tag.accumulator.substring(length)
        }
      } while (length > 0)
      if (length < 0) {
        socket.end()
      }
    } catch (err) {
      logger.error(err)
    }
  }

  onClose = async (socket: CIRASocket): Promise<void> => {
    try {
      if (socket.tag.nodeid) { // If this is a CIRA connection
        if (devices[socket.tag.nodeid]?.ciraSocket?.tag.id === socket?.tag.id) {
          // Make sure we only delete/update device connection if socket id's match
          logger.debug(`${messages.MPS_CIRA_CONNECTION_CLOSED} for ${socket.tag.nodeid} with socketid ${socket.tag.id}`)
          await this.handleDeviceDisconnect(socket.tag.nodeid)
        } else {
          // This is an old/inactive connection which we've already ended
          // There might already be a new CIRA connection active so no action needed
          logger.silly(`${messages.MPS_CIRA_CONNECTION_CLOSED} for ${socket.tag.nodeid} with socketid ${socket.tag.id}, connection status was already updated`)
        }
      } else {
        // This is called when user makes HTTP GET request
        logger.debug(messages.MPS_CONNECTION_CLOSED)
      }
    } catch (e) {
      logger.error(`${messages.SOCKET_CLOSE_ERROR}: ${e}`)
    }
  }

  onError = (socket: CIRASocket, error: NodeJS.ErrnoException): void => {
    // error "ECONNRESET" means the other side of the TCP conversation abruptly closed its end of the connection.
    if (error.code !== 'ECONNRESET') {
      logger.error(`${messages.SOCKET_ERROR} ${socket.tag.SystemId},  ${socket.remoteAddress}: ${JSON.stringify(error)}`)
    }
  }

  async handleDeviceDisconnect (guid: string): Promise<void> {
    if (devices[guid]) {
      delete devices[guid]
      const device: Device = await this.db.devices.getById(guid)
      if (device != null) {
        device.connectionStatus = false
        device.mpsInstance = null
        const results = await this.db.devices.update(device)
        if (results) {
          // Device connection status updated in db
          logger.debug(`${messages.DEVICE_CONNECTION_STATUS_UPDATED} : ${guid}`)
        }
      }
      this.events.emit('disconnected', guid)
    }
  }

  async handleDeviceConnect (guid: string): Promise<void> {
    const device: Device = await this.db.devices.getById(guid)
    device.connectionStatus = true
    device.mpsInstance = Environment.Config.instance_name
    const results = await this.db.devices.update(device)
    if (results) {
      MqttProvider.publishEvent('success', ['CIRA_Connected'], messages.MPS_CIRA_CONNECTION_ESTABLISHED, guid)
      logger.debug(`${messages.MPS_CIRA_CONNECTION_ESTABLISHED} for ${guid}`)
    } else {
      MqttProvider.publishEvent('fail', ['CIRA_Connected'], messages.MPS_CIRA_CONNECTION_FAILED, guid)
      logger.error(`${messages.MPS_CIRA_CONNECTION_FAILED} for ${guid}`)
    }
  }
}
