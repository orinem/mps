/*********************************************************************
 * Copyright (c) Intel Corporation 2022
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

import { logger, messages } from '../logging'
import { CIRAHandler } from './CIRAHandler'
import { AMT, CIM, IPS, Common } from '@open-amt-cloud-toolkit/wsman-messages'
import { Selector } from '@open-amt-cloud-toolkit/wsman-messages/WSMan'
import { CIRASocket } from '../models/models'

export class DeviceAction {
  ciraHandler: CIRAHandler
  ciraSocket: CIRASocket
  cim: CIM.Messages
  amt: AMT.Messages
  ips: IPS.Messages
  constructor (ciraHandler: CIRAHandler, ciraSocket: CIRASocket) {
    this.ciraHandler = ciraHandler
    this.ciraSocket = ciraSocket
    this.cim = new CIM.Messages()
    this.amt = new AMT.Messages()
    this.ips = new IPS.Messages()
  }

  async getPowerState (): Promise<Common.Models.Pull<CIM.Models.AssociatedPowerManagementService>> {
    logger.silly(`getPowerState ${messages.REQUEST}`)
    let xmlRequestBody = this.cim.ServiceAvailableToElement(CIM.Methods.ENUMERATE)
    const result = await this.ciraHandler.Enumerate(this.ciraSocket, xmlRequestBody)
    const enumContext: string = result?.Envelope?.Body?.EnumerateResponse?.EnumerationContext
    if (enumContext == null) {
      logger.error(`getPowerState failed. Reason: ${messages.ENUMERATION_RESPONSE_NULL}`)
      return null
    }
    xmlRequestBody = this.cim.ServiceAvailableToElement(CIM.Methods.PULL, enumContext)
    const pullResponse = await this.ciraHandler.Pull<CIM.Models.AssociatedPowerManagementService>(this.ciraSocket, xmlRequestBody)
    logger.silly(`getPowerState ${messages.COMPLETE}`)
    return pullResponse.Envelope.Body
  }

  async getSoftwareIdentity (): Promise<Common.Models.Pull<CIM.Models.SoftwareIdentity>> {
    logger.silly(`getSoftwareIdentity enumeration ${messages.REQUEST}`)
    const result = await this.ciraHandler.Enumerate(this.ciraSocket, this.cim.SoftwareIdentity(CIM.Methods.ENUMERATE))
    logger.info('getSoftwareIdentity enumeration result :', JSON.stringify(result, null, '\t'))
    const enumContext: string = result?.Envelope.Body?.EnumerateResponse?.EnumerationContext
    if (enumContext == null) {
      logger.error(`getSoftwareIdentity failed. Reason: ${messages.ENUMERATION_RESPONSE_NULL}`)
      return null
    }
    logger.silly(`getSoftwareIdentity pull ${messages.REQUEST}`)
    const pullResponse = await this.ciraHandler.Pull<CIM.Models.SoftwareIdentity>(this.ciraSocket, this.cim.SoftwareIdentity(CIM.Methods.PULL, enumContext))
    logger.info('getSoftwareIdentity pullResponse :', JSON.stringify(pullResponse, null, '\t'))
    logger.silly(`getSoftwareIdentity ${messages.COMPLETE}`)
    return pullResponse.Envelope.Body
  }

  async getIpsOptInService (): Promise<IPS.Models.OptInServiceResponse> {
    logger.silly(`getIpsOptInService ${messages.REQUEST}`)
    const xmlRequestBody = this.ips.OptInService(IPS.Methods.GET)
    const result = await this.ciraHandler.Get<IPS.Models.OptInServiceResponse>(this.ciraSocket, xmlRequestBody)
    logger.silly(`getIpsOptInService ${messages.COMPLETE}`)
    return result.Envelope.Body
  }

  async putIpsOptInService (data: IPS.Models.OptInServiceResponse): Promise<IPS.Models.OptInServiceResponse> {
    logger.silly(`putIpsOptInService ${messages.REQUEST}`)
    const xmlRequestBody = this.ips.OptInService(IPS.Methods.PUT, null, data)
    const result = await this.ciraHandler.Get<IPS.Models.OptInServiceResponse>(this.ciraSocket, xmlRequestBody)
    logger.silly(`putIpsOptInService ${messages.COMPLETE}`)
    return result.Envelope.Body
  }

  async getRedirectionService (): Promise<AMT.Models.RedirectionResponse> {
    logger.silly(`getRedirectionService ${messages.REQUEST}`)
    const xmlRequestBody = this.amt.RedirectionService(AMT.Methods.GET)
    const result = await this.ciraHandler.Get<AMT.Models.RedirectionResponse>(this.ciraSocket, xmlRequestBody)
    logger.silly(`getRedirectionService ${messages.COMPLETE}`)
    return result.Envelope.Body
  }

  async setRedirectionService (requestState: number): Promise<any> {
    logger.silly(`setRedirectionService ${messages.REQUEST}`)
    const xmlRequestBody = this.amt.RedirectionService(AMT.Methods.REQUEST_STATE_CHANGE, requestState)
    const result = await this.ciraHandler.Send(this.ciraSocket, xmlRequestBody)
    logger.silly(`setRedirectionService ${messages.COMPLETE}`)
    return result.Envelope.Body
  }

  async putRedirectionService (data: AMT.Models.RedirectionResponse): Promise<any> {
    logger.silly(`putRedirectionService ${messages.REQUEST}`)
    const xmlRequestBody = this.amt.RedirectionService(AMT.Methods.PUT, null, data)
    const result = await this.ciraHandler.Send(this.ciraSocket, xmlRequestBody)
    logger.silly(`putRedirectionService ${messages.COMPLETE}`)
    return result.Envelope.Body
  }

  async getKvmRedirectionSap (): Promise<CIM.Models.KVMRedirectionSAPResponse> {
    logger.silly(`getKvmRedirectionSap ${messages.REQUEST}`)
    const xmlRequestBody = this.cim.KVMRedirectionSAP(CIM.Methods.GET)
    const result = await this.ciraHandler.Get<CIM.Models.KVMRedirectionSAPResponse>(this.ciraSocket, xmlRequestBody)
    logger.silly(`getKvmRedirectionSap ${messages.COMPLETE}`)
    return result.Envelope.Body
  }

  async setKvmRedirectionSap (requestedState: number): Promise<any> {
    logger.silly(`setKvmRedirectionSap ${messages.REQUEST}`)
    const xmlRequestBody = this.cim.KVMRedirectionSAP(CIM.Methods.REQUEST_STATE_CHANGE, requestedState)
    const result = await this.ciraHandler.Send(this.ciraSocket, xmlRequestBody)
    logger.silly(`setKvmRedirectionSap ${messages.COMPLETE}`)
    return result.Envelope.Body
  }

  async forceBootMode (bootSource: string = 'Intel(r) AMT: Boot Configuration 0', role: number = 1): Promise<number> {
    logger.silly(`forceBootMode ${messages.REQUEST}`)
    const xmlRequestBody = this.cim.BootService(CIM.Methods.SET_BOOT_CONFIG_ROLE, bootSource, role)
    const result = await this.ciraHandler.Send(this.ciraSocket, xmlRequestBody)
    logger.silly(`forceBootMode ${messages.COMPLETE}`)
    return result
  }

  async changeBootOrder (bootSource: string): Promise<any> {
    logger.silly(`changeBootOrder ${messages.REQUEST}`)
    // TODO: convert to string enum
    const bootChoice = `<Address xmlns="http://schemas.xmlsoap.org/ws/2004/08/addressing">http://schemas.xmlsoap.org/ws/2004/08/addressing</Address><ReferenceParameters xmlns="http://schemas.xmlsoap.org/ws/2004/08/addressing"><ResourceURI xmlns="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd">http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_BootSourceSetting</ResourceURI><SelectorSet xmlns="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"><Selector Name="InstanceID">Intel(r) AMT: ${bootSource}</Selector></SelectorSet></ReferenceParameters>`
    const xmlRequestBody = this.cim.BootConfigSetting(CIM.Methods.CHANGE_BOOT_ORDER, bootChoice)
    const result = await this.ciraHandler.Send(this.ciraSocket, xmlRequestBody)
    logger.silly(`changeBootOrder ${messages.COMPLETE}`)
    return result
  }

  async setBootConfiguration (data: AMT.Models.BootSettingData): Promise<any> {
    logger.silly(`setBootConfiguration ${messages.REQUEST}`)
    const xmlRequestBody = this.amt.BootSettingData(AMT.Methods.PUT, data)
    const result = await this.ciraHandler.Send(this.ciraSocket, xmlRequestBody)
    logger.silly(`setBootConfiguration ${messages.COMPLETE}`)
    return result.Envelope.Body
  }

  async getBootOptions (): Promise<AMT.Models.BootSettingDataResponse> {
    logger.silly(`getBootOptions ${messages.REQUEST}`)
    const xmlRequestBody = this.amt.BootSettingData(AMT.Methods.GET)
    const result = await this.ciraHandler.Get<AMT.Models.BootSettingDataResponse>(this.ciraSocket, xmlRequestBody)
    logger.silly(`getBootOptions ${messages.COMPLETE}`)
    return result.Envelope.Body
  }

  async sendPowerAction (powerState: number): Promise<any> {
    logger.silly(`sendPowerAction ${messages.REQUEST}`)
    const xmlToSend = this.cim.PowerManagementService(CIM.Methods.REQUEST_POWER_STATE_CHANGE, powerState)
    const result = await this.ciraHandler.Get<CIM.Models.PowerActionResponse>(this.ciraSocket, xmlToSend)
    logger.silly(`sendPowerAction ${messages.COMPLETE}`)
    return result.Envelope
  }

  async getSetupAndConfigurationService (): Promise<Common.Models.Envelope<AMT.Models.SetupAndConfigurationService>> {
    logger.silly(`getSetupAndConfigurationService ${messages.REQUEST}`)
    const xmlRequestBody = this.amt.SetupAndConfigurationService(AMT.Methods.GET)
    const getResponse = await this.ciraHandler.Get<AMT.Models.SetupAndConfigurationService>(this.ciraSocket, xmlRequestBody)
    logger.info('getSetupAndConfigurationService result :', JSON.stringify(getResponse, null, '\t'))
    logger.silly(`getSetupAndConfigurationService ${messages.COMPLETE}`)
    return getResponse.Envelope
  }

  async getGeneralSettings (): Promise<Common.Models.Envelope<AMT.Models.GeneralSettingsResponse>> {
    logger.silly(`getGeneralSettings ${messages.REQUEST}`)
    const xmlRequestBody = this.amt.GeneralSettings(AMT.Methods.GET)
    const getResponse = await this.ciraHandler.Get<AMT.Models.GeneralSettingsResponse>(this.ciraSocket, xmlRequestBody)
    logger.silly(`getGeneralSettings ${messages.COMPLETE}`)
    return getResponse.Envelope
  }

  async getPowerCapabilities (): Promise<Common.Models.Envelope<AMT.Models.BootCapabilities>> {
    logger.silly(`getPowerCapabilities ${messages.REQUEST}`)
    const xmlRequestBody = this.amt.BootCapabilities(AMT.Methods.GET)
    const result = await this.ciraHandler.Get<AMT.Models.BootCapabilities>(this.ciraSocket, xmlRequestBody)
    logger.info(JSON.stringify(result))
    logger.silly(`getPowerCapabilities ${messages.COMPLETE}`)
    return result.Envelope
  }

  async requestUserConsentCode (): Promise<Common.Models.Envelope<IPS.Models.StartOptIn_OUTPUT>> {
    logger.silly(`requestUserConsentCode ${messages.REQUEST}`)
    const xmlRequestBody = this.ips.OptInService(IPS.Methods.START_OPT_IN)
    const getResponse = await this.ciraHandler.Get<IPS.Models.StartOptIn_OUTPUT>(this.ciraSocket, xmlRequestBody)
    logger.silly(`requestUserConsentCode ${messages.COMPLETE}`)
    return getResponse.Envelope
  }

  async cancelUserConsentCode (): Promise<Common.Models.Envelope<IPS.Models.CancelOptIn_OUTPUT>> {
    logger.silly(`cancelUserConsentCode ${messages.REQUEST}`)
    const xmlRequestBody = this.ips.OptInService(IPS.Methods.CANCEL_OPT_IN)
    const getResponse = await this.ciraHandler.Get<IPS.Models.CancelOptIn_OUTPUT>(this.ciraSocket, xmlRequestBody)
    logger.silly(`cancelUserConsentCode ${messages.COMPLETE}`)
    return getResponse.Envelope
  }

  async sendUserConsentCode (code: Number): Promise<Common.Models.Envelope<IPS.Models.SendOptInCode_OUTPUT>> {
    logger.silly(`sendUserConsentCode ${messages.REQUEST}`)
    const xmlRequestBody = this.ips.OptInService(IPS.Methods.SEND_OPT_IN_CODE, code)
    const getResponse = await this.ciraHandler.Get<IPS.Models.SendOptInCode_OUTPUT>(this.ciraSocket, xmlRequestBody)
    logger.silly(`sendUserConsentCode ${messages.COMPLETE}`)
    return getResponse.Envelope
  }

  async getComputerSystemPackage (): Promise<Common.Models.Envelope<CIM.Models.ComputerSystemPackage>> {
    logger.silly(`getComputerSystemPackage ${messages.REQUEST}`)
    const xmlRequestBody = this.cim.ComputerSystemPackage(CIM.Methods.GET)
    const getResponse = await this.ciraHandler.Get<CIM.Models.ComputerSystemPackage>(this.ciraSocket, xmlRequestBody)
    logger.info('getComputerSystemPackage getResponse :', JSON.stringify(getResponse, null, '\t'))
    logger.silly(`getComputerSystemPackage ${messages.COMPLETE}`)
    return getResponse.Envelope
  }

  async getChassis (): Promise<Common.Models.Envelope<CIM.Models.Chassis>> {
    logger.silly(`getChassis ${messages.REQUEST}`)
    const xmlRequestBody = this.cim.Chassis(CIM.Methods.GET)
    const getResponse = await this.ciraHandler.Get<CIM.Models.Chassis>(this.ciraSocket, xmlRequestBody)
    logger.info('getChassis getChassis :', JSON.stringify(getResponse, null, '\t'))
    logger.silly(`getChassis ${messages.COMPLETE}`)
    return getResponse.Envelope
  }

  async getCard (): Promise<Common.Models.Envelope<CIM.Models.Card>> {
    logger.silly(`getCard ${messages.REQUEST}`)
    const xmlRequestBody = this.cim.Card(CIM.Methods.GET)
    const getResponse = await this.ciraHandler.Get<CIM.Models.Card>(this.ciraSocket, xmlRequestBody)
    logger.info('getCard getResponse :', JSON.stringify(getResponse, null, '\t'))
    logger.silly(`getCard ${messages.COMPLETE}`)
    return getResponse.Envelope
  }

  async getBIOSElement (): Promise<Common.Models.Envelope<CIM.Models.BIOSElement>> {
    logger.silly(`getBIOSElement ${messages.REQUEST}`)
    const xmlRequestBody = this.cim.BIOSElement(CIM.Methods.GET)
    const getResponse = await this.ciraHandler.Get<CIM.Models.BIOSElement>(this.ciraSocket, xmlRequestBody)
    logger.info('getBIOSElement getResponse :', JSON.stringify(getResponse, null, '\t'))
    logger.silly(`getBIOSElement ${messages.COMPLETE}`)
    return getResponse.Envelope
  }

  async getProcessor (): Promise<Common.Models.Envelope<Common.Models.Pull<CIM.Models.Processor>>> {
    logger.silly(`getProcessor ${messages.REQUEST}`)
    let xmlRequestBody = this.cim.Processor(CIM.Methods.ENUMERATE)
    const enumResponse = await this.ciraHandler.Enumerate(this.ciraSocket, xmlRequestBody)
    console.log(JSON.stringify(enumResponse))
    if (enumResponse == null) {
      logger.error(`getProcessor failed. Reason: ${messages.ENUMERATION_RESPONSE_NULL}`)
      return null
    }
    xmlRequestBody = this.cim.Processor(CIM.Methods.PULL, enumResponse.Envelope.Body.EnumerateResponse.EnumerationContext)
    const pullResponse = await this.ciraHandler.Pull<CIM.Models.Processor>(this.ciraSocket, xmlRequestBody)
    logger.silly(`getProcessor ${messages.COMPLETE}`)
    return pullResponse.Envelope
  }

  async getPhysicalMemory (): Promise<Common.Models.Envelope<Common.Models.Pull<CIM.Models.PhysicalMemory>>> {
    logger.silly(`getPhysicalMemory ${messages.REQUEST}`)
    let xmlRequestBody = this.cim.PhysicalMemory(CIM.Methods.ENUMERATE)
    const enumResponse = await this.ciraHandler.Enumerate(this.ciraSocket, xmlRequestBody)
    if (enumResponse == null) {
      logger.error(`getPhysicalMemory failed. Reason: ${messages.ENUMERATION_RESPONSE_NULL}`)
      return null
    }
    xmlRequestBody = this.cim.PhysicalMemory(CIM.Methods.PULL, enumResponse.Envelope.Body.EnumerateResponse.EnumerationContext)
    const pullResponse = await this.ciraHandler.Pull<CIM.Models.PhysicalMemory>(this.ciraSocket, xmlRequestBody)
    logger.silly(`getPhysicalMemory ${messages.COMPLETE}`)
    return pullResponse.Envelope
  }

  async getMediaAccessDevice (): Promise<Common.Models.Envelope<Common.Models.Pull<CIM.Models.MediaAccessDevice>>> {
    logger.silly(`getMediaAccessDevice ${messages.REQUEST}`)
    let xmlRequestBody = this.cim.MediaAccessDevice(CIM.Methods.ENUMERATE)
    const enumResponse = await this.ciraHandler.Enumerate(this.ciraSocket, xmlRequestBody)
    if (enumResponse == null) {
      logger.error(`getMediaAccessDevice failed. Reason: ${messages.ENUMERATION_RESPONSE_NULL}`)
      return null
    }
    xmlRequestBody = this.cim.MediaAccessDevice(CIM.Methods.PULL, enumResponse.Envelope.Body.EnumerateResponse.EnumerationContext)
    const pullResponse = await this.ciraHandler.Pull<CIM.Models.MediaAccessDevice>(this.ciraSocket, xmlRequestBody)
    logger.silly(`getMediaAccessDevice ${messages.COMPLETE}`)
    return pullResponse.Envelope
  }

  async getPhysicalPackage (): Promise<Common.Models.Envelope<Common.Models.Pull<CIM.Models.PhysicalPackage>>> {
    logger.silly(`getPhysicalPackage ${messages.REQUEST}`)
    let xmlRequestBody = this.cim.PhysicalPackage(CIM.Methods.ENUMERATE)
    const enumResponse = await this.ciraHandler.Enumerate(this.ciraSocket, xmlRequestBody)
    if (enumResponse == null) {
      logger.error(`getPhysicalPackage failed. Reason: ${messages.ENUMERATION_RESPONSE_NULL}`)
      return null
    }
    xmlRequestBody = this.cim.PhysicalPackage(CIM.Methods.PULL, enumResponse.Envelope.Body.EnumerateResponse.EnumerationContext)
    const pullResponse = await this.ciraHandler.Pull<CIM.Models.PhysicalPackage>(this.ciraSocket, xmlRequestBody)
    logger.silly(`getPhysicalPackage ${messages.COMPLETE}`)
    return pullResponse.Envelope
  }

  async getSystemPackaging (): Promise<Common.Models.Envelope<Common.Models.Pull<CIM.Models.SystemPackaging>>> {
    logger.silly(`getSystemPackaging ${messages.REQUEST}`)
    let xmlRequestBody = this.cim.SystemPackaging(CIM.Methods.ENUMERATE)
    const enumResponse = await this.ciraHandler.Enumerate(this.ciraSocket, xmlRequestBody)
    if (enumResponse == null) {
      logger.error(`getSystemPackaging failed. Reason: ${messages.ENUMERATION_RESPONSE_NULL}`)
      return null
    }
    xmlRequestBody = this.cim.SystemPackaging(CIM.Methods.PULL, enumResponse.Envelope.Body.EnumerateResponse.EnumerationContext)
    const pullResponse = await this.ciraHandler.Pull<CIM.Models.SystemPackaging>(this.ciraSocket, xmlRequestBody)
    logger.silly(`getSystemPackaging ${messages.COMPLETE}`)
    return pullResponse.Envelope
  }

  async getChip (): Promise<Common.Models.Envelope<Common.Models.Pull<CIM.Models.Chip>>> {
    logger.silly(`getChip ${messages.REQUEST}`)
    let xmlRequestBody = this.cim.Chip(CIM.Methods.ENUMERATE)
    const enumResponse = await this.ciraHandler.Enumerate(this.ciraSocket, xmlRequestBody)
    if (enumResponse == null) {
      logger.error(`getChip failed. Reason: ${messages.ENUMERATION_RESPONSE_NULL}`)
      return null
    }
    xmlRequestBody = this.cim.Chip(CIM.Methods.PULL, enumResponse.Envelope.Body.EnumerateResponse.EnumerationContext)
    const pullResponse = await this.ciraHandler.Pull<CIM.Models.Chip>(this.ciraSocket, xmlRequestBody)
    logger.silly(`getChip ${messages.COMPLETE}`)
    return pullResponse.Envelope
  }

  async getEventLog (): Promise<Common.Models.Envelope<AMT.Models.MessageLog>> {
    logger.silly(`getEventLog ${messages.REQUEST}`)
    let xmlRequestBody = this.amt.MessageLog(AMT.Methods.POSITION_TO_FIRST_RECORD)
    const response = await this.ciraHandler.Get<{PositionToFirstRecord_OUTPUT: {
      IterationIdentifier: string
      ReturnValue: string
    }}>(this.ciraSocket, xmlRequestBody)
    if (response == null) {
      logger.error(`failed to get position to first record of AMT_MessageLog. Reason: ${messages.RESPONSE_NULL}`)
      return null
    }
    xmlRequestBody = this.amt.MessageLog(AMT.Methods.GET_RECORDS, Number(response.Envelope.Body.PositionToFirstRecord_OUTPUT.IterationIdentifier))
    const eventLogs = await this.ciraHandler.Get<AMT.Models.MessageLog>(this.ciraSocket, xmlRequestBody)
    logger.info('getEventLog response :', JSON.stringify(eventLogs, null, '\t'))
    logger.silly(`getEventLog ${messages.COMPLETE}`)
    return eventLogs.Envelope
  }

  async getAuditLog (startIndex: number): Promise<AMT.Models.AuditLog_ReadRecords> {
    logger.silly(`getAuditLog ${messages.REQUEST}`)
    const xmlRequestBody = this.amt.AuditLog(AMT.Methods.READ_RECORDS, startIndex)
    const getResponse = await this.ciraHandler.Get<AMT.Models.AuditLog_ReadRecords>(this.ciraSocket, xmlRequestBody)
    logger.info('getAuditLog response :', JSON.stringify(getResponse, null, '\t'))

    if (getResponse == null) {
      logger.error(`failed to get audit log. Reason: ${messages.RESPONSE_NULL}`)
      throw new Error('unable to retrieve audit log')
    }
    logger.silly(`getAuditLog ${messages.COMPLETE}`)
    return getResponse.Envelope.Body
  }

  async addAlarmClockOccurrence (alarm: IPS.Models.AlarmClockOccurrence): Promise<any> {
    logger.silly(`addAlarmClockOccurrence ${messages.ALARM_ADD_REQUESTED}`)
    const xmlRequestBody = this.amt.AlarmClockService(AMT.Methods.ADD_ALARM, alarm)
    const addResponse = await this.ciraHandler.Get(this.ciraSocket, xmlRequestBody)
    if (addResponse == null) {
      logger.error(`addAlarmClockOccurrence failed. Reason: ${messages.ALARM_ADD_RESPONSE_NULL}`)
      return null
    }
    logger.silly(`addAlarmClockOccurrence ${messages.COMPLETE}`)
    return addResponse.Envelope
  }

  async getAlarmClockOccurrences (): Promise<Common.Models.Envelope<Common.Models.Pull<IPS.Models.AlarmClockOccurrence>>> {
    logger.silly(`getAlarmClockOccurrences ${messages.REQUEST}`)
    let xmlRequestBody = this.ips.AlarmClockOccurrence(IPS.Methods.ENUMERATE)
    const enumResponse = await this.ciraHandler.Enumerate(this.ciraSocket, xmlRequestBody)
    if (enumResponse == null) {
      logger.error(`getAlarmClockOccurrences failed. Reason: ${messages.ENUMERATION_RESPONSE_NULL}`)
      return null
    }
    xmlRequestBody = this.ips.AlarmClockOccurrence(IPS.Methods.PULL, enumResponse.Envelope.Body.EnumerateResponse.EnumerationContext)
    const pullResponse = await this.ciraHandler.Pull<IPS.Models.AlarmClockOccurrence>(this.ciraSocket, xmlRequestBody)
    logger.silly(`getAlarmClockOccurrences ${messages.COMPLETE}`)
    return pullResponse.Envelope
  }

  async deleteAlarmClockOccurrence (selector: Selector): Promise<any> {
    logger.silly(`deleteAlarmClockOccurrence ${messages.DELETE}`)
    const xmlRequestBody = this.ips.AlarmClockOccurrence(IPS.Methods.DELETE, null, selector)
    const deleteResponse = await this.ciraHandler.Delete(this.ciraSocket, xmlRequestBody)
    if (deleteResponse == null) {
      logger.error(`deleteAlarmClockOccurrences failed. Reason: ${messages.DELETE_RESPONSE_NULL}`)
      return null
    }
    logger.silly(`deleteAlarmClockOccurrences ${messages.COMPLETE}`)
    return deleteResponse.Envelope
  }
}
