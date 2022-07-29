/*********************************************************************
 * Copyright (c) Intel Corporation 2022
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

import { CIRASocket } from '../models/models'
import {
  alarmClockOccurrences,
  addAlarmClockOccurrenceResponse,
  amtMessageLog,
  auditLog,
  biosElement,
  bootCapabilities,
  cancelOptInResponse,
  card,
  chassis,
  chip,
  computerSystemPackage,
  deleteAlarmClockOccurrence,
  enumerateResponse,
  enumerateResponseIPSAlarmClockOccurrence,
  generalSettings,
  mediaAccessDevice,
  physicalMemory,
  physicalPackage,
  positionToFirstRecord,
  processor,
  sendOptInCodeResponse,
  serviceAvailableToElement,
  setupAndConfigurationServiceResponse,
  softwareIdentityResponse,
  startOptInResponse,
  systemPackaging
} from '../test/helper/wsmanResponses'
import { CIRAHandler } from './CIRAHandler'
import { DeviceAction } from './DeviceAction'
import { HttpHandler } from './HttpHandler'
import { Selector } from '@open-amt-cloud-toolkit/wsman-messages/WSMan'
import { AlarmClockOccurrence } from '@open-amt-cloud-toolkit/wsman-messages/ips/models'

describe('Device Action Tests', () => {
  let enumerateSpy: jest.SpyInstance
  let pullSpy: jest.SpyInstance
  let getSpy: jest.SpyInstance
  let sendSpy: jest.SpyInstance
  let deleteSpy: jest.SpyInstance
  let device: DeviceAction
  beforeEach(() => {
    const socket: CIRASocket = null
    const handler = new CIRAHandler(new HttpHandler(), 'admin', 'P@ssw0rd')
    device = new DeviceAction(handler, socket)
    enumerateSpy = jest.spyOn(device.ciraHandler, 'Enumerate')
    pullSpy = jest.spyOn(device.ciraHandler, 'Pull')
    getSpy = jest.spyOn(device.ciraHandler, 'Get')
    sendSpy = jest.spyOn(device.ciraHandler, 'Send')
    deleteSpy = jest.spyOn(device.ciraHandler, 'Delete')
  })

  afterEach(() => {
    getSpy.mockReset()
    enumerateSpy.mockReset()
    pullSpy.mockReset()
    deleteSpy.mockReset()
  })

  describe('power', () => {
    it('should return null when enumerate call to power state is null', async () => {
      enumerateSpy.mockResolvedValueOnce(null)
      const result = await device.getPowerState()
      expect(result).toBe(null)
    })
    it('should return power state', async () => {
      enumerateSpy.mockResolvedValueOnce(enumerateResponse)
      pullSpy.mockResolvedValue({ Envelope: { Body: {} } })
      const result = await device.getPowerState()
      expect(result).toEqual({})
    })
    it('should return power state', async () => {
      enumerateSpy.mockResolvedValueOnce(enumerateResponse)
      pullSpy.mockResolvedValue(serviceAvailableToElement)
      const result = await device.getPowerState()
      expect(result.PullResponse.Items.CIM_AssociatedPowerManagementService.PowerState).toBe('4')
    })
    it('should send power action', async () => {
      getSpy.mockResolvedValueOnce({ Envelope: { Body: { RequestPowerStateChange_OUTPUT: { ReturnValue: 0 } } } })
      const result = await device.sendPowerAction(10)
      expect(result).toEqual({ Body: { RequestPowerStateChange_OUTPUT: { ReturnValue: 0 } } })
    })
  })

  describe('boot', () => {
    it('should forceBootMode', async () => {
      sendSpy.mockResolvedValue(null)
      const result = await device.forceBootMode('')
      expect(sendSpy).toHaveBeenCalled()
      expect(result).toBe(null)
    })
    it('should changeBootOrder', async () => {
      sendSpy.mockResolvedValue({})
      const result = await device.changeBootOrder('')
      expect(sendSpy).toHaveBeenCalled()
      expect(result).toEqual({})
    })
    it('should setBootConfiguration', async () => {
      sendSpy.mockResolvedValue({ Envelope: { Body: {} } })
      const result = await device.setBootConfiguration({})
      expect(sendSpy).toHaveBeenCalled()
      expect(result).toEqual({})
    })
    it('should getBootOptions', async () => {
      getSpy.mockResolvedValue({ Envelope: { Body: {} } })
      const result = await device.getBootOptions()
      expect(getSpy).toHaveBeenCalled()
      expect(result).toEqual({})
    })
  })

  describe('version', () => {
    it('should return null when enumerate call to software identity is null', async () => {
      enumerateSpy.mockResolvedValueOnce(null)
      const result = await device.getSoftwareIdentity()
      expect(result).toBe(null)
    })
    it('should return null when pull call to software identity is null', async () => {
      enumerateSpy.mockResolvedValueOnce({ Envelope: { Header: { To: 'http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous', RelatesTo: '0', Action: 'http://schemas.xmlsoap.org/ws/2004/09/enumeration/EnumerateResponse', MessageID: 'uuid:00000000-8086-8086-8086-000000000001', ResourceURI: 'http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_SoftwareIdentity' }, Body: { EnumerateResponse: { EnumerationContext: '01000000-0000-0000-0000-000000000000' } } } })
      pullSpy.mockResolvedValue(softwareIdentityResponse)
      const result = await device.getSoftwareIdentity()
      expect(result).toBe(softwareIdentityResponse.Envelope.Body)
    })
    it('should get AMT SetupAndConfigurationService ', async () => {
      getSpy.mockResolvedValueOnce(setupAndConfigurationServiceResponse)
      const result = await device.getSetupAndConfigurationService()
      expect(result).toBe(setupAndConfigurationServiceResponse.Envelope)
    })
  })

  describe('general settings', () => {
    it('should get general settings ', async () => {
      getSpy.mockResolvedValueOnce(generalSettings)
      const result = await device.getGeneralSettings()
      expect(result).toBe(generalSettings.Envelope)
    })
  })

  describe('user consent code', () => {
    it('should request for user consent code ', async () => {
      getSpy.mockResolvedValueOnce(startOptInResponse)
      const result = await device.requestUserConsentCode()
      expect(result).toBe(startOptInResponse.Envelope)
    })
    it('should cancel for user consent code ', async () => {
      getSpy.mockResolvedValueOnce(cancelOptInResponse)
      const result = await device.cancelUserConsentCode()
      expect(result).toBe(cancelOptInResponse.Envelope)
    })
    it('should send for user consent code ', async () => {
      getSpy.mockResolvedValueOnce(sendOptInCodeResponse)
      const result = await device.sendUserConsentCode(985167)
      expect(result).toBe(sendOptInCodeResponse.Envelope)
    })
  })

  describe('event log', () => {
    it('should get event log ', async () => {
      getSpy.mockResolvedValueOnce(positionToFirstRecord)
      getSpy.mockResolvedValueOnce(amtMessageLog)
      const result = await device.getEventLog()
      expect(result).toBe(amtMessageLog.Envelope)
    })
    it('should return null if fails to get event log', async () => {
      getSpy.mockResolvedValueOnce(null)
      const result = await device.getEventLog()
      expect(result).toBe(null)
    })
  })

  describe('auditLog', () => {
    it('should get audit log', async () => {
      getSpy.mockResolvedValueOnce(auditLog)
      const result = await device.getAuditLog(1)
      expect(result).toBe(auditLog.Envelope.Body)
    })
    it('should return null if fails to get audit log', async () => {
      getSpy.mockResolvedValueOnce(null)
      await expect(device.getAuditLog(1)).rejects.toThrow('unable to retrieve audit log')
    })
  })

  describe('amt features', () => {
    it('should get IPS Opt In Service', async () => {
      getSpy.mockResolvedValue({ Envelope: { Body: {} } })
      const result = await device.getIpsOptInService()
      expect(result).toEqual({})
    })
    it('should get kvm', async () => {
      getSpy.mockResolvedValueOnce({ Envelope: { Body: {} } })
      const result = await device.getKvmRedirectionSap()
      expect(result).toEqual({})
    })
    it('should get redirection service', async () => {
      getSpy.mockResolvedValueOnce({ Envelope: { Body: {} } })
      const result = await device.getRedirectionService()
      expect(result).toEqual({})
    })
    it('should get KVM redirection SAP', async () => {
      getSpy.mockResolvedValueOnce({ Envelope: { Body: {} } })
      const result = await device.getKvmRedirectionSap()
      expect(result).toEqual({})
    })
  })

  describe('hardware information', () => {
    it('should get ComputerSystemPackage', async () => {
      getSpy.mockResolvedValue(computerSystemPackage)
      const result = await device.getComputerSystemPackage()
      expect(result).toEqual(computerSystemPackage.Envelope)
    })
    it('should get Chassis', async () => {
      getSpy.mockResolvedValue(chassis)
      const result = await device.getChassis()
      expect(result).toEqual(chassis.Envelope)
    })
    it('should get Card', async () => {
      getSpy.mockResolvedValue(card)
      const result = await device.getCard()
      expect(result).toEqual(card.Envelope)
    })
    it('should get BIOSElement', async () => {
      getSpy.mockResolvedValue(biosElement)
      const result = await device.getBIOSElement()
      expect(result).toEqual(biosElement.Envelope)
    })
    it('should return null when enumerate call to getProcessor fails', async () => {
      enumerateSpy.mockResolvedValueOnce(null)
      const result = await device.getProcessor()
      expect(result).toBe(null)
    })
    it('should get processor', async () => {
      enumerateSpy.mockResolvedValueOnce(enumerateResponse)
      pullSpy.mockResolvedValue(processor)
      const result = await device.getProcessor()
      expect(result).toEqual(processor.Envelope)
    })
    it('should return null when enumerate call to getPhysicalMemory fails', async () => {
      enumerateSpy.mockResolvedValueOnce(null)
      const result = await device.getPhysicalMemory()
      expect(result).toBe(null)
    })
    it('should get PhysicalMemory', async () => {
      enumerateSpy.mockResolvedValueOnce(enumerateResponse)
      pullSpy.mockResolvedValue(physicalMemory)
      const result = await device.getPhysicalMemory()
      expect(result).toEqual(physicalMemory.Envelope)
    })
    it('should return null when enumerate call to getMediaAccessDevice fails', async () => {
      enumerateSpy.mockResolvedValueOnce(null)
      const result = await device.getMediaAccessDevice()
      expect(result).toBe(null)
    })
    it('should get MediaAccessDevice', async () => {
      enumerateSpy.mockResolvedValueOnce(enumerateResponse)
      pullSpy.mockResolvedValue(mediaAccessDevice)
      const result = await device.getMediaAccessDevice()
      expect(result).toEqual(mediaAccessDevice.Envelope)
    })
    it('should return null when enumerate call to getPhysicalPackage fails', async () => {
      enumerateSpy.mockResolvedValueOnce(null)
      const result = await device.getPhysicalPackage()
      expect(result).toBe(null)
    })
    it('should get PhysicalPackage', async () => {
      enumerateSpy.mockResolvedValueOnce(enumerateResponse)
      pullSpy.mockResolvedValue(physicalPackage)
      const result = await device.getPhysicalPackage()
      expect(result).toEqual(physicalPackage.Envelope)
    })
    it('should return null when enumerate call to getSystemPackaging fails', async () => {
      enumerateSpy.mockResolvedValueOnce(null)
      const result = await device.getSystemPackaging()
      expect(result).toBe(null)
    })
    it('should get SystemPackaging', async () => {
      enumerateSpy.mockResolvedValueOnce(enumerateResponse)
      pullSpy.mockResolvedValue(systemPackaging)
      const result = await device.getSystemPackaging()
      expect(result).toEqual(systemPackaging.Envelope)
    })
    it('should return null when enumerate call to getChip fails', async () => {
      enumerateSpy.mockResolvedValueOnce(null)
      const result = await device.getChip()
      expect(result).toBe(null)
    })
    it('should get Chip', async () => {
      enumerateSpy.mockResolvedValueOnce(enumerateResponse)
      pullSpy.mockResolvedValue(chip)
      const result = await device.getChip()
      expect(result).toEqual(chip.Envelope)
    })
  })
  describe('power capabilities', () => {
    it('should get power capabilities', async () => {
      getSpy.mockResolvedValueOnce(bootCapabilities)
      const result = await device.getPowerCapabilities()
      expect(result).toEqual(bootCapabilities.Envelope)
    })
  })
  describe('alarm occurrences', () => {
    it('should return null when enumerate call to getAlarmClockOccurrences fails', async () => {
      enumerateSpy.mockResolvedValueOnce(null)
      const result = await device.getAlarmClockOccurrences()
      expect(result).toBe(null)
    })
    it('should get alarm occurrences', async () => {
      enumerateSpy.mockResolvedValueOnce(enumerateResponseIPSAlarmClockOccurrence)
      pullSpy.mockResolvedValueOnce(alarmClockOccurrences)
      const result = await device.getAlarmClockOccurrences()
      expect(result).toEqual(alarmClockOccurrences.Envelope)
    })

    const fakeSelector: Selector = {
      name: 'Name',
      value: 'Alarm Instance Name'
    }
    it('should delete an alarm occurence', async () => {
      deleteSpy.mockResolvedValueOnce(deleteAlarmClockOccurrence)

      const result = await device.deleteAlarmClockOccurrence(fakeSelector)
      expect(result).toEqual(deleteAlarmClockOccurrence.Envelope)
    })

    it('should return null when call to deleteAlarmClockOccurrence fails', async () => {
      deleteSpy.mockResolvedValueOnce(null)
      const result = await device.deleteAlarmClockOccurrence(fakeSelector)
      expect(result).toBe(null)
    })

    const fakeAlarm: AlarmClockOccurrence = {
      DeleteOnCompletion: true,
      ElementName: 'Instance Name',
      InstanceID: 'Instance',
      StartTime: new Date('2022-12-31T23:59:00Z')
    }
    it('should create an alarm occurence', async () => {
      getSpy.mockResolvedValueOnce(addAlarmClockOccurrenceResponse)

      const result = await device.addAlarmClockOccurrence(fakeAlarm)
      expect(result).toEqual(addAlarmClockOccurrenceResponse.Envelope)
    })
    it('should return null when call to addAlarmClockOccurrence fails', async () => {
      getSpy.mockResolvedValueOnce(null)
      const result = await device.addAlarmClockOccurrence(fakeAlarm)
      expect(result).toBe(null)
    })
  })
})
