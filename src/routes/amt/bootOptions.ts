/*********************************************************************
 * Copyright (c) Intel Corporation 2022
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

import { Response, Request } from 'express'
import { logger, messages } from '../../logging'
import { ErrorResponse } from '../../utils/amtHelper'
import { MqttProvider } from '../../utils/MqttProvider'
import { AMTStatusCodes } from '../../utils/constants'
import { AMT, CIM } from '@open-amt-cloud-toolkit/wsman-messages'

export async function bootOptions (req: Request, res: Response): Promise<void> {
  try {
    const payload = req.body // payload.action
    const device = req.deviceAction
    const results = await device.getBootOptions()
    const bootData = setBootData(payload.action, payload.useSOL, results.AMT_BootSettingData)
    await device.setBootConfiguration(bootData)
    const forceBootSource = setBootSource(payload.action)
    if (forceBootSource != null) { // only if
      await device.forceBootMode(forceBootSource)
      await device.changeBootOrder(forceBootSource)
    } else {
      await device.forceBootMode()
    }
    const newAction = determinePowerAction(payload.action)
    const powerActionResult = await device.sendPowerAction(newAction)
    powerActionResult.Body.RequestPowerStateChange_OUTPUT.ReturnValueStr = AMTStatusToString(powerActionResult.Body.RequestPowerStateChange_OUTPUT.ReturnValue)
    powerActionResult.Body = powerActionResult.Body.RequestPowerStateChange_OUTPUT

    res.status(200).json(powerActionResult)
  } catch (error) {
    logger.error(`${messages.BOOT_SETTING_EXCEPTION} : ${error}`)
    MqttProvider.publishEvent('fail', ['AMT_BootSettingData'], messages.INTERNAL_SERVICE_ERROR)
    res.status(500).json(ErrorResponse(500, messages.BOOT_SETTING_EXCEPTION))
  }
}

export function setBootData (action: number, useSOL: boolean, r: AMT.Models.BootSettingData): AMT.Models.BootSettingData {
  r.BIOSPause = false
  r.BIOSSetup = action < 104
  r.BootMediaIndex = 0
  r.ConfigurationDataReset = false
  r.FirmwareVerbosity = 0
  r.ForcedProgressEvents = false
  r.IDERBootDevice = action === 202 || action === 203 ? 1 : 0 // 0 = Boot on Floppy, 1 = Boot on IDER
  r.LockKeyboard = false
  r.LockPowerButton = false
  r.LockResetButton = false
  r.LockSleepButton = false
  r.ReflashBIOS = false
  r.UseIDER = action > 199 && action < 300
  r.UseSOL = useSOL
  r.UseSafeMode = false
  r.UserPasswordBypass = false
  r.SecureErase = false
  return r
}

export function setBootSource (action: number): string {
  let bootSource
  if (action === 300 || action === 301) {
    bootSource = 'Force Diagnostic Boot'
  }
  if (action === 400 || action === 401) {
    bootSource = 'Force PXE Boot'
  }

  return bootSource
}

export function determinePowerAction (action: number): CIM.Types.PowerManagementService.PowerState {
  let powerState: CIM.Types.PowerManagementService.PowerState = 2
  if (action === 101 || action === 200 || action === 202 || action === 301 || action === 400) {
    powerState = 10
  } // Reset

  return powerState
}

function AMTStatusToString (code: number): string {
  if (AMTStatusCodes[code]) {
    return AMTStatusCodes[code]
  } else return 'UNKNOWN_ERROR'
}
