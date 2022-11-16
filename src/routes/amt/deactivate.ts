/*********************************************************************
 * Copyright (c) Intel Corporation 2022
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

import { Response, Request } from 'express'
import { logger, messages } from '../../logging'
import { ErrorResponse } from '../../utils/amtHelper'
import { MqttProvider } from '../../utils/MqttProvider'

export async function deactivate (req: Request, res: Response): Promise<void> {
  try {
    const guid: string = req.params.guid

    const result = await req.deviceAction.unprovisionDevice()
    if (result.Body?.Unprovision_OUTPUT?.ReturnValue === 0) {
      await req.db.devices.delete(guid)
      await req.secrets.deleteSecretAtPath(`devices/${guid}`)
      res.status(200).json({ status: 'SUCCESS' })
    } else {
      res.status(200).json(result.Body?.Unprovision_OUTPUT)
    }
  } catch (error) {
    logger.error(`${messages.UNPROVISION_EXCEPTION} : ${error}`)
    MqttProvider.publishEvent('fail', ['AMT_Unprovision'], messages.INTERNAL_SERVICE_ERROR)
    res.status(500).json(ErrorResponse(500, messages.UNPROVISION_EXCEPTION))
  }
}
