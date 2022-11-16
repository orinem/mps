/*********************************************************************
 * Copyright (c) Intel Corporation 2022
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

import { Request, Response } from 'express'
import { logger } from '../../logging/logger'
import { messages } from '../../logging/messages'

export async function stats (req: Request, res: Response): Promise<void> {
  try {
    const connectedCount = await req.db.devices.getConnectedDevices()
    const totalCount = await req.db.devices.getCount()
    res.json({
      totalCount,
      connectedCount,
      disconnectedCount: Math.max(totalCount - connectedCount, 0)
    })
  } catch (err) {
    logger.error(`${messages.DEVICE_GET_STATES_EXCEPTION}: ${err}`)
    res.status(500).end()
  }
}
