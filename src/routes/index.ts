/*********************************************************************
 * Copyright (c) Intel Corporation 2022
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

import { Router } from 'express'
import deviceRouter from './devices/index'
import { mpsrootcert } from './certs'
import authRouter from './auth/index'
import amtRouter from './amt/index'
import healthRouter from './health'
import version from './version'

const router: Router = Router()

router.use('/authorize', authRouter)
router.use('/devices', deviceRouter)
router.get('/ciracert', mpsrootcert)
router.use('/amt', amtRouter)
router.use('/health', healthRouter)
router.use('/version', version)

export default router
