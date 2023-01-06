/*********************************************************************
 * Copyright (c) Intel Corporation 2022
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

import { validationResult } from 'express-validator'
import { Request, Response } from 'express'
import { logger } from '../../logging/logger'
import { Environment } from '../../utils/Environment'
import { messages } from '../../logging'
import { signature } from './signature'
import got from 'got'
import validate from 'validate-azure-ad-token'

interface PartialAzureProfileType {
  givenName?: string
  surname?: string
  userPrincipalName?: string
  id?: string
}

export async function login (req: Request, res: Response): Promise<void> {
  const errors = validationResult(req)
  if (!errors.isEmpty()) {
    res.status(400).json({ errors: errors.array() })
    return
  }

  // For Azure authentication, the bearer token is passed as the password and the username is 'AzureAD'
  // We call the graph API to find the user and ensure the user is allowed.
  if (req.body.password && req.body.username === 'AzureAD') {
    try {
      // First validate that the token is from our app...
      try {
        await validate(req.body.password, {
          tenantId: Environment.Config.azure_tenantid,
          audience: '00000003-0000-0000-c000-000000000000', // graph
          applicationId: ,Environment.Config.azure_clientid
          scopes: ['User.Read']
        })
      } catch (error: unknown) {
        logger.silly(`${messages.LOGIN_FAILED}, Invalid Token`)
        res.status(401).send({ message: messages.LOGIN_FAILED })
        return
      }

      // We may make more graph calls in the future, so use got.extend here...
      const options = {
        prefixUrl: 'https://graph.microsoft.com/v1.0/',
        headers: {
          Authorization: `bearer ${req.body.password}`
        }
      }
      const client = got.extend(options)
      const profile: PartialAzureProfileType = await client.get('me').json()
      // For testing, just inisit on the userPrincipalName matching the configured user...
      // Other options could be:
      //  - check for group membership via graph
      //  - keep list of allowed users in the database
      if (profile.userPrincipalName?.toLowerCase() === Environment.Config.web_admin_user.toLowerCase()) {
        const expirationMinutes = Number(Environment.Config.jwt_expiration)
        res.status(200).send({ token: signature(expirationMinutes, '*') })
        return
      }
      // else let it fail naturally below...
    } catch (err) {
      logger.silly(`${messages.LOGIN_FAILED}, ${err}`)
      res.status(401).send({ message: messages.LOGIN_FAILED })
    }
  }

  // todo: implement a more advanced authentication system and RBAC
  if (!Environment.Config.web_auth_enabled) {
    res.status(405).send({ message: messages.AUTH_DISABLED })
    return
  }
  const username: string = req.body.username
  const password: string = req.body.password
  if (username.toLowerCase() === Environment.Config.web_admin_user.toLowerCase() && password === Environment.Config.web_admin_password) {
    const expirationMinutes = Number(Environment.Config.jwt_expiration)
    res.status(200).send({ token: signature(expirationMinutes, '*') })
  } else {
    logger.silly(`${messages.LOGIN_FAILED}, username: ${username}`)
    res.status(401).send({ message: messages.LOGIN_FAILED })
  }
}
