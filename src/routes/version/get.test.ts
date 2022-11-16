/*********************************************************************
 * Copyright (c) Intel Corporation 2022
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

import { getVersion } from './get'
import { createSpyObj } from '../../test/helper/jest'
import { ServiceVersion } from '../../utils/constants'

describe('Checks version of dependent services', () => {
  describe('getVersion tests', () => {
    let resSpy
    beforeEach(() => {
      resSpy = createSpyObj('Response', ['status', 'json', 'end', 'send'])
      resSpy.status.mockReturnThis()
      resSpy.json.mockReturnThis()
      resSpy.send.mockReturnThis()
    })
    it('should return a version', async () => {
      getVersion(null, resSpy)
      expect(resSpy.status).toHaveBeenCalledWith(200)
      expect(resSpy.json).toHaveBeenCalledWith({ serviceVersion: ServiceVersion })
    })
  })
})
