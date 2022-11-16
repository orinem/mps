/*********************************************************************
 * Copyright (c) Intel Corporation 2022
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

import index from './index'

describe('Check index from version', () => {
  let indexSpy: jest.SpyInstance
  beforeEach(() => {
    indexSpy = jest.spyOn(index, 'get')
  })
  it('should pass', async () => {
    expect(indexSpy).toBeDefined()
  })
})
