// Copyright IBM Corp. 2012,2017. All Rights Reserved.
// Node module: loopback-component-oauth2
// This file is licensed under the MIT License.
// License text available at https://opensource.org/licenses/MIT

'use strict';
const vows = require('vows');
const assert = require('assert');
const util = require('util');
const bearer = require('../../lib/passport-http-bearer/index');

vows.describe('passport-http-bearer').addBatch({

  'module': {
    'should report a version': function(x) {
      assert.isString(bearer.version);
    },
  },

}).export(module);
