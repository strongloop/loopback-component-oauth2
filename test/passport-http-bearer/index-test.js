// Copyright IBM Corp. 2012,2014. All Rights Reserved.
// Node module: loopback-component-oauth2
// US Government Users Restricted Rights - Use, duplication or disclosure
// restricted by GSA ADP Schedule Contract with IBM Corp.

'use strict';
var vows = require('vows');
var assert = require('assert');
var util = require('util');
var bearer = require('../../lib/passport-http-bearer/index');

vows.describe('passport-http-bearer').addBatch({

  'module': {
    'should report a version': function(x) {
      assert.isString(bearer.version);
    },
  },

}).export(module);
