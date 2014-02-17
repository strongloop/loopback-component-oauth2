var vows = require('vows');
var assert = require('assert');
var util = require('util');
var bearer = require('../../lib/passport-http-bearer/index');


vows.describe('passport-http-bearer').addBatch({
  
  'module': {
    'should report a version': function (x) {
      assert.isString(bearer.version);
    },
  },
  
}).export(module);
