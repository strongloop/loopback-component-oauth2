// Copyright IBM Corp. 2013,2017. All Rights Reserved.
// Node module: loopback-component-oauth2
// This file is licensed under the MIT License.
// License text available at https://opensource.org/licenses/MIT

var util = require('util');
/**
 * `ForbiddenError` error.
 *
 * @api public
 */
function ForbiddenError(message) {
  Error.call(this);
  Error.captureStackTrace(this, arguments.callee);
  this.name = 'ForbiddenError';
  this.message = message;
  this.status = 403;
}

/**
 * Inherit from `Error`.
 */
util.inherits(ForbiddenError, Error);

/**
 * Expose `ForbiddenError`.
 */
module.exports = ForbiddenError;
