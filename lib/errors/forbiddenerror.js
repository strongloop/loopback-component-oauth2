// Copyright IBM Corp. 2013,2014. All Rights Reserved.
// Node module: loopback-component-oauth2
// US Government Users Restricted Rights - Use, duplication or disclosure
// restricted by GSA ADP Schedule Contract with IBM Corp.

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
