var util = require('util');

/**
 * `BadRequestError` error.
 *
 * @api public
 */
function BadRequestError(message) {
  Error.call(this);
  Error.captureStackTrace(this, arguments.callee);
  this.name = 'BadRequestError';
  this.message = message;
  this.status = 400;
}

/**
 * Inherit from `Error`.
 */
util.inherits(BadRequestError, Error);

/**
 * Expose `BadRequestError`.
 */
module.exports = BadRequestError;
