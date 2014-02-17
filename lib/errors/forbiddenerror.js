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
