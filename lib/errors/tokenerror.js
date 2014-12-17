var util = require('util');
/**
 * `TokenError` error.
 *
 * @api public
 */
function TokenError(message, code, uri, status) {
  if (!status) {
    switch (code) {
      case 'invalid_request': status = 400; break;
      case 'invalid_client': status = 401; break;
      case 'invalid_grant': status = 403; break;
      case 'unauthorized_client': status = 403; break;
      case 'unsupported_grant_type': status = 400; break;
      case 'invalid_scope': status = 400; break;
    }
  }
  
  Error.call(this);
  Error.captureStackTrace(this, arguments.callee);
  this.name = 'TokenError';
  this.message = message;
  this.code = code || 'server_error';
  this.uri = uri;
  this.status = status || 500;
}

/**
 * Inherit from `Error`.
 */
util.inherits(TokenError, Error);

/**
 * Expose `TokenError`.
 */
module.exports = TokenError;
