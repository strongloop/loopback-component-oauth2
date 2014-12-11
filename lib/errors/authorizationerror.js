var util = require('util');
/**
 * `AuthorizationError` error.
 *
 * @api public
 */
function AuthorizationError(message, code, uri, status) {
  if (!status) {
    switch (code) {
      case 'invalid_request': status = 400; break;
      case 'invalid_client': status = 401; break;
      case 'unauthorized_client': status = 403; break;
      case 'access_denied': status = 403; break;
      case 'unsupported_response_type': status = 400; break;
      case 'invalid_scope': status = 400; break;
      case 'temporarily_unavailable': status = 503; break;
    }
  }
  
  Error.call(this);
  Error.captureStackTrace(this, arguments.callee);
  this.name = 'AuthorizationError';
  this.message = message;
  this.code = code || 'server_error';
  this.uri = uri;
  this.status = status || 500;
}

/**
 * Inherit from `Error`.
 */
util.inherits(AuthorizationError, Error);

/**
 * Expose `AuthorizationError`.
 */
module.exports = AuthorizationError;
