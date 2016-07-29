// Copyright IBM Corp. 2015. All Rights Reserved.
// Node module: loopback-component-oauth2
// US Government Users Restricted Rights - Use, duplication or disclosure
// restricted by GSA ADP Schedule Contract with IBM Corp.

/**
 * `OAuth2Error` error.
 *
 * @api public
 */
function OAuth2Error(message, code, uri, status) {
  Error.call(this);
  this.message = message;
  this.code = code || 'server_error';
  this.uri = uri;
  this.status = status || 500;
}

/**
 * Inherit from `Error`.
 */
OAuth2Error.prototype.__proto__ = Error.prototype;

/**
 * Expose `OAuth2Error`.
 */
module.exports = OAuth2Error;
