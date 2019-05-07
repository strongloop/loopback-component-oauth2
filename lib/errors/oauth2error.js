// Copyright IBM Corp. 2015,2017. All Rights Reserved.
// Node module: loopback-component-oauth2
// This file is licensed under the MIT License.
// License text available at https://opensource.org/licenses/MIT

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
