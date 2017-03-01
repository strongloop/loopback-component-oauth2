// Copyright IBM Corp. 2014,2015. All Rights Reserved.
// Node module: loopback-component-oauth2
// US Government Users Restricted Rights - Use, duplication or disclosure
// restricted by GSA ADP Schedule Contract with IBM Corp.

'use strict';
var utils = require('../../lib/utils');

module.exports = function(User) {
	/**
   * Create access token for the logged in user. This method can be overridden to
   * customize how access tokens are generated
   *
   * @param {Number} ttl The requested ttl
   * @param {Object} [options] The options for access token, such as scopes, appId
   * @callback {Function} cb The callback function
   * @param {String|Error} err The error string or object
   * @param {AccessToken} token The generated access token object
   * @promise
   */
  User.prototype.createAccessToken = function(ttl, options, cb) {
    if (cb === undefined && typeof options === 'function') {
      // createAccessToken(ttl, cb)
      cb = options;
      options = undefined;
    }

    cb = cb || utils.createPromiseCallback();

    if (typeof ttl === 'object' && !options) {
      // createAccessToken(options, cb)
      options = ttl;
      ttl = options.ttl;
    }
    options = options || {};
    var userModel = this.constructor;
    ttl = Math.min(ttl || userModel.settings.ttl, userModel.settings.maxTTL);
    this.accessTokens.create({
      ttl: ttl,
      appId: options.appId,
      scopes: options.scopes,
      refreshToken: utils.uid(32),
    }, cb);
    return cb.promise;
  };
};
