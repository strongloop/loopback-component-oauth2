// Copyright IBM Corp. 2015,2017. All Rights Reserved.
// Node module: loopback-component-oauth2
// This file is licensed under the MIT License.
// License text available at https://opensource.org/licenses/MIT

'use strict';
/**
 * Module dependencies.
 */
var SG = require('strong-globalize');
var g = SG();
var TokenError = require('../errors/tokenerror');

/**
 * https://tools.ietf.org/html/rfc7009
 *
 * @param {Server} server
 * @param {Object} options
 * @return {Function}
 * @api protected
 */
module.exports = function revoke(server, options, revokeToken) {
  if (typeof options === 'function' && revokeToken === undefined) {
    revokeToken = options;
    options = {};
  }
  options = options || {};

  if (!server) {
    throw new TypeError(g.f(
      '{{oauth2orize.revoke}} middleware requires a {{server}} argument'));
  }

  if (typeof revokeToken !== 'function') {
    throw new TypeError(g.f(
      '{{oauth2orize.revoke}} middleware requires a {{revokeToken}} function'));
  }

  var userProperty = options.userProperty || 'user';

  return function revoke(req, res, next) {
    // The 'user' property of `req` holds the authenticated user.  In the case
    // of the token endpoint, the property will contain the OAuth 2.0 client.
    var client = req[userProperty];

    var token = (req.body && req.body.token) || req.query.token;
    if (!token) {
      return next(new TokenError(g.f(
        'Missing required parameter: {{token}}'), 'invalid_request'));
    }
    var type = (req.body && req.body.token_type_hint) ||
      req.query.token_type_hint || 'access_token';

    if (type !== 'refresh_token' && type !== 'access_token') {
      return next(new TokenError(g.f(
        'Unsupported token type: %s', type), 'unsupported_token_type'));
    }

    revokeToken(client, token, type, function(err) {
      if (err) {
        return next(err);
      } else {
        res.status(200).end();
      }
    });
  };
};
