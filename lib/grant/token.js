// Copyright IBM Corp. 2012,2017. All Rights Reserved.
// Node module: loopback-component-oauth2
// This file is licensed under the MIT License.
// License text available at https://opensource.org/licenses/MIT

'use strict';
/**
 * Module dependencies.
 */
const SG = require('strong-globalize');
const g = SG();
const url = require('url'),
  qs = require('querystring'),
  utils = require('../utils'),
  AuthorizationError = require('../errors/authorizationerror');

/**
 * Handles requests to obtain an implicit grant.
 *
 * Callbacks:
 *
 * This middleware requires an `issue` callback, for which the function
 * signature is as follows:
 *
 *     function(client, user, scope, ares, done) { ... }
 *
 * `client` is the client instance making the authorization request.  `user` is
 * the authenticated user approving the request.  `ares` is any additional
 * parameters parsed from the user's decision, including scope, duration of
 * access, etc.  `done` is called to issue an access token:
 *
 *     done(err, accessToken, params)
 *
 * `accessToken` is the access token that will be sent to the client.
 * Optionally, any additional `params` will be included in the response.  If an
 * error occurs, `done` should be invoked with `err` set in idomatic Node.js
 * fashion.
 *
 * Implicit grants do not include client authentication, and rely on the
 * registration of the redirect URI.  Applications can enforce this constraint
 * in the `validate` callback of `authorization` middleware.
 *
 * Options:
 *
 *     scopeSeparator  separator used to demarcate scope values (default: ' ')
 *
 * Examples:
 *
 *     server.grant(oauth2orize.grant.token(function(client, user, scope, ares, done) {}
 *       AccessToken.create(client, user, scope, function(err, accessToken) {
 *         if (err) { return done(err); }
 *         done(null, accessToken);
 *       });
 *     }));
 *
 * References:
 *  - [Implicit](http://tools.ietf.org/html/draft-ietf-oauth-v2-28#section-1.3.2)
 *  - [Implicit Grant](http://tools.ietf.org/html/draft-ietf-oauth-v2-28#section-4.2)
 *
 * @param {Object} options
 * @param {Function} issue
 * @return {Object} module
 * @api public
 */
module.exports = function token(options, issue) {
  if (typeof options === 'function') {
    issue = options;
    options = undefined;
  }
  options = options || {};

  if (!issue) { throw new TypeError(g.f('{{oauth2orize.token}} grant requires an {{issue}} callback')); }

  // For maximum flexibility, multiple scope spearators can optionally be
  // allowed.  This allows the server to accept clients that separate scope
  // with either space or comma (' ', ',').  This violates the specification,
  // but achieves compatibility with existing client libraries that are already
  // deployed.
  let separators = options.scopeSeparator || ' ';
  if (!Array.isArray(separators)) {
    separators = [separators];
  }

  function getParam(req, name) {
    if (options.allowsPost) {
      return req.param(name);
    } else {
      return req.query[name];
    }
  }

  /* Parse requests that request `token` as `response_type`.
   *
   * @param {http.ServerRequest} req
   * @api public
   */
  function request(req) {
    const clientID = getParam(req, 'client_id'),
      redirectURI = getParam(req, 'redirect_uri'),
      state = getParam(req, 'state');
    let scope = getParam(req, 'scope');

    if (!clientID) {
      throw new AuthorizationError(g.f('Missing required parameter: {{client_id}}'), 'invalid_request');
    }

    if (scope) {
      for (let i = 0, len = separators.length; i < len; i++) {
        const separated = scope.split(separators[i]);
        // only separate on the first matching separator.  this allows for a sort
        // of separator "priority" (ie, favor spaces then fallback to commas)
        if (separated.length > 1) {
          scope = separated;
          break;
        }
      }

      if (!Array.isArray(scope)) { scope = [scope]; }
    }

    return {
      clientID: clientID,
      redirectURI: redirectURI,
      scope: scope,
      state: state,
    };
  }

  /* Sends responses to transactions that request `token` as `response_type`.
   *
   * @param {Object} txn
   * @param {http.ServerResponse} res
   * @param {Function} next
   * @api public
   */
  function response(txn, res, next) {
    if (!txn.redirectURI) { return next(new Error(g.f('Unable to issue redirect for {{OAuth 2.0}} transaction'))); }
    if (!txn.res.allow) {
      const err = {};
      err.error = 'access_denied';
      if (txn.req && txn.req.state) { err.state = txn.req.state; }

      const parsed = url.parse(txn.redirectURI);
      parsed.hash = qs.stringify(err);

      const location = url.format(parsed);
      return res.redirect(location);
    }

    function issued(err, accessToken, params) {
      if (err) { return next(err); }
      if (!accessToken) {
        return next(new AuthorizationError(g.f('Request denied by authorization server'), 'access_denied'));
      }

      const tok = {};
      tok.access_token = accessToken;
      if (params) { utils.merge(tok, params); }
      tok.token_type = tok.token_type || 'Bearer';
      if (txn.req && txn.req.state) { tok.state = txn.req.state; }

      const parsed = url.parse(txn.redirectURI);
      parsed.hash = qs.stringify(tok);

      const location = url.format(parsed);
      return res.redirect(location);
    }

    // NOTE: In contrast to an authorization code grant, redirectURI is not
    //       passed as an argument to the issue callback because it is not used
    //       as a verifier in a subsequent token exchange.  However, when
    //       issuing an implicit access tokens, an application must ensure that
    //       the redirection URI is registered, which can be done in the
    //       `validate` callback of `authorization` middleware.

    try {
      const arity = issue.length;
      if (arity === 5) {
        issue(txn.client, txn.user, txn.req.scope, txn.res, issued);
      } else { // arity == 4
        issue(txn.client, txn.user, txn.req.scope, issued);
      }
    } catch (ex) {
      return next(ex);
    }
  }

  /**
   * Return `token` approval module.
   */
  const mod = {};
  mod.name = 'token';
  mod.request = request;
  mod.response = response;
  return mod;
};
