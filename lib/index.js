// Copyright IBM Corp. 2012,2017. All Rights Reserved.
// Node module: loopback-component-oauth2
// This file is licensed under the MIT License.
// License text available at https://opensource.org/licenses/MIT

'use strict';
/**
 * Module dependencies.
 */
const path = require('path');
const SG = require('strong-globalize');
SG.SetRootDir(path.join(__dirname, '..'));
const g = SG();
const loopbackOAuth2 = require('./oauth2-loopback');
exports = module.exports = loopbackOAuth2;

exports.oAuth2Provider = loopbackOAuth2; // Keep backward-compatibility
exports.oauth2orize = require('./oauth2orize');

/**
 * A factory function for middleware handler that obtains the `authentication`
 * handler configured by the OAuth2 component.
 */
exports.authenticate = function(options) {
  let router;
  return function oauth2AuthenticateHandler(req, res, next) {
    if (!router) {
      const app = req.app;
      const authenticate = app._oauth2Handlers && app._oauth2Handlers.authenticate;

      if (!authenticate) {
        return next(new Error(g.f(
          'The {{OAuth2}} component was not configured for this application.'
        )));
      }

      const handlers = authenticate(options);
      router = app.loopback.Router();
      for (let i = 0, n = handlers.length; i < n; i++) {
        router.use(handlers[i]);
      }
    }

    return router(req, res, next);
  };
};
