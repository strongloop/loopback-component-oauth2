// Copyright IBM Corp. 2012,2016. All Rights Reserved.
// Node module: loopback-component-oauth2
// This file is licensed under the MIT License.
// License text available at https://opensource.org/licenses/MIT

'use strict';
/**
 * Module dependencies.
 */
var path = require('path');
var SG = require('strong-globalize');
SG.SetRootDir(path.join(__dirname, '..'));
var g = SG();
var loopbackOAuth2 = require('./oauth2-loopback');
var exports = module.exports = loopbackOAuth2;

exports.oAuth2Provider = loopbackOAuth2; // Keep backward-compatibility
exports.oauth2orize = require('./oauth2orize');

/**
 * A factory function for middleware handler that obtains the `authentication`
 * handler configured by the OAuth2 component.
 *
 * @param { Object } [options]   // possible options: { oauthACLgateway : Boolean }
 *                               // if oauthACLgateway is true, we will check if the token provided is a user token.
 *                               //  |_ if the token is a user accesstoken (exists in AccessToken model), we skip oauth authentication
 *                               //  |_ if no token is provided, we skip oauth authentication
 *                               // if it is false, the oauth module will work as normal.
 */
exports.authenticate = function (options) {
  let router;

  // keep track of the tokens we have handled before so we do not need to query for every request.
  let inMemoryTokenList = {};
  return function oauth2AuthenticateHandler(req, res, next) {

    if (!router) {
      let app = req.app;
      let authenticate = app._oauth2Handlers && app._oauth2Handlers.authenticate;
      if (!authenticate) {
        return next(new Error(g.f('The {{OAuth2}} component was not configured for this application.')));
      }

      let handlers = authenticate(options);
      router = app.loopback.Router();
      for (let i = 0, n = handlers.length; i < n; i++) {
        router.use(handlers[i]);
      }
    }

    // if we did not explicitly enable the oauthACLgatewayEnabled option
    let oauthACLgatewayEnabledEnabled = options && options.oauthACLgatewayEnabled || false;
    if (oauthACLgatewayEnabledEnabled !== true) {
      return router(req, res, next);
    }

    // if we do not have an access_token, do not use oauth2 to authenticate this request.
    let accessToken = (req && (req.body && req.body.access_token) || (req.query && req.query.access_token)) || null;
    if (!accessToken) {
      next();
      return;
    }

    // We keep a map of accessTokens to make sure we do not query the same token over and over.
    // We keep the tokens alive for an hour, postponing them on each request.
    if (inMemoryTokenList[accessToken] === undefined) {
      inMemoryTokenList[accessToken] = {removalTimeout: null, isUserToken: null};
    }
    else if (inMemoryTokenList[accessToken].removalTimeout) {
      // remove the pending timeout so we can set a new one.
      clearTimeout(inMemoryTokenList[accessToken].removalTimeout);
    }

    // set a new timeout to remove this token from the inMemoryTokenList to make sure we do not keep an ever growing list.
    inMemoryTokenList[accessToken].removalTimeout = setTimeout(() => { inMemoryTokenList[accessToken] = undefined; delete inMemoryTokenList[accessToken]; }, 3600000 ); // remove reference after one hour

    // if we have seen this token before and if it turns out to be a user token, we skip the oauth authentication.
    if (inMemoryTokenList[accessToken].isUserToken === true) {
      next();
      return;
    }
    else if (inMemoryTokenList[accessToken].isUserToken === false) {
      return router(req, res, next);
    }

    let accessTokenModel = req.app.loopback.getModel("AccessToken");
    // if we use promises insteade of the callback, the context is lost and the loopback-component-access-groups middleware fails to do it's thing.
    accessTokenModel.findById(accessToken, function (err, token) {
      // if the token is not found, it is null. If it is not in the user AccessToken model, we let oauth handle it.
      if (token === null || err) {
        inMemoryTokenList[accessToken].isUserToken = false;
        return router(req, res, next);
      }
      else {
        // the token belongs to a user, we skip the oauth step.
        inMemoryTokenList[accessToken].isUserToken = true;
        next();
      }
    });
  };
}; 
