// Copyright IBM Corp. 2015,2016. All Rights Reserved.
// Node module: loopback-component-oauth2
// This file is licensed under the MIT License.
// License text available at https://opensource.org/licenses/MIT

'use strict';
var SG = require('strong-globalize');
var g = SG();
var jwt = require('jws');
var AuthorizationError = require('./errors/authorizationerror');

function clientInfo(client) {
  if (!client) {
    return client;
  }
  return client.id + ',' + client.name;
}

function userInfo(user) {
  if (!user) {
    return user;
  }
  return user.id + ',' + user.username + ',' + user.email;
}

function isExpired(tokenOrCode) {
  var issuedTime =
    (tokenOrCode.created && tokenOrCode.created.getTime());
  var now = Date.now();
  var expirationTime = issuedTime + (tokenOrCode.ttl * 1000);
  return now > expirationTime;
}

/**
 * Normalize items to string[]
 * @param {String|String[]} items
 * @returns {String[]}
 */
function normalizeList(items) {
  if (!items) {
    return [];
  }
  var list;
  if (Array.isArray(items)) {
    list = [].concat(items);
  } else if (typeof items === 'string') {
    list = items.split(/[\s,]+/g).filter(Boolean);
  } else {
    throw new Error(g.f('Invalid items: %s', items));
  }
  return list;
}

/**
 * Normalize scope to string[]
 * @param {String|String[]} scope
 * @returns {String[]}
 */
function normalizeScope(scope) {
  return normalizeList(scope);
}

/**
 * Check if one of the scopes is in the allowedScopes array
 * @param {String[]} allowedScopes An array of required scopes
 * @param {String[]} scopes An array of granted scopes
 * @returns {boolean}
 */
function isScopeAllowed(allowedScopes, tokenScopes) {
  allowedScopes = normalizeScope(allowedScopes);
  tokenScopes = normalizeScope(tokenScopes);
  if (allowedScopes.length === 0) {
    return true;
  }
  for (var i = 0, n = allowedScopes.length; i < n; i++) {
    if (tokenScopes.indexOf(allowedScopes[i]) !== -1) {
      return true;
    }
  }
  return false;
}

/**
 * Check if the requested scopes are covered by authorized scopes
 * @param {String|String[]) requestedScopes
 * @param {String|String[]) authorizedScopes
 * @returns {boolean}
 */
function isScopeAuthorized(requestedScopes, authorizedScopes) {
  requestedScopes = normalizeScope(requestedScopes);
  authorizedScopes = normalizeScope(authorizedScopes);
  if (requestedScopes.length === 0) {
    return true;
  }
  for (var i = 0, n = requestedScopes.length; i < n; i++) {
    if (authorizedScopes.indexOf(requestedScopes[i]) === -1) {
      return false;
    }
  }
  return true;
}

function validateClient(client, options, next) {
  options = options || {};
  next = next || function(err) {
    return err;
  };
  var err;
  if (options.redirectURI) {
    var redirectURIs = client.callbackUrls || client.redirectUris || client.redirectURIs || [];

    if (redirectURIs.length > 0) {
      var matched = false;
      for (var i = 0, n = redirectURIs.length; i < n; i++) {
        if (options.redirectURI.indexOf(redirectURIs[i]) === 0) {
          matched = true;
          break;
        }
      }
      if (!matched) {
        err = new AuthorizationError(g.f(
            'Unauthorized {{redirectURI}}: %s', options.redirectURI), 'access_denied');
        return next(err) || err;
      }
    }
  }

  if (options.scope) {
    var authorizedScopes = normalizeList(client.scopes);
    var requestedScopes = normalizeList(options.scope);
    if (authorizedScopes.length && !isScopeAuthorized(requestedScopes, authorizedScopes)) {
      err = new AuthorizationError(g.f(
          'Unauthorized {{scope}}: %s', options.scope), 'access_denied');
      return next(err) || err;
    }
  }

  // token or code
  if (options.responseType) {
    var authorizedTypes = normalizeList(client.responseTypes);
    if (authorizedTypes.length &&
      authorizedTypes.indexOf(options.responseType) === -1) {
      err = new AuthorizationError(g.f(
          'Unauthorized response type: %s', options.responseType), 'access_denied');
      return next(err) || err;
    }
  }

  // authorization_code, password, client_credentials, refresh_token,
  // urn:ietf:params:oauth:grant-type:jwt-bearer
  if (options.grantType) {
    var authorizedGrantTypes = normalizeList(client.grantTypes);
    if (authorizedGrantTypes.length &&
      authorizedGrantTypes.indexOf(options.grantType) === -1) {
      err = new AuthorizationError(g.f(
          'Unauthorized grant type: %s', options.grantType), 'access_denied');
      return next(err) || err;
    }
  }
  return null;
}

function generateJWT(payload, secret, alg) {
  var body = {
    header: {alg: alg || 'HS256'}, // Default to hash
    secret: secret,
    payload: payload,
  };
  return jwt.sign(body);
}

function buildTokenParams(accessToken, token) {
  var params = {
    expires_in: accessToken.expiresIn,
  };
  var scope = accessToken.scopes && accessToken.scopes.join(' ');
  if (scope) {
    params.scope = scope;
  }
  if (accessToken.refreshToken) {
    params.refresh_token = accessToken.refreshToken;
  }
  if (typeof token === 'object') {
    for (var p in token) {
      if (p !== 'id' && !params[p] && token[p]) {
        params[p] = token[p];
      }
    }
  }
  return params;
}

module.exports = {
  clientInfo: clientInfo,
  userInfo: userInfo,
  isExpired: isExpired,
  normalizeList: normalizeList,
  validateClient: validateClient,
  isScopeAllowed: isScopeAllowed,
  isScopeAuthorized: isScopeAuthorized,
  generateJWT: generateJWT,
  buildTokenParams: buildTokenParams,
};
