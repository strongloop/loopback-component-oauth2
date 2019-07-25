// Copyright IBM Corp. 2014,2017. All Rights Reserved.
// Node module: loopback-component-oauth2
// This file is licensed under the MIT License.
// License text available at https://opensource.org/licenses/MIT

'use strict';
const SG = require('strong-globalize');
const g = SG();
const pathToRegexp = require('path-to-regexp');
const debug = require('debug')('loopback:oauth2:scope');
const oauth2Provider = require('./oauth2orize');
const helpers = require('./oauth2-helper');

function toLowerCase(m) {
  return m.toLowerCase();
}

/**
 * Load the definition of scopes
 *
 * ```json
 * {
 *   "scope1": [{"methods": "get", path: "/:user/profile"}, "/order"],
 *   "scope2": [{"methods": "post", path: "/:user/profile"}]
 * }
 * ```
 * @param {Object} scopes
 * @returns {Object}
 */
function loadScopes(scopes) {
  const scopeMapping = {};
  if (typeof scopes === 'object' && !Array.isArray(scopes)) {
    for (const s in scopes) {
      const routes = [];
      const entries = scopes[s];
      debug('Scope: %s routes: %j', s, entries);
      if (Array.isArray(entries)) {
        for (let j = 0, k = entries.length; j < k; j++) {
          const route = entries[j];
          if (typeof route === 'string') {
            routes.push({methods: ['all'], path: route,
              regexp: pathToRegexp(route, [], {end: false})});
          } else {
            let methods = helpers.normalizeList(route.methods);
            if (methods.length === 0) {
              methods.push('all');
            }
            methods = methods.map(toLowerCase);
            routes.push({methods: methods,
              path: route.path,
              regexp: pathToRegexp(route.path, [], {end: false})});
          }
        }
      } else {
        debug('Routes must be an array: %j', entries);
      }
      scopeMapping[s] = routes;
    }
  } else if (typeof scopes === 'string' || Array.isArray(scopes)) {
    scopes = helpers.normalizeList(scopes);
    for (let i = 0, n = scopes.length; i < n; i++) {
      scopeMapping[scopes[i]] = [
        {methods: 'all', path: '/.+', regexp: /\/.+/},
      ];
    }
  }
  return scopeMapping;
}

function findMatchedScopes(req, scopeMapping) {
  const matchedScopes = [];
  const method = req.method.toLowerCase();
  let url = req.originalUrl;
  for (const s in scopeMapping) {
    const routes = scopeMapping[s];
    for (let i = 0, n = routes.length; i < n; i++) {
      const route = routes[i];
      if (route.methods.indexOf('all') !== -1 ||
        route.methods.indexOf(method) !== -1) {
        debug('url: %s, regexp: %s', url, route.regexp);
        const index = url.indexOf('?');
        if (index !== -1) {
          url = url.substring(0, index);
        }
        if (route.regexp.test(url)) {
          matchedScopes.push(s);
        }
      }
    }
  }
  return matchedScopes;
}

/**
 * Validate if the oAuth 2 scope is satisfied
 *
 * @param {Object} options Options object
 * @returns {validateScope}
 */
module.exports = function(options) {
  const configuredScopes = options.checkScopes || options.scopes || options.scope;
  let checkScopes;
  if (typeof configuredScopes === 'function') {
    checkScopes = configuredScopes;
  } else {
    checkScopes = function(req, tokenScopes, cb) {
      const scopeMapping = loadScopes(configuredScopes);
      debug('Scope mapping: ', scopeMapping);
      const allowedScopes = findMatchedScopes(req, scopeMapping);
      debug('Allowed scopes: ', allowedScopes);
      if (helpers.isScopeAllowed(allowedScopes, tokenScopes)) {
        cb();
      } else {
        debug('Insufficient scope: ', tokenScopes);
        cb(new oauth2Provider.TokenError(g.f(
          'Insufficient scope'
        ), 'insufficient_scope', null, 403));
      }
    };
  }
  return function validateScope(req, res, next) {
    const scopes = req.accessToken && req.accessToken.scopes;
    debug('Scopes of the access token: ', scopes);
    checkScopes(req, scopes, next);
  };
};
