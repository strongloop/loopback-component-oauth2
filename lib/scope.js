var pathToRegexp = require('path-to-regexp');
var debug = require('debug')('loopback:oauth2:scope');
var oauth2Provider = require('./oauth2orize');
var helpers = require('./oauth2-helper');

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
  var scopeMapping = {};
  if (typeof scopes === 'object') {
    for (var s in scopes) {
      var routes = [];
      var entries = scopes[s];
      debug('Scope: %s routes: %j', s, entries);
      if (Array.isArray(entries)) {
        for (var j = 0, k = entries.length; j < k; j++) {
          var route = entries[j];
          if (typeof route === 'string') {
            routes.push({methods: ['all'], path: route,
              regexp: pathToRegexp(route, [], {end: false})});
          } else {
            var methods = helpers.normalizeList(methods);
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
  } else if (typeof scopes === 'string') {
    scopes = helpers.normalizeList(scopes);
    for (var i = 0, n = scopes.length; i < n; i++) {
      scopeMapping[scopes[i]] = [
        {methods: 'all', path: '/.+', regexp: /\/.+/}
      ];
    }
  }
  return scopeMapping;
}

function findMatchedScopes(req, scopeMapping) {
  var matchedScopes = [];
  var method = req.method.toLowerCase();
  var url = req.originalUrl;
  for (var s in scopeMapping) {
    var routes = scopeMapping[s];
    for (var i = 0, n = routes.length; i < n; i++) {
      var route = routes[i];
      if (route.methods.indexOf('all') !== -1 ||
        route.methods.indexOf(method) !== -1) {
        debug("url: %s, regexp: %s", url, route.regexp);
        var index = url.indexOf('?');
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
 * @param {Object|String}|String[]} scopes A list of scopes or scope mapping
 * @returns {validateScope}
 */
module.exports = function(scopes) {
  var scopeMapping = loadScopes(scopes);
  return function validateScope(req, res, next) {
    var allowedScopes = findMatchedScopes(req, scopeMapping);
    debug('Allowed scopes: ', allowedScopes);
    var scopes = req.accessToken && req.accessToken.scopes;
    debug('Scopes of the access token: ', scopes);
    if (helpers.isScopeAllowed(allowedScopes, scopes)) {
      next();
    } else {
      debug('Insufficient scope: ', scopes);
      next(new oauth2Provider.TokenError(
        'Insufficient scope', 'insufficient_scope', null, 403));
    }
  };
}

