var debug = require('debug')('loopback:oauth2:scope');
var oauth2Provider = require('./oauth2orize');

/**
 * Normalize scope to string[]
 * @param {String|String[]} scope
 * @returns {String[]}
 */
function normalizeScope(scope) {
  if (!scope) {
    return [];
  }
  var scopes;
  if (Array.isArray(scope)) {
    scopes = [].concat(scope);
  } else if (typeof scope === 'string') {
    scopes = scope.split(/[\s,]+/g).filter(Boolean);
  } else {
    throw new Error('Invalid scope: ' + scope);
  }
  return scopes;
}

/**
 * Check if one of the scopes is in the allowedScopes array
 * @param {String[]} allowedScopes An array of required scopes
 * @param {String[]} scopes An array of granted scopes
 * @returns {boolean}
 */
function isAllowed(allowedScopes, tokenScopes) {
  if (allowedScopes.length === 0) {
    return true;
  }
  for (var i = 0, n = allowedScopes.length; i < n; i++) {
    if (allowedScopes.indexOf(tokenScopes[i]) !== -1) {
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
function isAuthorized(requestedScopes, authorizedScopes) {
  requestedScopes = normalizeScope(requestedScopes);
  authorizedScopes = normalizeScope(authorizedScopes);
  if (requestedScopes.length === 0) {
    return true;
  }
  for (var i = 0, n = requestedScopes.length; i < n; i++) {
    if (requestedScopes.indexOf(authorizedScopes[i]) === -1) {
      return false;
    }
  }
  return true;
}

module.exports = function(scope) {
  var allowedScopes = normalizeScope(scope);
  return function validateScope(req, res, next) {
    debug('Allowed scopes: ', allowedScopes);
    var scopes = normalizeScope(req.accessToken && req.accessToken.scopes);
    debug('Scopes of the access token: ', scopes);
    if (isAllowed(allowedScopes, scopes)) {
      next();
    } else {
      debug('Insufficient scope: ', scopes);
      next(new oauth2Provider.TokenError(
        'Insufficient scope', 'insufficient_scope', null, 403));
    }
  };
}

module.exports.isAuthorized = isAuthorized;
module.exports.isAllowed = isAllowed;
module.exports.normalizeScope = normalizeScope;