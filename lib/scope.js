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
 * Check if one of the scopes is in the requiredScopes array
 * @param {String[]} requiredScopes An array of required scopes
 * @param {String[]} scopes An array of granted scopes
 * @returns {boolean}
 */
function isInScope(requiredScopes, scopes) {
  if (requiredScopes.length === 0) {
    return true;
  }
  for (var i = 0, n = requiredScopes.length; i < n; i++) {
    if (requiredScopes.indexOf(scopes[i]) !== -1) {
      return true;
    }
  }
  return false;
}

function checkScopes(scopes, cb) {
  cb(null, true);
}

module.exports = function(scope) {
  var requiredScopes = normalizeScope(scope);
  return function validateScope(req, res, next) {
    debug('Required scopes: ', requiredScopes);
    var scopes = normalizeScope(req.accessToken && req.accessToken.scopes);
    debug('Scopes of the access token: ', scopes);
    if (isInScope(requiredScopes, scopes)) {
      next();
    } else {
      debug('Insufficient scope: ', scopes);
      next(new oauth2Provider.TokenError(
        'Insufficient scope', 'insufficient_scope', null, 403));
    }
  };
}