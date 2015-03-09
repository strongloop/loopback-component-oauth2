var debug = require('debug')('loopback:oauth2:scope');
var oauth2Provider = require('./oauth2orize');
var helpers = require('./oauth2-helper');

module.exports = function(scope) {
  var allowedScopes = scope;
  return function validateScope(req, res, next) {
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
