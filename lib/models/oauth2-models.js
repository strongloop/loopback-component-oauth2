var tokenDef = require('../../common/models/oauth-token.json');
var authorizationCodeDef =
  require('../../common/models/oauth-authorization-code.json');
var clientRegistrationDef =
  require('../../common/models/oauth-client-registration.json');
var permissionDef =
  require('../../common/models/oauth-permission.json');
var scopeDef =
  require('../../common/models/oauth-scope.json');

module.exports = function(dataSource) {

  // "OAuth token"
  var OAuthToken = dataSource.createModel(
    tokenDef.name, tokenDef.properties);

  // "OAuth authorization code"
  var OAuthAuthorizationCode = dataSource.createModel(
    authorizationCodeDef.name, authorizationCodeDef.properties);

  // "OAuth client registration record"
  var ClientRegistration = dataSource.createModel(
    clientRegistrationDef.name, clientRegistrationDef.properties);

  // "OAuth permission"
  var OAuthPermission = dataSource.createModel(
    permissionDef.name, permissionDef.properties);

  // "OAuth scope"
  var OAuthScope = dataSource.createModel(
    scopeDef.name, scopeDef.properties);

  return {
    OAuthToken: OAuthToken,
    OAuthAuthorizationCode: OAuthAuthorizationCode,
    ClientRegistration: ClientRegistration,
    OAuthPermission: OAuthPermission,
    OAuthScope: OAuthScope
  };
};
