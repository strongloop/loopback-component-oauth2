// Copyright IBM Corp. 2014,2017. All Rights Reserved.
// Node module: loopback-component-oauth2
// This file is licensed under the MIT License.
// License text available at https://opensource.org/licenses/MIT

'use strict';
var tokenDef = require('../../common/models/oauth-token.json');
var authorizationCodeDef =
  require('../../common/models/oauth-authorization-code.json');
var clientApplicationDef =
  require('../../common/models/oauth-client-application.json');
var permissionDef =
  require('../../common/models/oauth-permission.json');
var scopeDef =
  require('../../common/models/oauth-scope.json');

var scopeMappingDef =
  require('../../common/models/oauth-scope-mapping.json');

// Remove proerties that will confuse LB
function getSettings(def) {
  var settings = {};
  for (var s in def) {
    if (s === 'name' || s === 'properties') {
      continue;
    } else {
      settings[s] = def[s];
    }
  }
  return settings;
}

module.exports = function(dataSource) {
  // "OAuth token"
  var OAuthToken = dataSource.createModel(
    tokenDef.name, tokenDef.properties, getSettings(tokenDef));

  // "OAuth authorization code"
  var OAuthAuthorizationCode = dataSource.createModel(
    authorizationCodeDef.name,
    authorizationCodeDef.properties,
    getSettings(authorizationCodeDef));

  // "OAuth client registration record"
  var OAuthClientApplication = dataSource.createModel(
    clientApplicationDef.name,
    clientApplicationDef.properties,
    getSettings(clientApplicationDef));

  // "OAuth permission"
  var OAuthPermission = dataSource.createModel(
    permissionDef.name,
    permissionDef.properties,
    getSettings(permissionDef));

  // "OAuth scope"
  var OAuthScope = dataSource.createModel(
    scopeDef.name,
    scopeDef.properties,
    getSettings(scopeDef));

  // "OAuth scope mapping"
  var OAuthScopeMapping = dataSource.createModel(
    scopeMappingDef.name,
    scopeMappingDef.properties,
    getSettings(scopeMappingDef));

  return {
    OAuthToken: OAuthToken,
    OAuthAuthorizationCode: OAuthAuthorizationCode,
    OAuthClientApplication: OAuthClientApplication,
    OAuthPermission: OAuthPermission,
    OAuthScope: OAuthScope,
    OAuthScopeMapping: OAuthScopeMapping,
  };
};
