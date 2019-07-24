// Copyright IBM Corp. 2014,2017. All Rights Reserved.
// Node module: loopback-component-oauth2
// This file is licensed under the MIT License.
// License text available at https://opensource.org/licenses/MIT

'use strict';
const tokenDef = require('../../common/models/oauth-token.json');
const authorizationCodeDef =
  require('../../common/models/oauth-authorization-code.json');
const clientApplicationDef =
  require('../../common/models/oauth-client-application.json');
const permissionDef =
  require('../../common/models/oauth-permission.json');
const scopeDef =
  require('../../common/models/oauth-scope.json');

const scopeMappingDef =
  require('../../common/models/oauth-scope-mapping.json');

// Remove proerties that will confuse LB
function getSettings(def) {
  const settings = {};
  for (const s in def) {
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
  const OAuthToken = dataSource.createModel(
    tokenDef.name, tokenDef.properties, getSettings(tokenDef)
  );

  // "OAuth authorization code"
  const OAuthAuthorizationCode = dataSource.createModel(
    authorizationCodeDef.name,
    authorizationCodeDef.properties,
    getSettings(authorizationCodeDef)
  );

  // "OAuth client registration record"
  const OAuthClientApplication = dataSource.createModel(
    clientApplicationDef.name,
    clientApplicationDef.properties,
    getSettings(clientApplicationDef)
  );

  // "OAuth permission"
  const OAuthPermission = dataSource.createModel(
    permissionDef.name,
    permissionDef.properties,
    getSettings(permissionDef)
  );

  // "OAuth scope"
  const OAuthScope = dataSource.createModel(
    scopeDef.name,
    scopeDef.properties,
    getSettings(scopeDef)
  );

  // "OAuth scope mapping"
  const OAuthScopeMapping = dataSource.createModel(
    scopeMappingDef.name,
    scopeMappingDef.properties,
    getSettings(scopeMappingDef)
  );

  return {
    OAuthToken: OAuthToken,
    OAuthAuthorizationCode: OAuthAuthorizationCode,
    OAuthClientApplication: OAuthClientApplication,
    OAuthPermission: OAuthPermission,
    OAuthScope: OAuthScope,
    OAuthScopeMapping: OAuthScopeMapping,
  };
};
