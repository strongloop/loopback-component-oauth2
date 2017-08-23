# loopback-component-oauth2

## What is different in this fork?

Apart from this readme, there has been a change to the lib index. This change is the addition of an option called "oauthACLgateway".

If **oauthACLgateway** is *true*, we will check if the *access_token* provided (to query or body) is a user token. If the token is a user token (exists in AccessToken model), we skip oauth authentication.
If no token is provided, we skip oauth authentication. Finally, if the option is omitted or false, the module will work as the original.

### How to use

Put something like this in your middleware.json:

```json
"auth": {
    "loopback-component-oauth2#authenticate": { "paths" : ["/api"], "params": [{
      "oauthACLgateway" : true,
      "scopes": {
        "read_only": [
          {
            "methods": "get",
            "path": "/api"
          }
        ],
        "write_only": [
          {
            "methods": "post",
            "path": "/api"
          }
        ],
        "read_write": [
          {
            "methods": ["get","post"],
            "path": "/api"
          }
        ],
        "all": [
          {
            "methods": "all",
            "path": "/api"
          }
        ]
      }
    }] }
  },
```

Additionally you will need to put the settings in the component-config.json. Here is the one we use as an example:

```json
"loopback-component-oauth2": {
    "dataSource": "db",
    "resourceServer": true,
    "authorizationServer": true,
    "loginPage": "/loginOauth",
    "loginPath": "/loginOauthStep2",
    "tokenPath": "/oauth/token"
  },
```

Finally, we put this in our loopback server.js after the boot function call:

```js
let options = {
  dataSource: app.dataSources.db, // Data source for oAuth2 metadata persistence
  resourceServer: true,
  authorizationServer: true,
  loginPage: '/loginOauth', // The login page URL
  loginPath: '/loginOauthStep2', // The login form processing URL
  tokenPath: "/oauth/token",
};

oauth2.oAuth2Provider(
  app, // The app instance
  options // The options
);
```

That's it! Enjoy!

## From the original repo:

The LoopBack oAuth 2.0 component provides full integration between [OAuth 2.0](http://tools.ietf.org/html/rfc6749)
and [LoopBack](http://loopback.io). It enables LoopBack applications to function
as an oAuth 2.0 provider to authenticate and authorize client applications and/or
resource owners (i.e. users) to access protected API endpoints.

The oAuth 2.0 protocol implementation is based on [oauth2orize](https://github.com/jaredhanson/oauth2orize)
and [passport](http://passportjs.org/). 

See [LoopBack Documentation - OAuth 2.0 Component](http://loopback.io/doc/en/lb2/OAuth-2.0.html) for more information.

## Install

Install the component as usual:

```
$ npm install loopback-component-oauth2
```

## Use

Use in an application as follows:

```js
var oauth2 = require('loopback-component-oauth2');

var options = { 
  dataSource: app.dataSources.db, // Data source for oAuth2 metadata persistence
  loginPage: '/login', // The login page url
  loginPath: '/login' // The login form processing url
};

oauth2.oAuth2Provider(
  app, // The app instance
  options // The options
);
```

The app instance will be used to set up middleware and routes. The data source
provides persistence for the oAuth 2.0 metadata models.

For more information, see [OAuth 2.0](http://loopback.io/doc/en/lb2/OAuth-2.0.html) LoopBack component official documentation.

## Example

This [example](https://github.com/strongloop/strong-gateway) demonstrates
how to implement an OAuth service provider, complete with protected API access.
