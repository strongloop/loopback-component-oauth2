# loopback-component-oauth2

The LoopBack oAuth 2.0 component provides full integration between [OAuth 2.0](http://tools.ietf.org/html/rfc6749)
and [LoopBack](http://loopback.io). It enables LoopBack applications to function
as an oAuth 2.0 provider to authenticate and authorize client applications and/or
resource owners (i.e. users) to access protected API endpoints.

The oAuth 2.0 protocol implementation is based on [oauth2orize](https://github.com/jaredhanson/oauth2orize)
and [passport](http://passportjs.org/). 

## Key building blocks

There are a few key building blocks in loopback-component-oauth2 to provide full
oAuth 2.0 server-side capabilities:

- Authorization server: The server issuing access tokens to the client after 
successfully authenticating the resource owner and obtaining authorization.

- Resource server: The server hosting the protected resources, capable of 
accepting and responding to protected resource requests using access tokens. 

The authorization server may be the same server as the resource server or a 
separate entity. A single authorization server may issue access tokens accepted 
by multiple resource servers.

For authorization servers, loopback-component-oauth2 implements the oAuth 2.0 
protocol endpoints, including [authorization endpoint](http://tools.ietf.org/html/rfc6749#section-3.1) 
and [token endpoint](http://tools.ietf.org/html/rfc6749#section-3.2).

For resource servers, loopback-component-oauth2 provides middleware to protect 
api endpoints. Only those requests with valid oAuth 2.0 access tokens can be 
accepted. It also establishes identities such as client application id and user
id for further access control and personalization.  
  
loopback-component-oauth2 defines the following models to manage oAuth 2.0
metadata such as access tokens, authorization codes, clients (i.e, applications), 
and resource owners (i.e. users).

- OAuthAccessToken (persisting access tokens)
- OAuthAuthorizationCode (persisting authorization codes)

It also uses the user and application model from the loopback module:

- User (managing resource owners)
- Application (managing client applications)

![loopback-oauth2](loopback-oauth2.png)

## Usage

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

### Server types

There are two option properties to indicate if you want to set up the oAuth 2.0
provider as an authorization server, a resource server, or both.

- authorizationServer (boolean)
  - false: Do not set up the authorization server
  - otherwise: Set up the authorization server
  
- resourceServer (boolean)
  - false: Do not set up the resource server
  - otherwise: Set up the resource server

### Authorization server Options

The following options are available for an authorization server:

- authorizePath (string or false)
  - a path to mount the authorization endpoint, default to GET '/oauth/authorize'
  - false: Do not set up the authorization endpoint

- tokenPath (string or false)
  - a path to mount the token endpoint, default to POST '/oauth/token'
  - false: Do not set up the token endpoint

- decisionPath (string or false)
  - a path to mount the decision endpoint, default to POST '/oauth/authorize/decision'
  - false: Do not set up the decision endpoint

- decisionView (string)
  - a server-side view name to render the decision dialog. The input for the 
  view is:
    - transactionId: An internal token to prevent forging
    - user: user/resource owner object
    - client: client application object
    - scope: oAuth 2.0 scope(s)
    - redirectURI: redirect uri after the decision is made
  
- decisionPage (string)
  - a url to the decision dialog page. It will override decisionView. The query
  parameters are:
    - transactionId: An internal token to prevent forging
    - userId: user/resource owner id
    - clientId: client application id
    - scope: oAuth 2.0 scope(s)
    - redirectURI: redirect uri after the decision is made
  
- loginPath (string or false)
  - a path to mount the user login endpoint, default to POST '/login'
  - false: Do not set up the user login endpoint
  
- loginPage (string)
  - a url to the login dialog page, default to '/login'
  

### Supported grant types

The `supportedGrantTypes` option controls what grant types should be enabled:

- supportedGrantTypes (string[])
  - default to ['authorizationCode', 'implicit', 'clientCredentials',
      'resourceOwnerPasswordCredentials', 'refreshToken', 'jwt'];

### Custom functions for token generation

- generateToken: function(options) returns a token string
- getTTL: function(grantType, clientId, resourceOwner, scopes) returns a ttl 
number in seconds

## Protect endpoints with oAuth 2.0

```js
oauth2.authenticate(['/protected', '/api', '/me'], 
  {session: false, scope: 'email'});
```    

## Examples

This [example](https://github.com/strongloop/loopback-gateway) demonstrates
how to implement an OAuth service provider, complete with protected API access.
