# Module for implementing an UMA-compliant (User-Managed Access) Server/Provider with Express in Node.js

This is a fully functional UMA (User-Managed Access) provider/server implementation, with support for the OAuth and
OpenID Connect (OIDC) specifications.
Based on https://github.com/thomseddon/node-oauth2-server.

## Install

Install via npm:

    $ npm install node-uma

You can add it to your Connect or Express application as another middleware.

-----

## Quick Start

The module provides middlewares for serving UMA, OAuth2 and OpenID Connect use them as you would any other middleware :

### Create project descriptor  

Create the following "package.json" file.

```json
{
  "name": "my-uma-example",
  "description": "My UMA Example",
  "version": "0.0.1",
  "main": "uma.js",
  "dependencies": {
    "express": "~4.4.3",
    "body-parser": "~1.3.1"
  },
  "engines": {
    "node": ">=0.8"
  }
}
```

Then fetch dependencies by running the following command :

    $ npm install 
    
### Define a model

The UMA server requires both pulling and storing information, such as fetching user credentials or saving OAuth tokens. In order to do so, a specific object has to be exposed to the server. 
The example below defines a volatile model based on memory storage. 

```js
var model = module.exports;

// In-memory datastores:
var oauthAccessTokens = [],
  oauthRefreshTokens = [],
  oauthCodes = [],
  oauthClients = [
    {
      clientId: 'client',
      clientSecret: 'secret',
      redirectUri: 'http://localhost:8080/openid_connect_login',
      claimsRedirectUri: 'http://localhost:8080/claims'
    }
  ],
  authorizedClientIds = {
    password: [
      'client'
    ],
    refresh_token: [
      'client'
    ],
    authorization_code: [
      'client'
    ]
  },
  users = [
    {
      id: '123',
      username: 'admin',
      password: 'password',
    }
  ],
  userDetails = [
    {
      id: '123',
      sub: 'jdoe',
      email: 'jdoe@acme.com',
      email_verified: true,
      phone_number: '444-222-5555',
      preferred_username: 'email',
      profile: 'I\'m John Doe'
    }
  ]
resourceSets = [],
  permissionTickets = [],
  requestingPartyTokens = [];


// Debug function to dump the state of the data stores
model.dump = function () {
  console.log('oauthAccessTokens', oauthAccessTokens);
  console.log('oauthClients', oauthClients);
  console.log('authorizedClientIds', authorizedClientIds);
  console.log('oauthRefreshTokens', oauthRefreshTokens);
  console.log('oauthCodes', oauthCodes);
  console.log('users', users);
  console.log('userDetails', userDetails);
  console.log('resourceSets', resourceSets);
  console.log('permissionTickets', permissionTickets);
  console.log('requestingPartyTokens', requestingPartyTokens);
};

model.getAccessToken = function (bearerToken, callback) {
  for (var i = 0, len = oauthAccessTokens.length; i < len; i++) {
    var elem = oauthAccessTokens[i];
    if (elem.accessToken === bearerToken) {
      return callback(false, elem);
    }
  }
  callback(false, false);
};

model.getRefreshToken = function (bearerToken, callback) {
  for (var i = 0, len = oauthRefreshTokens.length; i < len; i++) {
    var elem = oauthRefreshTokens[i];
    if (elem.refreshToken === bearerToken) {
      return callback(false, elem);
    }
  }
  callback(false, false);
};

model.getClient = function (clientId, clientSecret, callback) {
  for (var i = 0, len = oauthClients.length; i < len; i++) {
    var elem = oauthClients[i];
    if (elem.clientId === clientId &&
      (clientSecret === null || elem.clientSecret === clientSecret)) {
      return callback(false, elem);
    }
  }
  callback(false, false);
};

model.grantTypeAllowed = function (clientId, grantType, callback) {
  callback(false, authorizedClientIds[grantType] &&
    authorizedClientIds[grantType].indexOf(clientId.toLowerCase()) >= 0);
};

model.saveAccessTokenWithIDToken = function (accessToken, clientId, expires, userId, type, idToken, scope, auth, nonce, callback) {
  oauthAccessTokens.unshift({
    accessToken: accessToken,
    clientId: clientId,
    userId: userId,
    expires: expires,
    type: type,
    idToken: idToken,
    scope: scope,
    auth: auth,
    nonce: nonce
  });
  callback(false);
};

model.saveAccessToken = function (accessToken, clientId, expires, userId, type, callback) {
  oauthAccessTokens.unshift({
    accessToken: accessToken,
    clientId: clientId,
    userId: userId,
    expires: expires,
    type: type,
  });
  callback(false);
};


model.saveRefreshToken = function (refreshToken, clientId, expires, userId, callback) {
  oauthRefreshTokens.unshift({
    refreshToken: refreshToken,
    clientId: clientId,
    userId: userId,
    expires: expires
  });

  callback(false);
};

model.getUser = function (username, password, callback) {
  for (var i = 0, len = users.length; i < len; i++) {
    var elem = users[i];
    if (elem.username === username && elem.password === password) {
      return callback(false, elem);
    }
  }
  callback(false, false);
};

model.getAuthCode = function (bearerCode, callback) {
  console.log("in getAuthCode (bearerCode: " + bearerCode + ")");

  for (var i = 0, len = oauthCodes.length; i < len; i++) {
    var elem = oauthCodes[i];
    if (elem.code === bearerCode) {
      if (elem.expires) {
        elem.expires = new Date(elem.expires * 1000);
      }
      return callback(false, elem);
    }
  }
  callback(false, false);

};

model.saveAuthCode = function (authCode, clientId, expires, user, scope, sub, redirectUri, responseType, status, nonce, callback) {
  console.log('in saveAuthCode (clientId : ' + clientId + ', scope: ' + scope + ', user: ' + user + ', sub: ' +
    sub + ', authCode: ' + authCode + ', redirectUri: ' + redirectUri + ', responseType: ' + responseType + ', status: ' +
    status + ', expires: ' + expires + ', nonce: ' + nonce + ')');

  var code = {
    clientId: clientId,
    scope: scope,
    user: user,
    sub: sub,
    code: authCode,
    redirectUri: redirectUri,
    responseType: responseType,
    status: status,
    expires: expires,
    nonce: nonce
  };

  if (expires) code.expires = parseInt(expires / 1000, 10);
  console.log("saving", code);

  oauthCodes.unshift(code);

  callback(false, code);

};

model.saveResourceSet = function (id, name, iconUri, type, scopes, uri, owner, policies, callback) {

  resourceSets.unshift({
    id: id,
    name: name,
    iconUri: iconUri,
    type: type,
    scopes: scopes,
    uri: uri,
    owner: owner,
    policies: policies
  });

  callback(false);
};

model.getResourceSet = function (id, callback) {
  for (var i = 0, len = resourceSets.length; i < len; i++) {
    var elem = resourceSets[i];
    if (elem.id === beid) {
      return callback(false, elem);
    }
  }
  callback(true, false);
};

model.updateResourceSet = function (id, name, iconUri, type, scopes, uri, owner, policies, callback) {
  for (var i = 0, len = resourceSets.length; i < len; i++) {
    var elem = resourceSets[i];
    if (elem.id === id) {
      elem.name = name;
      elem.iconUri = iconUri;
      elem.type = type;
      elem.scopes = scopes;
      elem.uri = uri;
      elem.owner = owner;
      elem.policies = policies;
      return callback(false, elem);
    }
  }

  callback(true, false);
};

model.deleteResourceSet = function (id, callback) {
  var i = resourceSets.length;
  while (i--) {
    if (resourceSets[i].id == id)
      resourceSets.splice(i, 1);
    return callback(false);
  }

  callback(true);
};

model.savePermissionTicket = function (ticket, callback) {
  permissionTickets.unshift(ticket);
  callback(false);
};

model.getPermissionTicket = function (ticket, callback) {
  for (var i = 0, len = permissionTickets.length; i < len; i++) {
    var elem = permissionTickets[i];
    if (elem.ticket === ticket) {
      return callback(false, elem);
    }
  }

  callback(true, false);
};

model.updatePermissionTicket = function (ticket, callback) {
  for (var i = 0, len = permissionTickets.length; i < len; i++) {
    var elem = permissionTickets[i];
    if (elem.uid === ticket.uid) {
      elem.permission = ticket.permission;
      elem.expiration = ticket.expiration;
      return callback(false, elem);
    }
  }
};

model.saveRequestingPartyToken = function (token, clientId, expires, user, callback) {
  requestingPartyTokens.unshift({
    token: token,
    clientId: clientId,
    expires: expires,
    user: user
  });

  callback(false);
};

model.getRequestingPartyToken = function (rpt, callback) {
  for (var i = 0, len = requestingPartyTokens.length; i < len; i++) {
    var elem = requestingPartyTokens[i];
    if (elem.token === rpt) {
      return callback(false, elem);
    }
  }
  callback(true, false);
};

model.loadUserDetails = function (username, callback) {

  for (var i = 0, len = userDetails.length; i < len; i++) {
    var elem = userDetails[i];
    if (elem.username === username) {
      return callback(false, elem);
    }
  }
  callback(true, false);
};
```

### Create an Example Server

The following is an example UMA server which is importing the previously defined model assuming that it has been saved in a file named "memory-model.js".

```js
var express = require('express'),
  bodyParser = require('body-parser'),
  umaserver = require('node-uma'),
  memorystore = require('./memory-model.js');

var app = express();

app.uma = umaserver({
  model: memorystore,
  grants: ['authorization_code', 'password', 'refresh_token'],
  debug: true,
  continueAfterResponse: false,
  restrictedAndReservedScopes: ['restricted_scope_1', 'restricted_scope_2']
});

function check(req, callback) {
  callback(false, true, {id: '123', username: 'admin', password: 'password'});
}

app.use(bodyParser.urlencoded({extended: true}));

app.use(bodyParser.json());

app.all('/oidc/authorize', app.uma.authCodeGrant(check));

app.all('/oidc/token', app.uma.grant());

app.get('/', app.uma.authorise(), function (req, res) {
  res.send('Secret area');
});

app.all('/uma/rset/register', app.uma.resourceSetRegistration());

app.all('/uma/rset/read', app.uma.resourceSetRead());

app.all('/uma/rset/update', app.uma.resourceSetUpdate());

app.all('/uma/perm/register', app.uma.permissionRegistration());

app.all('/uma/rset/authorize', app.uma.resourceSetAuthorise());

app.all('/uma/claims/collect', app.uma.claimsCollection());

app.use(app.uma.errorHandler());

app.listen(3000);
```

### Run Example Server

Run with NodeJS. For instance, if the example script has been stored in the "uma.js" file, run :

    $ node uma

Visit <http://localhost:3000/login> to gain access to
<http://localhost:3000/secret> or use OAuth/OpenID Connect to obtain an access token as a code (default) or a token
(in the URL hash):

  - code: <http://localhost:3000/oidc/authorize?client_id=client&redirect_uri=http://localhost:8080/openid_connect_login>
  - token: <http://localhost:3000/oidc/authorize?client_id=client&redirect_uri=http://localhost:8080/openid_connect_login&response_type=token>

Then consume UMA services (e.g. resource and policy management, etc.) on <http://localhost:3000/uma> . 

## Running tests

  Install dev dependencies:

    $ npm install -d

  Run the tests:

    $ node_modules/.bin/mocha

## Features

- Implements an UMA (User-Managed Access) provider: resource sets, policies, permissions and authorization.
- Implements an OAuth2 provider: authorization_code, password, refresh_token, client_credentials and extension
(custom) grant types.
- Supports OpenID Connect: Builds on OAuth2 for delivering browser-based single sign-on through ID tokens.
- Full test suite

## Copyright

Copyright (c) 2015-2017 [Atricore Inc.](http://www.atricore.com)

This project is released under the Apache License. 

## Help!

Any suggestions, bug reports, bug fixes, pull requests, etc, are very welcome ([here](https://github.com/atricore/node-uma/issues)).
