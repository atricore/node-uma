# Module for implementing an UMA-compliant (User-Managed Access) Server/Provider with Express in Node.js

This is a fully functional UMA (User-Managed Access) provider/server implementation, with support for the OAuth and
OpenID Connect (OIDC) specifications.
Based on https://github.com/thomseddon/node-oauth2-server.

## Install

Install via npm:

    $ npm install node-uma

You can add it to your Connect or Express application as another middleware.

The module provides middlewares for serving UMA, OAuth2 and OpenID Connect use them as you would any other middleware.

-----

## Quick Start

Within the root folder, run :

    $ node uma

Visit <http://localhost:3000/login> to gain access to
<http://localhost:3000/secret> or use OAuth/OpenID Connect to obtain an access token as a code (default) or a token
(in the URL hash):

  - code: <http://localhost:3000/oidc/authorize?client_id=client&redirect_uri=http://localhost:8080/openid_connect_login>
  - token: <http://localhost:3000/oidc/authorize?client_id=client&redirect_uri=http://localhost:8080/openid_connect_login&response_type=token>

Then consume UMA services (e.g. resource and policy management, etc.) on <http://localhost:3000/uma> . 

## Example

```js
var express = require('express'),
  bodyParser = require('body-parser'),
  umaserver = require('./lib/umaserver'),
  memorystore = require('./models/memory/model.js');

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

Copyright (c) 2015 [Atricore Inc.](http://www.atricore.com)

This project is released under the Apache License. 

## Help!

Any suggestions, bug reports, bug fixes, pull requests, etc, are very welcome ([here](https://github.com/atricore/node-uma/issues)).
