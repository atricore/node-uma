/**
 * Copyright 2015-present Atricore Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
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

/// OpenID Connect endpoints
app.all('/oidc/authorize', app.uma.authCodeGrant(check));

app.all('/oidc/token', app.uma.grant());

/// OIDC-protected resource
app.get('/secret', app.uma.authorise(), function (req, res) {
  res.send('Secret area');
});

/// UMA endpoints
app.all('/uma/rset/register', app.uma.resourceSetRegistration());

app.all('/uma/rset/read', app.uma.resourceSetRead());

app.all('/uma/rset/update', app.uma.resourceSetUpdate());

app.all('/uma/perm/register', app.uma.permissionRegistration());

app.all('/uma/rset/authorize', app.uma.resourceSetAuthorise());

app.all('/uma/claims/collect', app.uma.claimsCollection());

app.use(app.uma.errorHandler());

app.listen(3000);