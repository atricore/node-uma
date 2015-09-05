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

/*
 * Required
 */

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

/*
 * Required to support password grant type
 */
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








