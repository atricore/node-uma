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
  request = require('supertest'),
  should = require('should'),
  jwt = require('jwt-simple');

var umaserver = require('../');

var bootstrap = function (umaConfig) {
  if (umaConfig === 'mockValid') {
    umaConfig = {
      model: {
        getAccessToken: function (token, callback) {
          (token === 'thom' || token === '123456789').should.equal(true);
          var expires = new Date();
          expires.setSeconds(expires.getSeconds() + 20);

          var d = Math.round(new Date().getTime() / 1000);

          var idToken = jwt.encode(
            {
              iss: 'https://idp1.secure.com',
              sub: 'jdoe',
              aud: 'thom',
              exp: d + 3600,
              iat: d,
              nonce: 'nonce123'
            },
            'secret'
          );

          callback(false, {user: {id: '123'}, expires: expires, idToken: idToken});
        },
        getClient: function (clientId, clientSecret, callback) {
          callback(false, {
            clientId: 'thom',
            clientSecret: 'secret',
            redirectUri: 'http://nightworld.com',
            claimsRedirectUri: 'http://nightworld.com/claims'
          });
        },
        getPermissionTicket: function (ticket, callback) {
          callback(false, {
            uid: ticket,
            expiration: Date.now + (60 * 1000),
            permission: {
              resourceSet: 'picture_1', scopes: ['read', 'write'],
              claimsSupplied: [
                {
                  name: 'Read Permission',
                  value: 'read-permission',
                  issuer: ['thom', 'john']
                },
                {
                  name: 'Write Permission',
                  value: 'write-permission',
                  issuer: ['thom', 'john']
                }
              ]
            }
          });
        },
        updatePermissionTicket: function (ticket, callback) {
          callback(false);
        },
        loadUserDetails: function (userId, callback) {
          callback(false, [
            {
              issuer: 'idp1',
              name: 'sub',
              value: 'jdoe'
            },
            {
              issuer: 'idp1',
              name: 'email',
              value: 'jdoe@acme.com'
            },
            {
              issuer: 'idp1',
              name: 'email_verified',
              value: true
            },
            {
              issuer: 'idp1',
              name: 'phone_number',
              value: '444-222-5555'
            },
            {
              issuer: 'idp1',
              name: 'phone_number_verified',
              value: true
            },
            {
              issuer: 'idp1',
              name: 'preferred_username',
              value: 'email'
            },
            {
              issuer: 'idp1',
              name: 'profile',
              value: 'I\'m John Doe'
            }
          ])
        }
      }
    };
  }

  var app = express();
  app.uma = umaserver(umaConfig || {model: {}});

  app.use(bodyParser());
  app.all('/*', app.uma.authorise());

  app.all('/', app.uma.claimsCollection());

  app.use(app.uma.errorHandler());

  return app;
};

describe('ClaimsCollection', function () {
  it('should detect no access token', function (done) {
    var app = bootstrap('mockValid');

    request(app)
      .get('/')
      .expect(400, /the access token was not found/i, done);
  });

  it('should allow valid token in header', function (done) {
    var app = bootstrap('mockValid');

    request(app)
      .get('/?ticket=123456&state=ABCDEF')
      .set('Authorization', 'Bearer thom')
      .set('Content-Type', 'application/x-www-form-urlencoded')
      .expect(302, done)
  });

  it('should detect missing required fields', function (done) {
    var app = bootstrap('mockValid');

    request(app)
      .get('/?state=ABCDEF')
      .set('Authorization', 'Bearer thom')
      .set('Content-Type', 'application/x-www-form-urlencoded')
      .expect(500, /Claims collection request was missing one or more required fields/i, done);
  });

  it('should update ticket with the collected claims', function (done) {
    var app = bootstrap('mockValid');

    app.uma.model.updatePermissionTicket = function (ticket, callback) {
      ticketClaims = ticket.permission.claimsSupplied.length;
      callback(false);
    };

    request(app)
      .get('/?ticket=123456&state=ABCDEF')
      .set('Authorization', 'Bearer thom')
      .set('Content-Type', 'application/x-www-form-urlencoded')
      .expect(302)
      .end(function (err, res) {
        if (err) return done(err);
        ticketClaims.should.equal(9);
        done();
      });

  });

  it('should update ticket with the collected claims', function (done) {
    var app = bootstrap('mockValid');

    app.uma.model.updatePermissionTicket = function (ticket, callback) {
      ticketClaims = ticket.permission.claimsSupplied.length;
      callback(false);
    };

    request(app)
      .get('/?ticket=123456&state=ABCDEF')
      .set('Authorization', 'Bearer thom')
      .set('Content-Type', 'application/x-www-form-urlencoded')
      .expect(302)
      .end(function (err, res) {
        if (err) return done(err);
        ticketClaims.should.equal(9);
        done();
      });
  });

  it('should redirect to the claims redirect URI configured for the client when none is supplied', function (done) {
    var app = bootstrap('mockValid');

    request(app)
      .get('/?ticket=123456&state=ABCDEF')
      .set('Authorization', 'Bearer thom')
      .set('Content-Type', 'application/x-www-form-urlencoded')
      .expect(302, /Redirecting to http:\/\/nightworld.com\/claims\?authorization_state=claims_submitted\&state=ABCDEF/i, done);
  });

  it('should redirect to the supplied redirect URI when non is configured for the client', function (done) {
    var app = bootstrap('mockValid');

    app.uma.model.getClient = function (clientId, clientSecret, callback) {
      callback(false, {
        clientId: 'thom',
        clientSecret: 'secret',
        redirectUri: 'http://nightworld.com',
      });
    };

    request(app)
      .get('/?ticket=123456&state=ABCDEF&redirect_uri=http://nightworld.com/other/claims')
      .set('Authorization', 'Bearer thom')
      .set('Content-Type', 'application/x-www-form-urlencoded')
      .expect(302, /Redirecting to http:\/\/nightworld.com\/other\/claims\?authorization_state=claims_submitted\&state=ABCDEF/i, done);
  });

});