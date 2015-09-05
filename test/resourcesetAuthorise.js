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
  should = require('should');

var umaserver = require('../');

var bootstrap = function (umaConfig) {
  if (umaConfig === 'mockValid') {
    umaConfig = {
      model: {
        getAccessToken: function (token, callback) {
          (token === 'thom' || token === '123456789').should.equal(true);
          var expires = new Date();
          expires.setSeconds(expires.getSeconds() + 20);
          callback(false, {user: {id: '123'}, expires: expires});
        },
        getRequestingPartyToken: function (rpt, callback) {
          (rpt === 'ABCDEF').should.equal(true);
          var expires = new Date();
          expires.setSeconds(expires.getSeconds() + 20);
          callback(false, {user: {id: '123'}, expires: expires});
        },
        saveRequestingPartyToken: function (token, clientId, expires, user, cb) {
          cb();
        },
        getClient: function (clientId, clientSecret, callback) {
          callback(false, {
            clientId: 'thom',
            redirectUri: 'http://nightworld.com'
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
        getResourceSet: function (id, callback) {
          callback(false, {
            id: 'picture_1', name: 'MyPicture', iconUri: '/mypicture.ico', type: 'photograph',
            scopes: 'read_family', uri: '/mypicture.png', owner: '123',
            policies: [
              {
                id: 'policy_1',
                name: 'Policy One',
                scopes: ['read', 'write'],
                claimsRequired: [
                  {
                    id: '100',
                    name: 'Read Permission',
                    value: 'read-permission',
                    friendlyName: 'Read Permission',
                    claimType: 'ClaimType1',
                    claimTokenFormat: 'ClaimTokenFormat1',
                    issuer: ['thom']
                  },
                  {
                    id: '101',
                    name: 'Write Permission',
                    value: 'write-permission',
                    friendlyName: 'Write Permission',
                    claimType: 'ClaimType1',
                    claimTokenFormat: 'ClaimTokenFormat1',
                    issuer: ['thom']
                  }
                ]
              }
            ]
          })
        },
        updateResourceSet: function (id, name, iconUri, type, scopes, uri, owner, policies, callback) {
          callback(false);
        },
        savePermissionTicket: function (ticket, callback) {
          callback(false);
        }
      },
      restrictedAndReservedScopes: ['restricted_scope_1', 'restricted_scope_2'],
      requestingPartyTokenLifetime: 60
    };
  }

  var app = express();
  app.uma = umaserver(umaConfig || {model: {}});

  app.use(bodyParser());
  app.all('/*', app.uma.authorise());

  app.all('/', app.uma.resourceSetAuthorise());

  app.use(app.uma.errorHandler());

  return app;
};

var validBodyWithRpt = {
  rpt: 'ABCDEF',
  ticket: 'A0B1C2'
};

var validBodyWithNoRpt = {
  ticket: 'A0B1C2'
};

describe('ResourceSetAuthorise', function () {
  it('should detect no access token', function (done) {
    var app = bootstrap('mockValid');

    request(app)
      .post('/')
      .expect(400, /the access token was not found/i, done);
  });

  it('should allow valid token in header', function (done) {
    var app = bootstrap('mockValid');

    request(app)
      .post('/')
      .set('Authorization', 'Bearer thom')
      .set('Content-Type', 'application/x-www-form-urlencoded')
      .send(validBodyWithRpt)
      .expect(200, done)
  });

  it('should detect missing required fields', function (done) {
    var app = bootstrap('mockValid');

    request(app)
      .post('/')
      .set('Authorization', 'Bearer thom')
      .set('Content-Type', 'application/x-www-form-urlencoded')
      .expect(500, /Authorization request was missing one or more required fields/i, done);
  });

  it('should return success along an rpt when claims are satisfied', function (done) {
    var app = bootstrap('mockValid');

    request(app)
      .post('/')
      .set('Authorization', 'Bearer thom')
      .set('Content-Type', 'application/x-www-form-urlencoded')
      .send(validBodyWithNoRpt)
      .expect(200)
      .expect('Cache-Control', 'no-store')
      .expect('Pragma', 'no-cache')
      .end(function (err, res) {
        if (err) return done(err);

        res.body.should.have.keys(['rpt']);
        res.body.rpt.should.be.instanceOf(String);
        res.body.rpt.should.have.length(40);
        done();
      });
  });

  it('should return error when claims are not satisfied', function (done) {
    var app = bootstrap('mockValid');

    app.uma.model.getPermissionTicket = function (ticket, callback) {
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
            }
          ]
        }
      });
    };

    request(app)
      .post('/')
      .set('Authorization', 'Bearer thom')
      .set('Content-Type', 'application/x-www-form-urlencoded')
      .send(validBodyWithNoRpt)
      .expect(403)
      .expect('Cache-Control', 'no-store')
      .expect('Pragma', 'no-cache')
      .end(function (err, res) {
        if (err) return done(err);

        res.body.should.have.keys(['error', 'error_details']);
        res.body.error_details.requesting_party_claims.required_claims.should.have.length(1);
        res.body.error_details.requesting_party_claims.required_claims[0].should.have.keys(['name',
          'friendly_name', 'claim_type', 'claim_token_format', 'issuer']);
        done();
      });
  });


});