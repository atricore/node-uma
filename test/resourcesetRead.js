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
          token.should.equal('thom');
          var expires = new Date();
          expires.setSeconds(expires.getSeconds() + 20);
          callback(false, {expires: expires});
        },
        getClient: function (clientId, clientSecret, callback) {
          callback(false, {
            clientId: 'thom',
            redirectUri: 'http://nightworld.com'
          });
        },
        saveResourceSet: function (id, name, iconUri, type, scopes, uri, callback) {
          callback(false);
        },

        getResourceSet: function (id, callback) {
          callback(false, {
            id: '12345', name: 'MyPicture', iconUri: '/mypicture.ico', type: 'photograph',
            scopes: 'read_family', uri: '/mypicture.png'
          })
        }

      },
      restrictedAndReservedScopes: ['restricted_scope_1', 'restricted_scope_2']
    };
  }

  var app = express();
  app.uma = umaserver(umaConfig || {model: {}});

  app.use(bodyParser());
  app.all('/*', app.uma.authorise());

  app.get('/:id', app.uma.resourceSetRead());

  app.use(app.uma.errorHandler());

  return app;
};

var validBody = {
  name: 'resourceset_1',
  scopes: 'uma_authorization'
};

describe('ResourceSetRead', function () {

  it('should detect no access token', function (done) {
    var app = bootstrap('mockValid');

    request(app)
      .get('/123456')
      .expect(400, /the access token was not found/i, done);
  });

  it('should allow valid token in header', function (done) {
    var app = bootstrap('mockValid');

    request(app)
      .get('/12345')
      .set('Authorization', 'Bearer thom')
      .set('Content-Type', 'application/x-www-form-urlencoded')
      .send(validBody)
      .expect(200, /id/, done);
  });

  it('should detect invalid resourceset id', function (done) {
    var app = bootstrap({
      model: {
        getAccessToken: function (token, callback) {
          token.should.equal('thom');
          var expires = new Date();
          expires.setSeconds(expires.getSeconds() + 20);
          callback(false, {expires: expires});
        },
        getClient: function (clientId, clientSecret, callback) {
          callback(false, {
            clientId: 'thom',
            redirectUri: 'http://nightworld.com'
          });
        },
        getResourceSet: function (id, callback) {
          callback(true, false);
        }

      }
    });

    request(app)
      .get('/12345')
      .set('Authorization', 'Bearer thom')
      .expect(500, /Invalid Resource Set has been requested/i, done);
  });

  it('should return an UMA compatible response', function (done) {
    var app = bootstrap('mockValid');

    request(app)
      .get('/12345')
      .set('Authorization', 'Bearer thom')
      .set('Content-Type', 'application/x-www-form-urlencoded')
      .send(validBody)
      .expect(200)
      .expect('Cache-Control', 'no-store')
      .expect('Pragma', 'no-cache')
      .end(function (err, res) {
        if (err) return done(err);

        res.body.should.have.keys(['_id', 'name', 'icon_uri', 'type', 'scopes', 'uri']);
        done();
      });

  });

});