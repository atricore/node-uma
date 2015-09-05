/**
 * Copyright 2013-present NightWorld.
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

var auth = require('basic-auth'),
  error = require('./error'),
  runner = require('./runner');

module.exports = Login;

/**
 * This is the function order used by the runner
 *
 * @type {Array}
 */
var fns = [
  login,
  sendResponse
];

/**
 * Login
 *
 * @param {Object}   config Instance of OAuth object
 * @param {Object}   req
 * @param {Object}   res
 * @param {Function} next
 */
function Login(config, req, res, next) {
  this.config = config;
  this.model = config.model;
  this.now = new Date();
  this.req = req;
  this.res = res;

  runner(fns, this, next);
}

/**
 * login
 *
 * returns a function to be placed as middleware in connect/express routing methods. For example:
 *
 * app.post('/login', oidc.login(),  afterLogin, loginErrorHandler);
 *
 * This calls verification strategy and creates session.
 * Verification strategy must have two parameters: req and callback function with two parameters: error and user
 *
 *
 */
function login(done) {

  if (!error && !user) {
    error = new Error('User not validated');
  }
  if (!error) {
    if (user.id) {
      req.session.user = user.id;
    } else {
      delete req.session.user;
    }
    if (user.sub) {
      if (typeof user.sub === 'function') {
        req.session.sub = user.sub();
      } else {
        req.session.sub = user.sub;
      }
    } else {
      delete req.session.sub;
    }
    return next();
  } else {
    return next(error);
  }
}


/**
 * Create an access token and save it with the model
 *
 * @param  {Function} done
 * @this   OAuth
 */
function sendResponse(done) {
  var response = {
    token_type: 'bearer',
    access_token: this.accessToken
  };


  if (this.config.accessTokenLifetime !== null) {
    response.expires_in = this.config.accessTokenLifetime;
  }

  if (this.refreshToken) response.refresh_token = this.refreshToken;

  this.res.set({'Cache-Control': 'no-store', 'Pragma': 'no-cache'});
  this.res.jsonp(response);

  if (this.config.continueAfterResponse)
    done();
}
