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

var error = require('./error'),
  AuthCodeGrant = require('./authCodeGrant'),
  Authorise = require('./authorise'),
  Grant = require('./grant'),
  ResourceSetRegistration = require('./resourcesetRegistration'),
  ResourceSetRead = require('./resourcesetRead'),
  ResourceSetUpdate = require('./resourcesetUpdate'),
  ResourceSetDelete = require('./resourcesetDelete'),
  PermissionRegistration = require('./permissionRegistration'),
  PolicyCreation = require('./policyCreation'),
  ResourceSetAuthorise = require('./resourcesetAuthorise'),
  ClaimsCollection = require('./claimsCollection');

module.exports = UMAServer;

/**
 * Constructor
 *
 * @param {Object} config Configuration object
 */
function UMAServer(config) {

  if (!(this instanceof UMAServer)) return new UMAServer(config);

  config = config || {};

  if (!config.model) throw new Error('No model supplied to UMAServer');
  this.model = config.model;

  this.grants = config.grants || [];
  this.debug = config.debug || function () {
    };
  if (typeof this.debug !== 'function') {
    this.debug = console.log;
  }
  this.passthroughErrors = config.passthroughErrors;
  this.continueAfterResponse = config.continueAfterResponse;

  this.accessTokenLifetime = config.accessTokenLifetime !== undefined ?
    config.accessTokenLifetime : 3600;
  this.refreshTokenLifetime = config.refreshTokenLifetime !== undefined ?
    config.refreshTokenLifetime : 1209600;
  this.authCodeLifetime = config.authCodeLifetime || 30;

  this.regex = {
    clientId: config.clientIdRegex || /^[a-z0-9-_]{3,40}$/i,
    grantType: new RegExp('^(' + this.grants.join('|') + ')$', 'i')
  };

  this.restrictedAndReservedScopes = config.restrictedAndReservedScopes;

}

/**
 * Authorisation Middleware
 *
 * Returns middleware that will authorise the request using oauth,
 * if successful it will allow the request to proceed to the next handler
 *
 * @return {Function} middleware
 */
UMAServer.prototype.authorise = function () {
  var self = this;

  return function (req, res, next) {
    return new Authorise(self, req, next);
  };
};

/**
 * Grant Middleware
 *
 * Returns middleware that will grant tokens to valid requests.
 * This would normally be mounted at '/oauth/token' e.g.
 *
 * `app.all('/oauth/token', oauth.grant());`
 *
 * @return {Function} middleware
 */
UMAServer.prototype.grant = function () {
  var self = this;

  return function (req, res, next) {
    new Grant(self, req, res, next);
  };
};

/**
 * Code Auth Grant Middleware
 *
 * @param  {Function} check Function will be called with req to check if the
 *                          user has authorised the request.
 * @return {Function}       middleware
 */
UMAServer.prototype.authCodeGrant = function (check) {
  var self = this;

  return function (req, res, next) {
    new AuthCodeGrant(self, req, res, next, check);
  };
};

/**
 * OAuth Error Middleware
 *
 * Returns middleware that will catch OAuth errors and ensure an OAuth
 * complaint response
 *
 * @return {Function} middleware
 */
UMAServer.prototype.errorHandler = function () {
  var self = this;

  return function (err, req, res, next) {
    if (!(err instanceof error) || self.passthroughErrors) return next(err);

    delete err.name;
    delete err.message;

    self.debug(err.stack || err);
    delete err.stack;

    if (err.headers) res.set(err.headers);
    delete err.headers;

    res.status(err.code).send(err);
  };
};

/**
 * Lockdown
 *
 * When using the lockdown patter, this function should be called after
 * all routes have been declared.
 * It will search through each route and if it has not been explitly bypassed
 * (by passing oauth.bypass) then authorise will be inserted.
 * If oauth.grant has been passed it will replace it with the proper grant
 * middleware
 * NOTE: When using this method, you must PASS the method not CALL the method,
 * e.g.:
 *
 * `
 * app.all('/oauth/token', app.oauth.grant);
 *
 * app.get('/secrets', function (req, res) {
 *   res.send('secrets');
 * });
 *
 * app.get('/public', app.oauth.bypass, function (req, res) {
 *   res.send('publci');
 * });
 *
 * app.oauth.lockdown(app);
 * `
 *
 * @param  {Object} app Express app
 */
UMAServer.prototype.lockdown = function (app) {
  var self = this;

  var lockdownExpress3 = function (stack) {
    // Check if it's a grant route
    var pos = stack.indexOf(self.grant);
    if (pos !== -1) {
      stack[pos] = self.grant();
      return;
    }

    // Check it's not been explitly bypassed
    pos = stack.indexOf(self.bypass);
    if (pos === -1) {
      stack.unshift(self.authorise());
    } else {
      stack.splice(pos, 1);
    }
  };

  var lockdownExpress4 = function (layer) {
    if (!layer.route)
      return;

    var stack = layer.route.stack;
    var handlers = stack.map(function (item) {
      return item.handle;
    });

    // Check if it's a grant route
    var pos = handlers.indexOf(self.grant);
    if (pos !== -1) {
      stack[pos].handle = self.grant();
      return;
    }

    // Check it's not been explitly bypassed
    pos = handlers.indexOf(self.bypass);
    if (pos === -1) {
      // Add authorise another route (could do it properly with express.route?)
      var copy = {};
      var first = stack[0];
      for (var key in first) {
        copy[key] = first[key];
      }
      copy.handle = self.authorise();
      stack.unshift(copy);
    } else {
      stack.splice(pos, 1);
    }
  };

  if (app.routes) {
    for (var method in app.routes) {
      app.routes[method].forEach(function (route) {
        lockdownExpress3(route.callbacks);
      });
    }
  } else {
    app._router.stack.forEach(lockdownExpress4);
  }
};

/**
 * Bypass
 *
 * This is used as placeholder for when using the lockdown pattern
 *
 * @return {Function} noop
 */
UMAServer.prototype.bypass = function () {
};

/**
 * ResourceSet Registration
 *
 * @return {Function}       middleware
 */
UMAServer.prototype.resourceSetRegistration = function () {
  var self = this;

  return function (req, res, next) {
    new ResourceSetRegistration(self, req, res, next);
  };
};

/**
 * ResourceSet Read
 *
 * @return {Function}       middleware
 */
UMAServer.prototype.resourceSetRead = function () {
  var self = this;

  return function (req, res, next) {
    new ResourceSetRead(self, req, res, next);
  };
};

/**
 * ResourceSet Update
 *
 * @return {Function}       middleware
 */
UMAServer.prototype.resourceSetUpdate = function () {
  var self = this;

  return function (req, res, next) {
    new ResourceSetUpdate(self, req, res, next);
  };
};

/**
 * ResourceSet Delete
 *
 * @return {Function}       middleware
 */
UMAServer.prototype.resourceSetDelete = function () {
  var self = this;

  return function (req, res, next) {
    new ResourceSetDelete(self, req, res, next);
  };
};

/**
 * Permission registration
 *
 * @return {Function}       middleware
 */
UMAServer.prototype.permissionRegistration = function () {
  var self = this;

  return function (req, res, next) {
    new PermissionRegistration(self, req, res, next);
  };
};

/**
 * Policy creation
 *
 * @return {Function}       middleware
 */
UMAServer.prototype.policyCreation = function () {
  var self = this;

  return function (req, res, next) {
    new PolicyCreation(self, req, res, next);
  };
};

/**
 * Resource Authorization
 *
 * @return {Function}       middleware
 */
UMAServer.prototype.resourceSetAuthorise = function () {
  var self = this;

  return function (req, res, next) {
    new ResourceSetAuthorise(self, req, res, next);
  };
};

/**
 * Claim Collection
 *
 * @return {Function}       middleware
 */
UMAServer.prototype.claimsCollection = function () {
  var self = this;

  return function (req, res, next) {
    new ClaimsCollection(self, req, res, next);
  };
};
