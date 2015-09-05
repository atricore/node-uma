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

var error = require('./error'),
  runner = require('./runner'),
  uuid = require('node-uuid');

module.exports = PermissionRegistration;

/**
 * This is the function order used by the runner
 *
 * @type {Array}
 */
var fns = [
  checkClient,
  getResourceSet,
  checkScopesAllowed,
  checkAuthorized,
  savePermissionTicket,
  sendResponse
];

/**
 * ResourceSet Registration
 *
 * @param {Object}   config Instance of OAuth object
 * @param {Object}   req
 * @param {Object}   res
 * @param {Function} next
 */
function PermissionRegistration(config, req, res, next) {
  this.config = config;
  this.model = config.model;
  this.now = new Date();
  this.req = req;
  this.res = res;


  runner(fns, this, next);
}


/**
 * Check extracted client against model
 *
 * @param  {Function} done
 * @this   OAuth
 */
function checkClient(done) {
  var self = this;

  this.model.getClient(this.req.oauth.bearerToken.client, null,
    function (err, client) {
      if (err) return done(error('server_error', false, err));

      if (!client) {
        return done(error('invalid_client', 'Client credentials are invalid'));
      }

      // Expose validated client
      self.req.oauth.client = client;

      done();
    });
}


/**
 * Fetches the resource set to be updated
 *
 * @param done
 */
function getResourceSet(done) {
  var self = this;
  var resourceSetId = this.req.body.resource_set_id;
  var scopes = this.req.body.scopes;

  if (!resourceSetId || !scopes) {
    return done(error('missing_required_fields',
      'Permission request was missing one or more required fields'));
  }

  this.model.getResourceSet(resourceSetId, function (err, rs) {
    if (err) {
      return done(error('invalid_resource_set_requested', 'Invalid Resource Set has been requested'));
    }
    self.req.resourceset = rs;

    done();
  });

}

/**
 *
 * Make sure the requested scopes for the permission ticket don't have any restricted or reserved scopes.
 *
 */
function checkScopesAllowed(done) {
  var self = this;
  // scopes that the client is asking for
  var requestedScopes = this.req.body.scopes.split(' ');
  var allowedScopes = [];

  // the scopes that the resource set can have must be a subset of the dynamically allowed scopes
  requestedScopes.forEach(function (requestedScope) {
    if (self.config.restrictedAndReservedScopes.indexOf(requestedScope) == -1) {
      allowedScopes.push(requestedScope);
    } else {
    }
  });

  if (allowedScopes.length == 0) {
    return done(error('invalid_scope',
      'Requested scope for permission is not allowed'));
  }

  done();

}

/**
 * Verify that authorized user of the token matches owner of the resource set
 */
function checkAuthorized(done) {

  if (this.req.resourceset.owner !== this.req.user.id)
    return done(error('not_owner',
      'Party requesting permission is not owner of resource set, expected'));

  done();

}


/**
 * Creates a permission ticket.
 */
function createPermission(resourceSet, scopes) {
  var permissionTicket = {};

  permissionTicket.permission = {resourceSet: resourceSet, scopes: scopes};
  permissionTicket.uid = uuid['v4']();
  permissionTicket.expiration = Date.now + (60 * 1000);

  return permissionTicket;
}

/**
 * Saves the supplied permission ticket.
 *
 * @param done
 */
function savePermissionTicket(done) {
  var self = this;
  var rs = this.req.resourceset;
  var permissionTicket = createPermission(rs.id, this.req.body.scopes);

  this.model.savePermissionTicket(permissionTicket,
    function (err) {
      if (err) return done(error('server_error', false, err));
      self.req.permissionTicket = permissionTicket;
      done();
    }
  );

}

/**
 * Return created permission ticket.
 *
 * @param  {Function} done
 * @this   UMA
 */
function sendResponse(done) {
  var response = {};

  response.ticket = this.req.permissionTicket.uid;
  this.res.set({'Cache-Control': 'no-store', 'Pragma': 'no-cache'});
  this.res.status(201)
  this.res.jsonp(response);
  if (this.config.continueAfterResponse)
    done();
}
