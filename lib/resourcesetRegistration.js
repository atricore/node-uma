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
  runner = require('./runner');

module.exports = ResourceSetRegistration;

/**
 * This is the function order used by the runner
 *
 * @type {Array}
 */
var fns = [
  checkClient,
  extractResourceSet,
  checkScopesAllowed,
  saveResourceSet,
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
function ResourceSetRegistration(config, req, res, next) {
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
 * ResourceSet Object (internal use only)
 *
 * @param {String} id       resourceset identifier
 * @param {String} name     resourceset name
 * @param {String} iconUri  resourceset ucon uri
 * @param {String} type     resourceset type
 * @param {String} scopes   resourceset scopes
 * @param {String} uri      resourceset URI
 */
function ResourceSet(id, name, iconUri, type, scopes, uri, owner, policies) {
  this.id = id;
  this.name = name;
  this.iconUri = iconUri;
  this.type = type;
  this.scopes = scopes;
  this.uri = uri;
  this.owner = owner;
  this.policies = policies;
}

/**
 * Register Resourceset
 *
 * @param  {Function} done
 * @this   OAuth
 */
function extractResourceSet(done) {
  var id = Date.now();

  if (!this.req.body.name || !this.req.body.scopes) {
    return done(error('missing_required_fields',
      'Resource request was missing one or more required fields'));
  }

  var rs = new ResourceSet(
    id,
    this.req.body.name,
    this.req.body.iconUri,
    this.req.body.type,
    this.req.body.scopes,
    this.req.body.uri,
    this.req.user,
    []
  );

  this.req.resourceset = rs;

  done();
}

/**
 *
 * Make sure the resource set doesn't have any restricted or reserved scopes.
 *
 */
function checkScopesAllowed(done) {
  var self = this;
  // scopes that the client is asking for
  var requestedScopes = this.req.resourceset.scopes.split(' ');
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
      'Requested scope for resourceset is not allowed'));
  }

  done();

}


/**
 * Saves the supplied resource set
 *
 * @param done
 */
function saveResourceSet(done) {

  var rs = this.req.resourceset;

  this.model.saveResourceSet(
    rs.id,
    rs.name,
    rs.iconUri,
    rs.type,
    rs.scopes,
    rs.uri,
    rs.owner,
    rs.policies,
    function (err) {
      if (err) return done(error('server_error', false, err));
      done;
    }
  );

  done();

}

/**
 * Return created resource set.
 *
 * @param  {Function} done
 * @this   OAuth
 */
function sendResponse(done) {
  var response = {};

  response._id = this.req.resourceset.id;
  response.user_access_policy_uri = this.req.oauth.client.clientId + "/manage/user/policy/" + this.req.resourceset.id;

  this.res.set({'Cache-Control': 'no-store', 'Pragma': 'no-cache'});
  this.res.set({location: this.req.oauth.client.clientId + '/resource_set/' + this.req.resourceset.id});
  this.res.status(201)
  this.res.jsonp(response);
  if (this.config.continueAfterResponse)
    done();
}
