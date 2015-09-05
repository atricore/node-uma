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

module.exports = PolicyCreation;

/**
 * This is the function order used by the runner
 *
 * @type {Array}
 */
var fns = [
  checkClient,
  getResourceSet,
  extractPolicy,
  checkAuthorized,
  savePolicy,
  sendResponse
];

/**
 * Policy Registration
 *
 * @param {Object}   config Instance of OAuth object
 * @param {Object}   req
 * @param {Object}   res
 * @param {Function} next
 */
function PolicyCreation(config, req, res, next) {
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
 * Fetches the resource set to which the supplied policy will be attached.
 *
 * @param done
 */
function getResourceSet(done) {
  var self = this;
  var resourceSetId = this.req.param('rsid');

  if (!resourceSetId) {
    return done(error('missing_required_fields',
      'Permission request was missing one or more required fields'));
  }

  this.model.getResourceSet(resourceSetId, function (err, rs) {
    if (err) {
      return done(error('invalid_resource_set_requested', 'Invalid Resource Set has been provided'));
    }
    self.req.resourceset = rs;

    done();
  });

}

function Policy(id, name, scopes, claimsRequired) {
  this.id = id;
  this.name = name;
  this.scopes = scopes;
  this.claimsRequired = claimsRequired;
}

function Claim(id, name, friendlyName, claimType, claimTokenFormat, issuer) {
  this.id = id;
  this.name = name;
  this.friendlyName = friendlyName;
  this.claimType = claimType;
  this.claimTokenFormat = claimTokenFormat;
  this.issuer = issuer;
}

/**
 * Extracts the Policy to be attached to the resource set from the request.
 */
function extractPolicy(done) {
  if (!this.req.body.id || !this.req.body.name || !this.req.body.scopes) {
    return done(error('missing_required_fields',
      'Policy creation request was missing one or more required fields'));
  }

  var policy = new Policy(
    this.req.body.id,
    this.req.body.name,
    this.req.body.scopes
  );

  var policyClaimsRequired = [];
  this.req.body.claimsRequired.forEach(function (claimRequired) {
    policyClaimsRequired.push(
      new Claim(
        claimRequired.id,
        claimRequired.name,
        claimRequired.friendlyName,
        claimRequired.claimType,
        claimRequired.claimTokenFormat,
        claimRequired.issuer
      )
    )
  });

  policy.claimsRequired = policyClaimsRequired;

  this.req.policy = policy;

  done();
}

/**
 * Verify that authorized user of the token matches owner of the resource set to which a policy
 * will be attached.
 */
function checkAuthorized(done) {

  if (this.req.resourceset.owner !== this.req.user.id)
    return done(error('not_owner',
      'Unauthorized resource set request from bad user'));
  done();

}

/**
 * Saves the supplied policy.
 *
 * @param done
 */
function savePolicy(done) {
  var self = this;
  var rs = this.req.resourceset;
  var policy = this.req.policy;

  rs.policies.push(policy);

  this.model.updateResourceSet(
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
      self.req.newPolicy = policy;
      done();
    }
  );

}

/**
 * Return created policy.
 *
 * @param  {Function} done
 * @this   UMA
 */
function sendResponse(done) {
  this.res.set({'Cache-Control': 'no-store', 'Pragma': 'no-cache'});
  this.res.status(201)
  this.res.jsonp(this.req.newPolicy);
  if (this.config.continueAfterResponse)
    done();
}
