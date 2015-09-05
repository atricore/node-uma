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
  token = require('./token'),
  jwt = require('jwt-simple');

module.exports = ClaimsCollection;

/**
 * This is the function order used by the runner
 *
 * @type {Array}
 */
var fns = [
  checkClient,
  getTicket,
  getUserDetails,
  attachUserClaims,
  updatePermissionTicket,
  redirect
];

/**
 * Claims Collection
 *
 * @param {Object}   config Instance of OAuth object
 * @param {Object}   req
 * @param {Object}   res
 * @param {Function} next
 */
function ClaimsCollection(config, req, res, next) {
  this.config = config;
  this.model = config.model;
  this.now = new Date();
  this.req = req;
  this.res = res;

  runner(fns, this, next);
}


/**
 * Check extracted client against model.
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
 * Fetches the ticket containing the requested permissions.
 *
 * @param done
 */
function getTicket(done) {
  var self = this;
  var ticket = this.req.param('ticket');

  if (!ticket) {
    return done(error('missing_required_fields',
      'Claims collection request was missing one or more required fields'));
  }

  this.model.getPermissionTicket(ticket, function (err, ticket) {
    if (err) {
      return done(error('invalid_resource_set_requested', 'Invalid Resource Set has been provided'));
    }
    self.req.ticket = ticket;

    done();
  });
}

/**
 * Obtain and expose user details for the supplied token.
 */
function getUserDetails(done) {
  var self = this;

  this.model.loadUserDetails(this.req.user.id, function (err, userDetails) {
    if (err) {
      return done(error('user_does_not_exist', 'User ' + this.req.user.id + ' not found'));
    } else {
      self.req.userDetails = userDetails;
    }
  });

  done();

}


/**
 * Augment claims of the supplied permission ticket with additional claims.
 */
function attachUserClaims(done) {

  for (var userAttribute in this.req.userDetails) {
    if (this.req.userDetails.hasOwnProperty(userAttribute)) {
      var userClaim = {};
      var idToken = jwt.decode(this.req.oauth.bearerToken.idToken, this.req.oauth.client.clientSecret);

      userClaim.issuer = idToken.iss;
      userClaim.name = userAttribute.name;
      userClaim.value = userAttribute.value;

      this.req.ticket.permission.claimsSupplied.push(userClaim);
    }
  }

  done();

}

/**
 * Saves permission ticket containing new claims.
 */
function updatePermissionTicket(done) {
  this.model.updatePermissionTicket(this.req.ticket,
    function (err) {
      if (err) return done(error('server_error', false, err));
      done();
    }
  );
}

/**
 * Notify claim collection completion to client.
 *
 * @param  {Function} done
 * @this   OAuth
 */
function redirect(done) {
  var redirectUri;

  if (!this.req.query.redirect_uri && this.req.oauth.client.claimsRedirectUri)
    redirectUri = this.req.oauth.client.claimsRedirectUri;
  else
    redirectUri = this.req.query.redirect_uri;

  this.res.redirect(redirectUri + '?authorization_state=claims_submitted' +
    (this.req.query.state ? '&state=' + this.req.query.state : ''));

  if (this.config.continueAfterResponse)
    return done();
}

