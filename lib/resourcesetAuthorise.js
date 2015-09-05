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
  token = require('./token');


module.exports = ResourceSetAuthorise;

/**
 * This is the function order used by the runner
 *
 * @type {Array}
 */
var fns = [
  checkClient,
  checkRpt,
  getTicket,
  authorize,
  generateRequestingPartyToken,
  saveRequestingPartyToken,
  sendResponse
];

/**
 * Resource set Authorization
 *
 * @param {Object}   config Instance of OAuth object
 * @param {Object}   req
 * @param {Object}   res
 * @param {Function} next
 */
function ResourceSetAuthorise(config, req, res, next) {
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
 * Check RPT in case it has been provided.
 *
 * Check it against model, ensure it's not expired
 * @param  {Function} done
 * @this   OAuth
 */
function checkRpt(done) {
  var self = this;
  var incomingRpt = this.req.body.rpt;

  if (incomingRpt) {
    this.model.getRequestingPartyToken(incomingRpt, function (err, token) {
      if (err) return done(error('server_error', false, err));

      if (!token) {
        return done(error('invalid_rpt_token',
          'The RPT provided is invalid.'));
      }

      if (token.expires !== null &&
        (!token.expires || token.expires < new Date())) {
        return done(error('invalid_token',
          'The RPT provided has expired.'));
      }

      // Expose params
      self.req.rpt = {
        token: token,
        user: token.user ? token.user : {id: token.userId}
      }

    });
  }

  done();
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
      'Authorization request was missing one or more required fields'));
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
 * Extracts the resource for which authorization is required.
 */
function authorize(done) {
  var self = this;
  var rsId = this.req.ticket.permission.resourceSet;
  var rs;

  this.model.getResourceSet(rsId, function (err, rs) {
    if (err) {
      return done(error('invalid_resource_set_requested', 'Invalid Resource Set has been provided'));
    }
    self.rs = rs;
  });

  if (!this.rs.policies) {
    // the required claims are empty, this resource has no way to be authorized
    return done(error('not_authorized',
      'This resource set can not be accessed.'));
  }

  var result = claimsAreSatisfied(this.rs, this.req.ticket);
  this.req.claimEvaluationResult = result;
  done();
}

function ClaimProcessingResult(satisfied, unmatched, matched) {
  this.satisfied = satisfied;
  this.unmatched = unmatched;
  this.matched = matched;
}

function claimsAreSatisfied(rs, ticket) {
  var self = this;
  this.allUnmatched = [];

  rs.policies.forEach(function (policy) {
    var unmatched = checkIndividualClaims(policy.claimsRequired, ticket.permission.claimsSupplied);
    if (unmatched.length === 0) {
      // we found something that's satisfied the claims, let's go with it!
      self.result = new ClaimProcessingResult(true, unmatched, policy.claimsRequired);
    } else {
      // otherwise add it to the stack to send back
      self.allUnmatched = self.allUnmatched.concat(unmatched);
      self.result = new ClaimProcessingResult(false, this.allUnmatched, []);
    }
  });

  return self.result;
}

function checkIndividualClaims(claimsRequired, claimsSupplied) {
  var claimsUnmatched = claimsRequired.slice(0);

  // see if each of the required claims has a counterpart in the supplied claims set
  claimsRequired.forEach(function (cr) {
    claimsSupplied.forEach(function (cs) {
      if (containsAll(cr.issuer, cs.issuer)) {
        // it's from the right issuer
        if (cr.name === cs.name && cr.value === cs.value) {
          // it's from the right issuer
          claimsUnmatched.splice(claimsUnmatched.indexOf(cr), 1);
        }
      }
    });
  });

  return claimsUnmatched;
}

function containsAll(needles, haystack) {
  return needles.every(function (v, i) {
    return haystack.indexOf(v) !== -1;
  });

}

/**
 * Generate an access token
 *
 * @param  {Function} done
 * @this   OAuth
 */
function generateRequestingPartyToken(done) {
  var self = this;
  token(this, 'rpt', function (err, token) {
    self.req.outgoingRpt = token;
    done(err);
  });
}

/**
 * Save access token with model
 *
 * @param  {Function} done
 * @this   OAuth
 */
function saveRequestingPartyToken(done) {
  var outgoingRpt = this.req.outgoingRpt;

  // Object indicates a reissue
  if (typeof outgoingRpt === 'object' && outgoingRpt.rpt) {
    this.req.outgoingRpt = outgoingRpt.rpt;
    return done();
  }

  var expires = null;
  if (this.config.requestingPartyTokenLifetime !== null) {
    expires = new Date(this.now);
    expires.setSeconds(expires.getSeconds() + this.config.requestingPartyTokenLifetime);
  }

  this.model.saveRequestingPartyToken(outgoingRpt, this.req.oauth.client, expires,
    this.user,
    function (err) {
      if (err) return done(error('server_error', false, err));
      done();
    });

}

/**
 * Return requesting party token (RPT).
 *
 * @param  {Function} done
 * @this   OAuth
 */
function sendResponse(done) {
  var response = {};

  if (this.req.claimEvaluationResult.satisfied) {
    response.rpt = this.req.outgoingRpt;
    this.res.set({'Cache-Control': 'no-store', 'Pragma': 'no-cache'});
    this.res.status(200);
    this.res.jsonp(response);
  } else {
    response.error = 'need-info';
    response.error_details = {
      requesting_party_claims: {
        redirect_user: true
      }
    };
    var targetUnmatchedList = [];
    this.req.claimEvaluationResult.unmatched.forEach(function (unmatched) {
      var targetUnmatched = {};
      targetUnmatched.name = unmatched.name;
      targetUnmatched.friendly_name = unmatched.friendlyName;
      targetUnmatched.claim_type = unmatched.claimType;
      targetUnmatched.claim_token_format = unmatched.claimTokenFormat;
      targetUnmatched.issuer = unmatched.issuer;
      targetUnmatchedList.push(targetUnmatched);

    });
    response.error_details.requesting_party_claims.required_claims = targetUnmatchedList;
    response.error_details.requesting_party_claims.ticket = this.req.ticket.uid;

    this.res.set({'Cache-Control': 'no-store', 'Pragma': 'no-cache'});
    this.res.status(403);
    this.res.jsonp(response);
  }

  if (this.config.continueAfterResponse)
    done();
}




