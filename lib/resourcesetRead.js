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

module.exports = ResourceSetRead;

/**
 * This is the function order used by the runner
 *
 * @type {Array}
 */
var fns = [
  checkClient,
  getResourceSet,
  sendResponse
];

/**
 * ResourceSet Read
 *
 * @param {Object}   config Instance of OAuth object
 * @param {Object}   req
 * @param {Object}   res
 * @param {Function} next
 */
function ResourceSetRead(config, req, res, next) {
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
 * Fetches the supplied resource set
 *
 * @param done
 */
function getResourceSet(done) {
  var self = this;
  var id = this.req.params.id;

  if (!id) {
    return done(error('missing_required_fields',
      'Resource request was missing one or more required fields'));
  }

  this.model.getResourceSet(id, function (err, rs) {
    if (err) {
      return done(error('invalid_resource_set_requested', 'Invalid Resource Set has been requested'));
    }
    self.req.resourceset = rs;

    done();
  });

}

/**
 * Return retrieved resource set.
 *
 * @param  {Function} done
 * @this   OAuth
 */
function sendResponse(done) {
  this.res.set({'Cache-Control': 'no-store', 'Pragma': 'no-cache'});
  this.res.code = 200;
  this.res.jsonp({
      '_id': this.req.resourceset.id,
      'name': this.req.resourceset.name,
      'icon_uri': this.req.resourceset.iconUri,
      'type': this.req.resourceset.type,
      'scopes': this.req.resourceset.scopes,
      'uri': this.req.resourceset.uri
    }
  );

  if (this.config.continueAfterResponse)
    done();
}
