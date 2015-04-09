var util = require('util');
var OAuth2Strategy = require('passport-oauth').OAuth2Strategy;
var InternalOAuthError = require('passport-oauth').InternalOAuthError;

util.inherits(SoundCloudTokenStrategy, OAuth2Strategy);

/**
 * `Strategy` constructor.
 * The SoundCloud authentication strategy authenticates requests by delegating to SoundCloud using OAuth2 access tokens.
 * Applications must supply a `verify` callback which accepts a accessToken, refreshToken, profile and callback.
 * Callback supplying a `user`, which should be set to `false` if the credentials are not valid.
 * If an exception occurs, `error` should be set.
 *
 * Options:
 * - clientID          Identifies client to SoundCloud App
 * - clientSecret      Secret used to establish ownership of the consumer key
 * - passReqToCallback If need, pass req to verify callback
 *
 * Example:
 *     passport.use(new SoundCloudTokenStrategy({
 *           clientID: '123-456-789',
 *           clientSecret: 'shhh-its-a-secret',
 *           passReqToCallback: true
 *       }, function(req, accessToken, refreshToken, profile, next) {
 *              User.findOrCreate(..., function (error, user) {
 *                  next(error, user);
 *              });
 *          }
 *       ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @constructor
 */
function SoundCloudTokenStrategy(options, verify) {
  options = options || {};
  options.authorizationURL = options.authorizationURL || 'https://soundcloud.com/connect';
  options.tokenURL = options.tokenURL || 'https://api.soundcloud.com/oauth2/token';
  options.profileURL = options.profileURL || 'https://api.soundcloud.com/me.json';

  OAuth2Strategy.call(this, options, verify);

  this.name = 'soundcloud-token';
  this._profileURL = options.profileURL;
  this._passReqToCallback = options.passReqToCallback;
  this._oauth2._useAuthorizationHeaderForGET = true;
}

/**
 * Authenticate method
 * @param {Object} req
 * @param {Object} options
 * @returns {*}
 */
SoundCloudTokenStrategy.prototype.authenticate = function (req, options) {
  var self = this;
  var accessToken = (req.body && req.body.access_token) || (req.query && req.query.access_token) || (req.headers && req.headers.access_token);
  var refreshToken = (req.body && req.body.refresh_token) || (req.query && req.query.refresh_token) || (req.headers && req.headers.refresh_token);

  if (!accessToken) {
    return self.fail({message: 'You should provide access_token'});
  }

  self._loadUserProfile(accessToken, function (error, profile) {
    if (error) return self.error(error);

    function verified(error, user, info) {
      if (error) return self.error(error);
      if (!user) return self.fail(info);

      return self.success(user, info);
    }

    if (self._passReqToCallback) {
      self._verify(req, accessToken, refreshToken, profile, verified);
    } else {
      self._verify(accessToken, refreshToken, profile, verified);
    }
  });
};

/**
 * Parse user profile
 * @param {String} accessToken SoundCloud OAuth2 access token
 * @param {Function} done
 */
SoundCloudTokenStrategy.prototype.userProfile = function (accessToken, done) {
  this._oauth2.get(this._profileURL, accessToken, function (error, body, res) {
    if (error) return done(new InternalOAuthError('Failed to fetch user profile', error));

    try {
      var json = JSON.parse(body);
      var profile = {
        provider: 'soundcloud',
        id: json.id,
        username: json.username,
        displayName: json.full_name || '',
        name: {
          familyName: json.full_name ? json.full_name.split(' ', 2)[1] : '',
          givenName: json.full_name ? json.full_name.split(' ', 2)[0] : ''
        },
        emails: [],
        photos: [{
          value: json.avatar_url || ''
        }],
        _raw: body,
        _json: json
      };

      return done(null, profile);
    } catch (e) {
      return done(e);
    }
  });
};

module.exports = SoundCloudTokenStrategy;
