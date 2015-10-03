import { OAuth2Strategy, InternalOAuthError } from 'passport-oauth';

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
 * @param {Object} _options
 * @param {Function} _verify
 * @example
 * passport.use(new SoundCloudTokenStrategy({
 *   clientID: '123456789',
 *   clientSecret: 'shhh-its-a-secret'
 * }), function(req, accessToken, refreshToken, profile, next) {
 *   User.findOrCreate({soundCloudId: profile.id}, function(error, user) {
 *     next(error, user);
 *   })
 * })
 */
export default class SoundCloudTokenStrategy extends OAuth2Strategy {
  constructor(_options, _verify) {
    let options = _options || {};
    let verify = _verify;

    options.authorizationURL = options.authorizationURL || 'https://soundcloud.com/connect';
    options.tokenURL = options.tokenURL || 'https://api.soundcloud.com/oauth2/token';

    super(options, verify);

    this.name = 'soundcloud-token';
    this._accessTokenField = options.accessTokenField || 'access_token';
    this._refreshTokenField = options.refreshTokenField || 'refresh_token';
    this._profileURL = options.profileURL || 'https://api.soundcloud.com/me.json';
    this._passReqToCallback = options.passReqToCallback;

    this._oauth2.useAuthorizationHeaderforGET(true);
  }

  /**
   * Authenticate method
   * @param {Object} req
   * @param {Object} options
   * @returns {*}
   */
  authenticate(req, options) {
    let accessToken = (req.body && req.body[this._accessTokenField]) || (req.query && req.query[this._accessTokenField]);
    let refreshToken = (req.body && req.body[this._refreshTokenField]) || (req.query && req.query[this._refreshTokenField]);

    if (!accessToken) return this.fail({message: `You should provide ${this._accessTokenField}`});

    this._loadUserProfile(accessToken, (error, profile) => {
      if (error) return this.error(error);

      const verified = (error, user, info) => {
        if (error) return this.error(error);
        if (!user) return this.fail(info);

        return this.success(user, info);
      };

      if (this._passReqToCallback) {
        this._verify(req, accessToken, refreshToken, profile, verified);
      } else {
        this._verify(accessToken, refreshToken, profile, verified);
      }
    });
  }

  /**
   * Parse user profile
   * @param {String} accessToken SoundCloud OAuth2 access token
   * @param {Function} done
   */
  userProfile(accessToken, done) {
    this._oauth2.get(this._profileURL, accessToken, (error, body, res) => {
      if (error) {
        try {
          let errorJSON = JSON.parse(error.data);
          return done(new InternalOAuthError(errorJSON.errors[0].error_message, error.statusCode));
        } catch (_) {
          return done(new InternalOAuthError('Failed to fetch user profile', error));
        }
      }

      try {
        let json = JSON.parse(body);
        let profile = {
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
  }
}
