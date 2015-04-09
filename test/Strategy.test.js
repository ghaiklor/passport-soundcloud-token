var chai = require('chai');
var assert = chai.assert;
var SoundCloudTokenStrategy = require('../');
var fakeProfile = JSON.stringify(require('./fixtures/profile.json'));

describe('SoundCloudTokenStrategy:init', function () {
  it('Should properly export Strategy constructor', function () {
    assert.equal(typeof SoundCloudTokenStrategy, 'function');
    assert.equal(typeof SoundCloudTokenStrategy.Strategy, 'function');
    assert.equal(SoundCloudTokenStrategy, SoundCloudTokenStrategy.Strategy);
  });

  it('Should properly initialize', function () {
    var strategy = new SoundCloudTokenStrategy({
      clientID: '123',
      clientSecret: '123'
    }, function () {
    });

    assert.equal(strategy.name, 'soundcloud-token');
    assert(strategy._oauth2._useAuthorizationHeaderForGET);
  });
});

describe('SoundCloudTokenStrategy:authenticate', function () {
  describe('Authenticate without passReqToCallback', function () {
    var strategy;

    before(function () {
      strategy = new SoundCloudTokenStrategy({
        clientID: '123',
        clientSecret: '123'
      }, function (accessToken, refreshToken, profile, next) {
        assert.equal(accessToken, 'access_token');
        assert.equal(refreshToken, 'refresh_token');
        assert.typeOf(profile, 'object');
        assert.typeOf(next, 'function');
        return next(null, profile, {info: 'foo'});
      });

      strategy._oauth2.get = function (url, accessToken, next) {
        next(null, fakeProfile, null);
      };
    });

    it('Should properly parse access_token', function (done) {
      chai.passport.use(strategy)
        .success(function (user, info) {
          assert.typeOf(user, 'object');
          assert.typeOf(info, 'object');
          assert.deepEqual(info, {info: 'foo'});
          done();
        })
        .req(function (req) {
          req.headers = {
            access_token: 'access_token',
            refresh_token: 'refresh_token'
          }
        })
        .authenticate({});
    });

    it('Should properly call fail if access_token is not provided', function (done) {
      chai.passport.use(strategy)
        .fail(function (error) {
          assert.typeOf(error, 'object');
          assert.typeOf(error.message, 'string');
          assert.equal(error.message, 'You should provide access_token');
          done();
        })
        .authenticate();
    });
  });

  describe('Authenticate with passReqToCallback', function () {
    var strategy;

    before(function () {
      strategy = new SoundCloudTokenStrategy({
        clientID: '123',
        clientSecret: '123',
        passReqToCallback: true
      }, function (req, accessToken, refreshToken, profile, next) {
        assert.typeOf(req, 'object');
        assert.equal(accessToken, 'access_token');
        assert.equal(refreshToken, 'refresh_token');
        assert.typeOf(profile, 'object');
        assert.typeOf(next, 'function');
        return next(null, profile, {info: 'foo'});
      });

      strategy._oauth2.get = function (url, accessToken, next) {
        next(null, fakeProfile, null);
      }
    });

    it('Should properly call _verify with req', function (done) {
      chai.passport.use(strategy)
        .success(function (user, info) {
          assert.typeOf(user, 'object');
          assert.typeOf(info, 'object');
          assert.deepEqual(info, {info: 'foo'});
          done();
        })
        .req(function (req) {
          req.body = {
            access_token: 'access_token',
            refresh_token: 'refresh_token'
          }
        })
        .authenticate({});
    });
  });
});

describe('SoundCloudTokenStrategy:userProfile', function () {
  it('Should properly fetch profile', function (done) {
    var strategy = new SoundCloudTokenStrategy({
      clientID: '123',
      clientSecret: '123'
    }, function () {
    });

    strategy._oauth2.get = function (url, accessToken, next) {
      next(null, fakeProfile, null);
    };

    strategy.userProfile('accessToken', function (error, profile) {
      if (error) return done(error);

      assert.equal(profile.provider, 'soundcloud');
      assert.equal(profile.id, '3207');
      assert.equal(profile.displayName, 'Johannes Wagener');
      assert.equal(profile.name.familyName, 'Wagener');
      assert.equal(profile.name.givenName, 'Johannes');
      assert.deepEqual(profile.emails, []);
      assert.equal(profile.photos[0].value, 'http://i1.sndcdn.com/avatars-000001552142-pbw8yd-large.jpg?142a848');
      assert.equal(typeof profile._raw, 'string');
      assert.equal(typeof profile._json, 'object');

      done();
    });
  });

  it('Should properly handle exception on fetching profile', function (done) {
    var strategy = new SoundCloudTokenStrategy({
      clientID: '123',
      clientSecret: '123'
    }, function () {
    });

    strategy._oauth2.get = function (url, accessToken, done) {
      done(null, 'not a JSON', null);
    };

    strategy.userProfile('accessToken', function (error, profile) {
      assert(error instanceof SyntaxError);
      assert.equal(typeof profile, 'undefined');
      done();
    });
  });
});
