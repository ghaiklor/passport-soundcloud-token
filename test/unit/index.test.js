import chai, { assert } from 'chai';
import sinon from 'sinon';
import SoundCloudTokenStrategy from '../../src/index';
import fakeProfile from '../fixtures/profile';

const STRATEGY_CONFIG = {
  clientID: '123',
  clientSecret: '123'
};

const BLANK_FUNCTION = () => {
};

describe('SoundCloudTokenStrategy:init', () => {
  it('Should properly export Strategy constructor', () => {
    assert.isFunction(SoundCloudTokenStrategy);
  });

  it('Should properly initialize', () => {
    let strategy = new SoundCloudTokenStrategy(STRATEGY_CONFIG, BLANK_FUNCTION);

    assert.equal(strategy.name, 'soundcloud-token');
    assert(strategy._oauth2._useAuthorizationHeaderForGET);
  });

  it('Should properly throw error on empty options', () => {
    assert.throws(() => new SoundCloudTokenStrategy(), Error);
  });
});

describe('SoundCloudTokenStrategy:authenticate', () => {
  describe('Authenticate without passReqToCallback', () => {
    let strategy;

    before(() => {
      strategy = new SoundCloudTokenStrategy(STRATEGY_CONFIG, (accessToken, refreshToken, profile, next) => {
        assert.equal(accessToken, 'access_token');
        assert.equal(refreshToken, 'refresh_token');
        assert.typeOf(profile, 'object');
        assert.typeOf(next, 'function');
        return next(null, profile, {info: 'foo'});
      });

      sinon.stub(strategy._oauth2, 'get', (url, accessToken, next) => next(null, fakeProfile, null));
    });

    it('Should properly parse token from body', done => {
      chai.passport.use(strategy)
        .success((user, info) => {
          assert.typeOf(user, 'object');
          assert.typeOf(info, 'object');
          assert.deepEqual(info, {info: 'foo'});
          done();
        })
        .req(req => {
          req.body = {
            access_token: 'access_token',
            refresh_token: 'refresh_token'
          }
        })
        .authenticate();
    });

    it('Should properly parse token from query', done => {
      chai.passport.use(strategy)
        .success((user, info) => {
          assert.typeOf(user, 'object');
          assert.typeOf(info, 'object');
          assert.deepEqual(info, {info: 'foo'});
          done();
        })
        .req(req => {
          req.query = {
            access_token: 'access_token',
            refresh_token: 'refresh_token'
          }
        })
        .authenticate();
    });

    it('Should properly call fail if access_token is not provided', done => {
      chai.passport.use(strategy)
        .fail(error => {
          assert.typeOf(error, 'object');
          assert.typeOf(error.message, 'string');
          assert.equal(error.message, 'You should provide access_token');
          done();
        })
        .authenticate();
    });
  });

  describe('Authenticate with passReqToCallback', () => {
    let strategy;

    before(() => {
      strategy = new SoundCloudTokenStrategy(Object.assign(STRATEGY_CONFIG, {passReqToCallback: true}), (req, accessToken, refreshToken, profile, next) => {
        assert.typeOf(req, 'object');
        assert.equal(accessToken, 'access_token');
        assert.equal(refreshToken, 'refresh_token');
        assert.typeOf(profile, 'object');
        assert.typeOf(next, 'function');
        return next(null, profile, {info: 'foo'});
      });

      sinon.stub(strategy._oauth2, 'get', (url, accessToken, next) => next(null, fakeProfile, null));
    });

    it('Should properly call _verify with req', done => {
      chai.passport.use(strategy)
        .success((user, info) => {
          assert.typeOf(user, 'object');
          assert.typeOf(info, 'object');
          assert.deepEqual(info, {info: 'foo'});
          done();
        })
        .req(req => {
          req.body = {
            access_token: 'access_token',
            refresh_token: 'refresh_token'
          }
        })
        .authenticate({});
    });
  });
});

describe('SoundCloudTokenStrategy:userProfile', () => {
  it('Should properly fetch profile', done => {
    let strategy = new SoundCloudTokenStrategy(STRATEGY_CONFIG, BLANK_FUNCTION);

    sinon.stub(strategy._oauth2, 'get', (url, accessToken, next) => next(null, fakeProfile, null));

    strategy.userProfile('accessToken', (error, profile) => {
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

  it('Should properly handle exception on fetching profile', done => {
    let strategy = new SoundCloudTokenStrategy(STRATEGY_CONFIG, BLANK_FUNCTION);

    sinon.stub(strategy._oauth2, 'get', (url, accessToken, done) => done(null, 'not a JSON', null));

    strategy.userProfile('accessToken', (error, profile) => {
      assert(error instanceof SyntaxError);
      assert.equal(typeof profile, 'undefined');
      done();
    });
  });

  it('Should properly handle wrong JSON on fetching profile', done => {
    let strategy = new SoundCloudTokenStrategy(STRATEGY_CONFIG, BLANK_FUNCTION);

    sinon.stub(strategy._oauth2, 'get', (url, accessToken, done) => done(new Error('ERROR'), 'not a JSON', null));

    strategy.userProfile('accessToken', (error, profile) => {
      assert.instanceOf(error, Error);
      assert.equal(typeof profile, 'undefined');
      done();
    });
  });

  it('Should properly handle wrong JSON on fetching profile', done => {
    let strategy = new SoundCloudTokenStrategy(STRATEGY_CONFIG, BLANK_FUNCTION);

    sinon.stub(strategy._oauth2, 'get', (url, accessToken, done) => done({
      data: JSON.stringify({
        error: {
          message: 'MESSAGE',
          code: 'CODE'
        }
      })
    }, 'not a JSON', null));

    strategy.userProfile('accessToken', (error, profile) => {
      assert.equal(error.message, 'Failed to fetch user profile');
      assert.equal(typeof profile, 'undefined');
      done();
    });
  });
});
