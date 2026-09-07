'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createRedisClient, parseSentinelNodes } = require('./redis-client');

test('parses multiple Sentinel seeds', () => {
  assert.deepEqual(parseSentinelNodes('sentinel-0:26379, sentinel-1:26380'), [
    { host: 'sentinel-0', port: 26379 },
    { host: 'sentinel-1', port: 26380 },
  ]);
});

test('creates an authenticated Sentinel client', () => {
  let options;
  const expected = { kind: 'sentinel' };
  const redis = {
    createSentinel(value) {
      options = value;
      return expected;
    },
  };

  const actual = createRedisClient(redis, {
    REDIS_PASSWORD: 'secret',
    REDIS_SENTINEL_MASTER: 'jcode',
    REDIS_SENTINEL_NODES: 's0:26379,s1:26379,s2:26379',
  });

  assert.equal(actual, expected);
  assert.equal(options.name, 'jcode');
  assert.equal(options.sentinelRootNodes.length, 3);
  assert.deepEqual(options.nodeClientOptions, { password: 'secret' });
  assert.deepEqual(options.sentinelClientOptions, { password: 'secret' });
});

test('keeps standalone Redis for local development', () => {
  let options;
  const redis = {
    createClient(value) {
      options = value;
      return {};
    },
  };

  createRedisClient(redis, { REDIS_HOST: 'redis', REDIS_PORT: '6380' });
  assert.deepEqual(options, { socket: { host: 'redis', port: 6380 } });
});

test('rejects partial Sentinel configuration', () => {
  assert.throws(
    () => createRedisClient({}, { REDIS_SENTINEL_MASTER: 'jcode' }),
    /must be configured together/
  );
});
