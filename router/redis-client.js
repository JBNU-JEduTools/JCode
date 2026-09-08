'use strict';

function parseSentinelNodes(value) {
  return value.split(',').map((entry) => entry.trim()).filter(Boolean).map((entry) => {
    const separator = entry.lastIndexOf(':');
    if (separator <= 0) {
      throw new Error(`Invalid Redis Sentinel address: ${entry}`);
    }
    const host = entry.slice(0, separator);
    const port = Number.parseInt(entry.slice(separator + 1), 10);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      throw new Error(`Invalid Redis Sentinel port: ${entry}`);
    }
    return { host, port };
  });
}

function createRedisClient(redis, env = process.env) {
  const password = env.REDIS_PASSWORD || '';
  const sentinelMaster = env.REDIS_SENTINEL_MASTER || '';
  const sentinelNodes = env.REDIS_SENTINEL_NODES || '';

  if (sentinelMaster || sentinelNodes) {
    if (!sentinelMaster || !sentinelNodes) {
      throw new Error('REDIS_SENTINEL_MASTER and REDIS_SENTINEL_NODES must be configured together');
    }
    const nodeClientOptions = password ? { password } : {};
    const sentinelClientOptions = password ? { password } : {};
    return redis.createSentinel({
      name: sentinelMaster,
      sentinelRootNodes: parseSentinelNodes(sentinelNodes),
      nodeClientOptions,
      sentinelClientOptions,
    });
  }

  const options = {
    socket: {
      host: env.REDIS_HOST || '127.0.0.1',
      port: Number.parseInt(env.REDIS_PORT || '6379', 10),
    },
  };
  if (password) {
    options.password = password;
  }
  return redis.createClient(options);
}

module.exports = { createRedisClient, parseSentinelNodes };
