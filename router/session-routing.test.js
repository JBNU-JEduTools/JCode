'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { extractSessionId, stripProxyPrefix, isVncPath, routeKeyForProfile } = require('./session-routing');

test('extracts a tab-scoped session from HTTP and WebSocket URLs', () => {
  assert.equal(extractSessionId('/jcode/session/a-b-c/?folder=%2Fhome'), 'a-b-c');
  assert.equal(extractSessionId('/jcode/session/a-b-c/stable/ws'), 'a-b-c');
  assert.equal(extractSessionId('/jcode/?id=legacy'), null);
});

test('strips only router-owned prefixes before proxying', () => {
  assert.equal(stripProxyPrefix('/jcode/session/a-b-c/stable/file.js'), '/stable/file.js');
  assert.equal(stripProxyPrefix('/session/a-b-c/proxy/6080/vnc.html'), '/vnc.html');
  assert.equal(stripProxyPrefix('/websockify'), '/websockify');
  assert.equal(stripProxyPrefix('/jcode/session/a/proxy/6080/websockify'), '/websockify');
});

test('detects VNC and websockify paths with a session prefix', () => {
  assert.equal(isVncPath('/jcode/session/a/proxy/6080/vnc.html'), true);
  assert.equal(isVncPath('/jcode/session/a/websockify'), true);
  assert.equal(isVncPath('/jcode/session/a/stable/ws'), false);
});

test('uses per-JCode routes and keeps legacy fallback', () => {
  assert.equal(routeKeyForProfile({ jcodeId: '51' }), 'jcode:51:route');
  assert.equal(
    routeKeyForProfile({ email: 'a@example.com', courseCode: 'os', clss: '1', snapshot: 'true' }),
    'user:a@example.com:course:os:1:snapshot'
  );
});
