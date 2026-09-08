'use strict';

function extractSessionId(url = '') {
  const match = url.match(/^\/jcode\/session\/([^/?#]+)(?:[/?#]|$)/);
  if (!match) return null;
  try {
    return decodeURIComponent(match[1]);
  } catch (_) {
    return null;
  }
}

function stripProxyPrefix(path = '') {
  const normalized = path
    .replace(/^\/jcode\/session\/[^/?#]+/, '')
    .replace(/^\/session\/[^/?#]+/, '')
    .replace(/^\/jcode/, '');
  if (normalized.startsWith('/proxy/6080')) {
    return normalized.replace(/^\/proxy\/6080/, '') || '/';
  }
  return normalized || '/';
}

function isVncPath(url = '') {
  const normalized = url
    .replace(/^\/jcode\/session\/[^/?#]+/, '')
    .replace(/^\/session\/[^/?#]+/, '')
    .replace(/^\/jcode/, '');
  return normalized.startsWith('/proxy/6080') || normalized.startsWith('/websockify');
}

function routeKeyForProfile(profile) {
  if (profile && profile.jcodeId) return `jcode:${profile.jcodeId}:route`;
  if (!profile || !profile.email || !profile.courseCode || !profile.clss) return null;
  const suffix = profile.snapshot === 'true' || profile.snapshot === true ? ':snapshot' : '';
  return `user:${profile.email}:course:${profile.courseCode}:${profile.clss}${suffix}`;
}

module.exports = { extractSessionId, stripProxyPrefix, isVncPath, routeKeyForProfile };
