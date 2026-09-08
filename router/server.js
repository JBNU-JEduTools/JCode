const express = require('express');
const jwt = require('jsonwebtoken');
const { createProxyMiddleware } = require('http-proxy-middleware');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const redis = require('redis');
const axios = require('axios');
const cookie = require('cookie'); 
const crypto = require('crypto');
const client = require('prom-client');  // prometheus client
const { createRedisClient } = require('./redis-client');
const { extractSessionId, stripProxyPrefix, isVncPath, routeKeyForProfile } = require('./session-routing');
require('dotenv').config();

const app = express();
const port = Number.parseInt(process.env.PORT || '3001', 10);

///////////////////////////////////// prometheus client  //////////////////////////////////////////

// 기본 메트릭 수집기 설정
const collectDefaultMetrics = client.collectDefaultMetrics;
collectDefaultMetrics({ timeout: 5000 });

// 사용자 정의 메트릭 (예: 요청 카운터)
const httpRequestCounter = new client.Counter({
  name: 'http_requests_total',
  help: 'Total number of HTTP requests',
  labelNames: ['method', 'route', 'status']
});

// 기존 라우트들 전에 /metrics 엔드포인트 추가  (맨 앞에 두어야 함 - 다른 미들웨어의 영향을 받지 않게 하기 위해)
app.get('/metrics', async (req, res) => {
  try {
    res.set('Content-Type', client.register.contentType);
    res.end(await client.register.metrics());
  } catch (ex) {
    res.status(500).end(ex);
  }
});

// 미들웨어 예시: 각 요청마다 카운터 증가  ( /metrics 라우트는 카운트 하지 않기 위해 이후로 배치 )
app.use((req, res, next) => {
  res.on('finish', () => {
    httpRequestCounter.labels(req.method, req.path, res.statusCode).inc();
  });
  next();
});

//////////////////////////////////////////////////////////////////////////////////////////////////

// JWT 정보 (미설정 시 기동 차단)
if (!process.env.JWT_SECRET || !process.env.JWT_REFRESH_SECRET) {
  console.error("FATAL: JWT_SECRET, JWT_REFRESH_SECRET 환경 변수가 반드시 설정되어야 합니다.");
  process.exit(1);
}
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET;

// token refresh 엔드포인트
const SPRING_REFRESH_URL = process.env.SPRING_REFRESH_URL || "SPRING_REFRESH_URL";

// 서비스 도메인
const COOKIE_DOMAIN = process.env.COOKIE_DOMAIN || "localhost";
const CORS_ORIGIN = process.env.CORS_ORIGIN || "https://localhost";

// Redis
const redisClient = createRedisClient(redis);
redisClient.on('error', (err) => {
  console.error('Redis Client Error:', err);
});
redisClient.connect().catch((err) => {
  console.error('FATAL: Redis connection failed:', err);
  process.exit(1);
});

app.use(cookieParser());
app.use(cors({
	origin: CORS_ORIGIN,
  credentials: true,
}));

// --------------------------------------
// [추가] 에러시 alert 후 창 닫기 헬퍼
// --------------------------------------
function closeWindowWithMessage(res, statusCode, message) {
  res.status(statusCode).send(`
    <!DOCTYPE html>
    <html lang="ko">
    <head>
      <meta charset="utf-8"/>
      <title>Error</title>
    </head>
    <body>
      <script>
        const sessionMatch = window.location.pathname.match(/^\\/jcode\\/session\\/([^/]+)/);
        const logoutUrl = '/jcode-logout' + (sessionMatch ? '?session=' + encodeURIComponent(sessionMatch[1]) : '');
        // 1) 로그아웃 요청
        fetch(logoutUrl, {
          method: 'POST',
          credentials: 'include'
        })
          .catch(e => console.error(e))
          .finally(() => {
            // 2) 메시지 표시 후 창 닫기
            alert("${message}");
            try {
              // 동일 출처인 경우: iframe 내부에서도 부모 창에 접근 가능
              if (window.top === window) {
                window.close();
              } else {
                window.top.close();
              }
            } catch (e) {
              // cross-origin인 경우: 부모 창에 메시지를 보내 창 닫기를 요청합니다.
              window.parent.postMessage({ action: 'close' }, '*');
            }
          });
      </script>
    </body>
    </html>
  `);
}

// 쿠키 옵션
const cookieOptions = {
  httpOnly: true,
  secure: true,
  sameSite: 'strict',
  path: '/',
  domain: COOKIE_DOMAIN,
  maxAge: 6 * 3600 * 1000  
};

async function canAccessUserProfile(decoded, userProfile) {
  const { sub, role } = decoded || {};
  const { courseCode, clss, email } = userProfile || {};
  if (!sub || !courseCode || !clss || !email) {
    return false;
  }
  if (role === "ADMIN" || sub === email) {
    return true;
  }
  return redisClient.sIsMember(`course:${courseCode}:${clss}:managers`, sub);
}

const refreshRequests = new Map();

async function requestFreshTokens(req, currentToken) {
  const response = await axios.post(`${SPRING_REFRESH_URL}`, null, {
    withCredentials: true,
    headers: {
      Authorization: currentToken ? `Bearer ${currentToken}` : '',
      Cookie: req.headers.cookie || ''
    }
  });
  const authHeader = response.headers['authorization'] || response.headers['Authorization'];
  if (!authHeader) throw new Error('Authorization header not found in refresh response');
  const setCookieHeader = response.headers['set-cookie'];
  const refreshCookie = Array.isArray(setCookieHeader)
    ? setCookieHeader.find(value => value.startsWith('jcodeRt='))
    : null;
  const refreshMatch = refreshCookie && refreshCookie.match(/^jcodeRt=([^;]+);?/);
  return {
    accessToken: authHeader.replace(/^Bearer\s/, ''),
    refreshToken: refreshMatch ? refreshMatch[1] : null
  };
}

// 같은 refresh token으로 동시에 들어오는 asset 요청은 한 번만 재발급한다.
const refreshAccessToken = async (req, res, next, currentToken) => {
  try {
    const refreshMaterial = req.cookies.jcodeRt || req.headers.cookie || 'missing';
    const refreshKey = crypto.createHash('sha256').update(refreshMaterial).digest('hex');
    let pending = refreshRequests.get(refreshKey);
    if (!pending) {
      pending = requestFreshTokens(req, currentToken)
        .finally(() => refreshRequests.delete(refreshKey));
      refreshRequests.set(refreshKey, pending);
    }
    const fresh = await pending;
    res.cookie('jcodeAt', fresh.accessToken, cookieOptions);
    req.cookies.jcodeAt = fresh.accessToken;
    req.user = jwt.verify(fresh.accessToken, JWT_SECRET);
    if (fresh.refreshToken) {
      res.cookie('jcodeRt', fresh.refreshToken, cookieOptions);
      req.cookies.jcodeRt = fresh.refreshToken;
    }
    console.log("Access token refreshed");
    return next();
  } catch (err) {
    console.error("Error during token refresh:", err.message);
    return closeWindowWithMessage(res, 503, "인증 재발급에 실패했습니다. 다시 시도해주세요.");
  }
};

// 인증 미들웨어
const ensureAuthenticated = (req, res, next) => {
  const token = req.cookies.jcodeAt;
  if (!token) {
    console.warn("Missing access token");
    return closeWindowWithMessage(res, 401, "세션이 만료되었거나 인증 토큰이 없습니다. 다시 시도해주세요.");
  }
  try {
    const decoded = jwt.decode(token);
    if (decoded && decoded.exp) {
      const expTime = decoded.exp * 1000;
      const timeRemaining = expTime - Date.now();
      if (timeRemaining < 60000) { // 만료 1분 전부터 재발급
        console.log("Access token nearing expiration, refreshing...");
        return refreshAccessToken(req, res, next, token);
      } else {
        // 서명 검증
        req.user = jwt.verify(token, JWT_SECRET);
        return next();
      }
    } else {
      console.warn("Unable to decode token properly, attempting refresh...");
      return refreshAccessToken(req, res, next, token);
    }
  } catch (err) {
    console.warn("Error verifying token:", err.message, "Attempting refresh...");
    return refreshAccessToken(req, res, next, token);
  }
};

// 토큰 서명 검증
const verifyTokenFromCookie = (req, res, next) => {
  const token = req.cookies.jcodeAt; 
  if (!token) {
    return closeWindowWithMessage(res, 401, "인증 토큰이 없습니다. 다시 시도해주세요.");
  }
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      return closeWindowWithMessage(res, 403, "인증에 실패하였습니다. 다시 시도해주세요.");
    }
    req.user = decoded;
    console.log("Token verified successfully");
    next();
  });
};

async function loadSession(req, res, uuid) {
  try {
    if (!uuid) {
      closeWindowWithMessage(res, 400, "유효한 프로젝트 세션이 없습니다.");
      return false;
    }
    
    const redisKey = `user:profile:${uuid}`;
    const userProfile = await redisClient.hGetAll(redisKey);
    if (!userProfile || Object.keys(userProfile).length === 0) {
      closeWindowWithMessage(res, 404, "사용자 정보를 찾을 수 없습니다. 다시 시도해주세요.");
      return false;
    }

    // 프로필 접근 시 TTL 초기화 (6시간)
    await redisClient.expire(redisKey, 6 * 3600);
    
    const { courseCode, clss, email: studentEmail } = userProfile;
    if (!courseCode || !clss || !studentEmail) {
      closeWindowWithMessage(res, 400, "필수 프로젝트 정보가 누락되었습니다.");
      return false;
    }
    
    const { sub, role } = req.user;
    console.log(`course: ${courseCode}:${clss}, studentEmail: ${studentEmail}, email: ${sub}, role: ${role}`);

    if (!await canAccessUserProfile(req.user, userProfile)) {
      closeWindowWithMessage(res, 403, "해당 프로젝트에 접근 권한이 없습니다.");
      return false;
    }
    
    // targetUrl 조회
    const redisKeyForTarget = routeKeyForProfile(userProfile);
    const resolvedTargetUrl = await redisClient.get(redisKeyForTarget);
    if (!resolvedTargetUrl) {
      closeWindowWithMessage(res, 403, "프로젝트 URL을 찾을 수 없습니다.");
      return false;
    }
    req.targetUrl = resolvedTargetUrl;
    console.log(`Resolved targetUrl for ${studentEmail}: ${resolvedTargetUrl}`);
    
    return true;
  } catch (error) {
    console.error("Error resolving targetUrl:", error.message);
    closeWindowWithMessage(res, 500, "서버 오류가 발생했습니다. 다시 시도해주세요.");
    return false;
  }
}

// 기존 query 링크는 한 번만 canonical session path로 전환한다.
app.get('/jcode', ensureAuthenticated, verifyTokenFromCookie, async (req, res) => {
  const uuid = req.query.id;
  if (!await loadSession(req, res, uuid)) return;
  res.cookie('jcode-uuid', uuid, cookieOptions); // 구버전 Router와의 rolling 호환
  const query = new URLSearchParams(req.query);
  query.delete('id');
  const suffix = query.toString();
  res.redirect(307, `/jcode/session/${encodeURIComponent(uuid)}/${suffix ? `?${suffix}` : ''}`);
});

// 프록시용 targetUrl 미들웨어
const resolveTargetUrlMiddleware = async (req, res, next) => {
  if (req.targetUrl) return next();
  const uuid = extractSessionId(req.originalUrl) || req.cookies['jcode-uuid'];
  if (!await loadSession(req, res, uuid)) return;
  next();
};

const proxy = createProxyMiddleware({
  changeOrigin: true,
  pathRewrite: (path, req) => {
    const newPath = stripProxyPrefix(path);
    console.log(`Proxying request => target: ${req.vncTargetUrl || req.wsTargetUrl || req.targetUrl}, path: ${newPath}`);
    return newPath;
  },
  router: (req) => {
    // VNC 요청(`/jcode/proxy/6080`)이면 `targetUrl`을 `vncTargetUrl`로 변환
    if (isVncPath(req.originalUrl || req.url)) {
      if (req.targetUrl) {
        req.vncTargetUrl = req.targetUrl.replace(/:8080$/, ':6080'); // 8080 → 6080 변경
      }
      console.log(`VNC Proxying request => target: ${req.vncTargetUrl}`);
      return req.vncTargetUrl;
    }
    return req.wsTargetUrl || req.targetUrl;
  },
});

// 프록시 라우트
app.use('/jcode', ensureAuthenticated, resolveTargetUrlMiddleware, proxy);

// IDE 창 종료는 해당 launch profile만 끝낸다. 인증 쿠키와 durable route는 다른 탭과 공유된다.
app.post('/jcode-logout', ensureAuthenticated, async (req, res) => {
  try {
    const jcodeUuid = req.query.session ||
      extractSessionId(req.get('referer') || '') ||
      req.cookies['jcode-uuid'];

    if (jcodeUuid) {
      const profileKey = `user:profile:${jcodeUuid}`;
      const profile = await redisClient.hGetAll(profileKey);
      if (profile && Object.keys(profile).length > 0) {
        if (!await canAccessUserProfile(req.user, profile)) {
          return res.status(403).send("No permission for this session");
        }
        await redisClient.del(profileKey);
      }
    }

    return res.status(200).send("Session closed");
  } catch (err) {
    console.error("Logout Error:", err);
    return res.status(500).send("Error while logging out");
  }
});

// 서버 시작
const server = app.listen(port, () => {
  console.log(`Node.js server listening on port ${port}`);
});

// WebSocket upgrade
server.on('upgrade', async (req, socket, head) => {
  try {
    const cookies = cookie.parse(req.headers.cookie || '');
    const token = cookies.jcodeAt;
    if (!token) {
      socket.write('HTTP/1.1 401 Unauthorized\r\n\r\nMissing access token');
      socket.destroy();
      return;
    }
    let decoded;
    try {
      decoded = jwt.verify(token, JWT_SECRET);
    } catch (err) {
      socket.write('HTTP/1.1 403 Forbidden\r\n\r\nInvalid access token');
      socket.destroy();
      return;
    }

    const jcodeUuid = extractSessionId(req.url) || cookies['jcode-uuid'];
    if (!jcodeUuid) {
      socket.write('HTTP/1.1 400 Bad Request\r\n\r\nMissing jcode-uuid cookie');
      socket.destroy();
      return;
    }
    const userProfile = await redisClient.hGetAll(`user:profile:${jcodeUuid}`);
    if (!userProfile || Object.keys(userProfile).length === 0) {
      socket.write('HTTP/1.1 404 Not Found\r\n\r\nUser profile not found');
      socket.destroy();
      return;
    }
    const { email } = userProfile;

    if (!await canAccessUserProfile(decoded, userProfile)) {
      socket.write('HTTP/1.1 403 Forbidden\r\n\r\nNo permission for this project');
      socket.destroy();
      return;
    }

    const redisKeyForTarget = routeKeyForProfile(userProfile);
    const ideTargetUrl = await redisClient.get(redisKeyForTarget);
    if (!ideTargetUrl) {
      socket.write('HTTP/1.1 403 Forbidden\r\n\r\nMissing targetUrl in Redis');
      socket.destroy();
      return;
    }
    let wsTargetUrl = ideTargetUrl
      .replace(/^http:/, 'ws:')
      .replace(/^https:/, 'wss:');

    if (isVncPath(req.url)) {
        wsTargetUrl = wsTargetUrl
          .replace(/:8080/, ':6080');
      }
    
    console.log(`WebSocket upgrade: ${email} => ${wsTargetUrl}`);
    req.wsTargetUrl = wsTargetUrl;
    proxy.upgrade(req, socket, head);
  } catch (err) {
    console.error("Error in WebSocket upgrade:", err.message);
    socket.write('HTTP/1.1 500 Internal Server Error\r\n\r\n');
    socket.destroy();
  }
});
