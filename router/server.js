const express = require('express');
const jwt = require('jsonwebtoken');
const { createProxyMiddleware } = require('http-proxy-middleware');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const redis = require('redis');
const axios = require('axios');
const cookie = require('cookie'); 
const client = require('prom-client');  // prometheus client
require('dotenv').config();

const app = express();
const port = 3001;

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

// JWT 정보
const JWT_SECRET = process.env.JWT_SECRET || "ACCESS_SECRET";
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || "REFRESH_SECRET";

// token refresh 엔드포인트
const SPRING_REFRESH_URL = process.env.SPRING_REFRESH_URL || "SPRING_REFRESH_URL";

// 서비스 도메인
const COOKIE_DOMAIN = process.env.COOKIE_DOMAIN || "localhost";
const CORS_ORIGIN = process.env.CORS_ORIGIN || "https://localhost";

// REDIS 정보
const REDIS_HOST = process.env.REDIS_HOST || "127.0.0.1";
const REDIS_PORT = parseInt(process.env.REDIS_PORT) || 6379;

// Redis
const redisClient = redis.createClient({ socket: { host: REDIS_HOST, port: REDIS_PORT }});
redisClient.on('error', (err) => {
  console.error('Redis Client Error:', err);
});
redisClient.connect();

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
        // 1) 로그아웃 요청
        fetch('/jcode-logout', {
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

// 토큰 재발급 함수
const refreshAccessToken = async (req, res, next, currentToken) => {
  try {
    const response = await axios.post(`${SPRING_REFRESH_URL}`, null, {
      withCredentials: true,
      headers: {
        Authorization: currentToken ? `Bearer ${currentToken}` : '',
        Cookie: req.headers.cookie || ''
      }
    });
    
    // 응답에서 Bearer 토큰 추출
    const authHeader = response.headers['authorization'] || response.headers['Authorization'];
    if (authHeader) {
      const token = authHeader.replace(/^Bearer\s/, '');
      // 새 access token
      res.cookie('jcodeAt', token, cookieOptions);
      req.cookies.jcodeAt = token;
      
      // refresh token 재발급
      const setCookieHeader = response.headers['set-cookie'];
      if (setCookieHeader && Array.isArray(setCookieHeader)) {
        const newRefreshCookie = setCookieHeader.find(cookieStr => cookieStr.startsWith('jcodeRt='));
        if (newRefreshCookie) {
          const match = newRefreshCookie.match(/^jcodeRt=([^;]+);/);
          if (match && match[1]) {
            const newRefreshToken = match[1];
            console.log("New refresh token extracted:", newRefreshToken);
            res.cookie('jcodeRt', newRefreshToken, cookieOptions);
            req.cookies.refreshToken = newRefreshToken;
          }
        }
      }
      
      console.log("Access token refreshed:", token);
      return next();
    } else {
      console.error("Authorization header not found in refresh response");
      return closeWindowWithMessage(res, 500, "인증 재발급 중 오류가 발생했습니다. 다시 시도해주세요.");
    }
  } catch (err) {
    console.error("Error during token refresh:", err);
    return closeWindowWithMessage(res, 500, "인증 재발급에 실패했습니다. 다시 시도해주세요.");
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
      if (timeRemaining < 540000) { // 9분 이하면 재발급
        console.log("Access token nearing expiration, refreshing...");
        return refreshAccessToken(req, res, next, token);
      } else {
        // 서명 검증
        jwt.verify(token, JWT_SECRET);
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
    console.log("Token Verified Successfully:", decoded);
    next();
  });
};

// GET /jcode
app.get('/jcode', ensureAuthenticated, verifyTokenFromCookie, async (req, res, next) => {
  try {
    const uuid = req.query.id;
    if (!uuid) {
      return closeWindowWithMessage(res, 400, "잘못된 접근입니다 (id 파라미터 누락).");
    }
    
    const redisKey = `user:profile:${uuid}`;
    const userProfile = await redisClient.hGetAll(redisKey);
    if (!userProfile || Object.keys(userProfile).length === 0) {
      return closeWindowWithMessage(res, 404, "사용자 정보를 찾을 수 없습니다. 다시 시도해주세요.");
    }

    // 프로필 접근 시 TTL 초기화 (6시간)
    await redisClient.expire(redisKey, 6 * 3600);
    
    const { courseCode, clss, email: studentEmail } = userProfile;
    if (!courseCode || !clss || !studentEmail) {
      return closeWindowWithMessage(res, 400, "필수 정보가 누락되었습니다 (courseCode, clss, email).");
    }
    
    const { sub, role } = req.user;
    console.log(`course: ${courseCode}:${clss}, studentEmail: ${studentEmail}, email: ${sub}, role: ${role}`);
    
    // 권한 체크
    if (role && !role.includes("ADMIN")) {
      if (role.includes("PROFESSOR") || role.includes("ASSISTANT")) {
        const isManager = await redisClient.sIsMember(`course:${courseCode}:${clss}:managers`, sub);
        // 교수/조교인데 매니저 할당이 안 되어 있다면, 자신의 이메일인지 추가 체크합니다.
        if (!isManager && sub !== studentEmail) {
          return closeWindowWithMessage(res, 403,"이 강의에 접근 권한이 없습니다 (교수/조교 미할당 및 이메일 불일치).");
        }
      } else {
        // 교수/조교가 아닌 경우, 자신의 이메일 여부만 확인합니다.
        if (sub !== studentEmail) {
          return closeWindowWithMessage(res, 403, "해당 프로젝트에 접근 권한이 없습니다 (이메일 불일치).");
        }
      }
    }
    
    // targetUrl 조회
    const redisKeyForTarget = (userProfile.snapshot === 'true' || userProfile.snapshot === true)
      ? `user:${studentEmail}:course:${courseCode}:${clss}:snapshot`
      : `user:${studentEmail}:course:${courseCode}:${clss}`;
    const resolvedTargetUrl = await redisClient.get(redisKeyForTarget);
    if (!resolvedTargetUrl) {
      return closeWindowWithMessage(res, 403, "프로젝트 URL을 찾을 수 없습니다.");
    }
    req.targetUrl = resolvedTargetUrl;
    console.log(`Resolved targetUrl for ${studentEmail}: ${resolvedTargetUrl}`);
    
    // jcode-uuid 쿠키 저장
    res.cookie('jcode-uuid', uuid, cookieOptions);
    
    next();
  } catch (error) {
    console.error("Error resolving targetUrl:", error.message);
    return closeWindowWithMessage(res, 500, "서버 오류가 발생했습니다. 다시 시도해주세요.");
  }
});

// 프록시용 targetUrl 미들웨어
const resolveTargetUrlMiddleware = async (req, res, next) => {
  if (!req.targetUrl) {
    const uuid = req.cookies['jcode-uuid'];
    if (!uuid) {
      return closeWindowWithMessage(res, 400, "유효한 프로젝트 정보를 찾을 수 없습니다 (jcode-uuid 미존재).");
    }
    try {
      const redisKey = `user:profile:${uuid}`;
      const userProfile = await redisClient.hGetAll(redisKey);
      if (!userProfile || Object.keys(userProfile).length === 0) {
        return closeWindowWithMessage(res, 404, "사용자 정보를 찾을 수 없습니다. 다시 시도해주세요.");
      }
      const { courseCode, clss, email } = userProfile;
      const redisKeyForTarget = (userProfile.snapshot === 'true' || userProfile.snapshot === true)
        ? `user:${email}:course:${courseCode}:${clss}:snapshot`
        : `user:${email}:course:${courseCode}:${clss}`;
      const resolvedTargetUrl = await redisClient.get(redisKeyForTarget);
      if (!resolvedTargetUrl) {
        return closeWindowWithMessage(res, 403, "프로젝트 URL을 찾을 수 없습니다.");
      }

      // 프로필 접근 시 TTL 초기화 (6시간)
      await redisClient.expire(redisKey, 6 * 3600);
    
      req.targetUrl = resolvedTargetUrl;
      console.log("Resolved targetUrl from jcode-uuid cookie:", req.targetUrl);
      next();
    } catch (error) {
      console.error("Error resolving targetUrl from jcode-uuid cookie:", error.message);
      return closeWindowWithMessage(res, 500, "서버 오류가 발생했습니다. 다시 시도해주세요.");
    }
  } else {
    next();
  }
};

const proxy = createProxyMiddleware({
  changeOrigin: true,
  pathRewrite: (path, req) => {
    const newPath = path.replace(/^\/proxy\/6080|^\/jcode|^\/websockify/, '');  
    console.log(`Proxying request => target: ${req.vncTargetUrl || req.wsTargetUrl || req.targetUrl}, path: ${newPath}`);
    return newPath;
  },
  router: (req) => {
    // VNC 요청(`/jcode/proxy/6080`)이면 `targetUrl`을 `vncTargetUrl`로 변환
    if (req.url.startsWith('/proxy/6080')) {
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

// 로그아웃 라우트 (Redis에서 userProfile, courseKey 삭제)
app.post('/jcode-logout', async (req, res) => {
  try {
    // 1) jcode-uuid 쿠키 확인
    const jcodeUuid = req.cookies['jcode-uuid'];

    if (jcodeUuid) {
      // 2) Redis에서 user:profile:${jcodeUuid} 조회
      const userProfile = await redisClient.hGetAll(`user:profile:${jcodeUuid}`);
      if (userProfile && Object.keys(userProfile).length > 0) {
        const { email, courseCode, clss } = userProfile;

        // 3) userProfile 키 삭제
        await redisClient.del(`user:profile:${jcodeUuid}`);

        // 4) user:${email}:course:${courseCode}:${clss} 키도 삭제
        if (email && courseCode && clss) {
          const token = req.cookies.jcodeAt;
          try {
            const decodedToken = jwt.verify(token, JWT_SECRET);
            if (decodedToken && decodedToken.sub === email) {
              await redisClient.del(`user:${email}:course:${courseCode}:${clss}`);
            } else {
              console.warn("토큰에 포함된 이메일과 사용자 이메일이 일치하지 않습니다. Redis 키 삭제를 건너뜁니다.");
            }
          } catch (err) {
            console.error("토큰 검증 중 오류 발생:", err);
          }
        }
      }
    }

    // 5) 쿠키 제거
    res.clearCookie('jcodeAt', {
      domain: COOKIE_DOMAIN,
      path: '/'
    });
    res.clearCookie('jcode-uuid', {
      domain: COOKIE_DOMAIN,
      path: '/'
    });

    return res.status(200).send("Logged out");
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
    try {
      jwt.verify(token, JWT_SECRET);
    } catch (err) {
      socket.write('HTTP/1.1 403 Forbidden\r\n\r\nInvalid access token');
      socket.destroy();
      return;
    }

    const jcodeUuid = cookies['jcode-uuid'];
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
    const { courseCode, clss, email, snapshot } = userProfile;
    const redisKeyForTarget = (snapshot === 'true' || snapshot === true)
      ? `user:${email}:course:${courseCode}:${clss}:snapshot`
      : `user:${email}:course:${courseCode}:${clss}`;
    const ideTargetUrl = await redisClient.get(redisKeyForTarget);
    if (!ideTargetUrl) {
      socket.write('HTTP/1.1 403 Forbidden\r\n\r\nMissing targetUrl in Redis');
      socket.destroy();
      return;
    }
    let wsTargetUrl = ideTargetUrl
      .replace(/^http:/, 'ws:')
      .replace(/^https:/, 'wss:');

    if (req.url.startsWith('/websockify')) {
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
