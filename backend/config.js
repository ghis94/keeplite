import crypto from 'node:crypto';

function int(value, fallback) {
  const parsed = Number.parseInt(value, 10);
  return Number.isNaN(parsed) ? fallback : parsed;
}

const secureCookieDefault = process.env.NODE_ENV === 'production';

export const config = {
  env: process.env.NODE_ENV || 'development',
  port: int(process.env.PORT, 4000),
  dbPath: process.env.DB_PATH || './data/keep.db',
  clientOrigin: (process.env.CLIENT_ORIGIN || 'http://localhost:5173').split(',').map((s) => s.trim()).filter(Boolean),
  jwtAccessSecret: process.env.JWT_ACCESS_SECRET || `dev-access-${crypto.randomBytes(16).toString('hex')}`,
  jwtRefreshSecret: process.env.JWT_REFRESH_SECRET || `dev-refresh-${crypto.randomBytes(16).toString('hex')}`,
  accessTokenTtlSec: int(process.env.ACCESS_TOKEN_TTL_SEC, 900),
  refreshTokenTtlSec: int(process.env.REFRESH_TOKEN_TTL_SEC, 604800),
  cookieSecure: process.env.COOKIE_SECURE ? process.env.COOKIE_SECURE === 'true' : secureCookieDefault,
  cookieSameSite: process.env.COOKIE_SAMESITE || 'lax',
  bcryptRounds: int(process.env.BCRYPT_ROUNDS, 12),
  payloadLimit: process.env.PAYLOAD_LIMIT || '256kb',
  rateLimitWindowMs: int(process.env.RATE_LIMIT_WINDOW_MS, 60000),
  rateLimitMax: int(process.env.RATE_LIMIT_MAX, 120),
  authRateLimitMax: int(process.env.AUTH_RATE_LIMIT_MAX, 20)
};
