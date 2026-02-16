import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import request from 'supertest';

const dbPath = path.join(process.cwd(), 'data', 'test.db');
process.env.NODE_ENV = 'test';
process.env.DB_PATH = dbPath;
process.env.JWT_ACCESS_SECRET = 'test-access-secret';
process.env.JWT_REFRESH_SECRET = 'test-refresh-secret';

if (fs.existsSync(dbPath)) fs.unlinkSync(dbPath);

const { createServer } = await import('./server.js');
const app = await createServer();

async function register(email, password) {
  const res = await request(app).post('/auth/register').send({ email, password });
  return res.body;
}

test('register/login and create notes', async () => {
  const reg = await register('admin@example.com', 'password1234');
  assert.equal(reg.user.role, 'admin');
  assert.ok(reg.accessToken);

  const login = await request(app).post('/auth/login').send({ email: 'admin@example.com', password: 'password1234' });
  assert.equal(login.status, 200);

  const create = await request(app)
    .post('/notes')
    .set('Authorization', `Bearer ${login.body.accessToken}`)
    .send({ title: 'Private', content: 'hello' });

  assert.equal(create.status, 201);
  assert.equal(create.body.title, 'Private');
});

test('authorization: user cannot access other user notes', async () => {
  const u1 = await register('u1@example.com', 'password1234');
  const u2 = await register('u2@example.com', 'password1234');

  const created = await request(app)
    .post('/notes')
    .set('Authorization', `Bearer ${u1.accessToken}`)
    .send({ title: 'u1 note' });

  const stolen = await request(app)
    .get(`/notes/${created.body.id}`)
    .set('Authorization', `Bearer ${u2.accessToken}`);

  assert.equal(stolen.status, 404);
});

test('admin endpoint blocked for non-admin', async () => {
  const usr = await register('plain@example.com', 'password1234');
  const res = await request(app).get('/admin/users').set('Authorization', `Bearer ${usr.accessToken}`);
  assert.equal(res.status, 403);
});
