const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const root = path.join(__dirname, "..");
const read = (file) => fs.readFileSync(path.join(root, file), "utf8");

test("state-changing routes have session CSRF protection", () => {
  const app = read("app.js");
  assert.match(app, /function verifyCsrf/);
  assert.match(app, /req\.method === "POST"/);
  assert.match(app, /upload\.single\("profile_photo"\), verifyCsrf/);
});

test("session persistence is backed by MySQL", () => {
  const app = read("app.js");
  assert.match(app, /class MySQLSessionStore extends session\.Store/);
  assert.match(app, /CREATE TABLE IF NOT EXISTS app_sessions/);
});

test("authentication protections and password change route exist", () => {
  const app = read("app.js");
  assert.match(app, /function authLimiter/);
  assert.match(app, /app\.post\("\/signin", authLimiter/);
  assert.match(app, /app\.post\("\/change-password"/);
});

test("admin forms submit valid actions and CSRF tokens", () => {
  const admin = read("views/admin.ejs");
  const listing = read("views/admin-listing-form.ejs");
  const alumniEdit = read("views/admin-alumni-edit.ejs");
  assert.match(admin, /action="\/admin\/alumni\/<%= person\.id %>\/delete"/);
  assert.match(admin, /action="\/admin\/events\/<%= event\.id %>\/delete"/);
  assert.match(admin, /action="\/admin\/jobs\/<%= job\.id %>\/delete"/);
  for (const view of [admin, listing, alumniEdit]) assert.match(view, /name="_csrf"/);
  assert.doesNotMatch(listing, /action="[^"]*<input/);
});

test("directory supports bounded pagination and preserves search", () => {
  const app = read("app.js");
  const view = read("views/alumni.ejs");
  assert.match(app, /const pageSize = 12/);
  assert.match(app, /LIMIT \? OFFSET \?/);
  assert.match(view, /totalPages/);
  assert.match(view, /encodeURIComponent\(search\)/);
});

test("signup password minimum matches server validation", () => {
  const app = read("app.js");
  const view = read("views/signup.ejs");
  assert.match(app, /p\.password\.length < 8/);
  assert.match(view, /minlength="8"/);
});

test("registration and contact forms are integrated with SMTP", () => {
  const app = read("app.js");
  const contact = read("views/contact.ejs");
  const signup = read("views/signup.ejs");
  assert.match(app, /nodemailer\.createTransport/);
  assert.match(app, /await sendMail\(/);
  assert.match(app, /app\.post\("\/contact"/);
  assert.match(app, /app\.post\("\/signup"/);
  assert.match(contact, /action="\/contact"/);
  assert.match(contact, /name="_csrf"/);
  assert.match(signup, /action="\/signup"/);
});
