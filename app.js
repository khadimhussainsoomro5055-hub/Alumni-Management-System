const fs = require("fs");
const path = require("path");
const envFile = path.join(__dirname, ".env");
if (fs.existsSync(envFile)) {
  for (const line of fs.readFileSync(envFile, "utf8").split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const index = trimmed.indexOf("=");
    if (index < 1) continue;
    const key = trimmed.slice(0, index).trim();
    const value = trimmed.slice(index + 1).trim().replace(/^(['"])(.*)\1$/, "$2");
    if (process.env[key] === undefined) process.env[key] = value;
  }
}

const express = require("express");
const mysql = require("mysql2/promise");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const multer = require("multer");
const crypto = require("crypto");

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const db = mysql.createPool({
  host: process.env.DB_HOST || "localhost",
  port: Number(process.env.DB_PORT) || 3306,
  user: process.env.DB_USER || "root",
  password: process.env.DB_PASSWORD || "",
  database: process.env.DB_NAME || "alumni_system",
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.disable("x-powered-by");
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  next();
});
app.use(express.urlencoded({ extended: true, limit: "30kb" }));
app.use(express.static(path.join(__dirname, "public")));

if (process.env.NODE_ENV === "production" && (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32)) {
  throw new Error("Production requires SESSION_SECRET with at least 32 characters.");
}
if (process.env.NODE_ENV !== "production" && (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32)) {
  console.warn("Set SESSION_SECRET in .env to a random value of at least 32 characters.");
}
if (process.env.NODE_ENV === "production") app.set("trust proxy", 1);
class MySQLSessionStore extends session.Store {
  get(sid, callback) {
    db.execute("SELECT data FROM app_sessions WHERE session_id=? AND expires_at > NOW()", [sid])
      .then(([rows]) => callback(null, rows.length ? JSON.parse(rows[0].data) : null))
      .catch(callback);
  }
  set(sid, value, callback = () => {}) {
    const expires = value.cookie && value.cookie.expires ? new Date(value.cookie.expires) : new Date(Date.now() + 8 * 60 * 60 * 1000);
    db.execute("INSERT INTO app_sessions(session_id,data,expires_at) VALUES(?,?,?) ON DUPLICATE KEY UPDATE data=VALUES(data), expires_at=VALUES(expires_at)",
      [sid, JSON.stringify(value), expires]).then(() => callback(null)).catch(callback);
  }
  destroy(sid, callback = () => {}) {
    db.execute("DELETE FROM app_sessions WHERE session_id=?", [sid]).then(() => callback(null)).catch(callback);
  }
  touch(sid, value, callback = () => {}) { this.set(sid, value, callback); }
}
const sessionStore = new MySQLSessionStore();
app.use(session({
  name: "alumni.sid",
  secret: process.env.SESSION_SECRET || "development-only-change-this-secret-please",
  store: sessionStore,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 8 * 60 * 60 * 1000
  }
}));

// Session-bound CSRF token for every state-changing form submission.
function verifyCsrf(req, res, next) {
  const supplied = req.body && req.body._csrf;
  if (typeof supplied !== "string" || supplied !== req.session.csrfToken) {
    return res.status(403).send("Invalid or missing security token. Refresh the page and try again.");
  }
  next();
}
app.use((req, res, next) => {
  if (!req.session.csrfToken) req.session.csrfToken = crypto.randomBytes(32).toString("hex");
  res.locals.csrfToken = req.session.csrfToken;
  if (req.method === "POST" && req.path !== "/profile") return verifyCsrf(req, res, next);
  next();
});
const loginAttempts = new Map();
function authLimiter(req, res, next) {
  const key = req.ip + ":" + (req.path === "/signin" ? String(req.body.email || "").toLowerCase() : "signup");
  const now = Date.now();
  const entry = loginAttempts.get(key);
  if (!entry || now - entry.startedAt > 15 * 60 * 1000) {
    loginAttempts.set(key, { startedAt: now, count: 1 });
    return next();
  }
  if (entry.count >= 10) return res.status(429).send("Too many attempts. Please try again in 15 minutes.");
  entry.count += 1;
  next();
}

const uploadDir = path.join(__dirname, "public", "uploads", "profiles");
fs.mkdirSync(uploadDir, { recursive: true });
const upload = multer({
  storage: multer.diskStorage({
    destination: (_, __, cb) => cb(null, uploadDir),
    filename: (_, file, cb) => cb(null, "profile-" + Date.now() + "-" + Math.round(Math.random() * 1e9) + path.extname(file.originalname).toLowerCase())
  }),
  limits: { fileSize: 2 * 1024 * 1024, files: 1 },
  fileFilter: (_, file, cb) => {
    if (["image/jpeg", "image/png", "image/webp"].includes(file.mimetype)) return cb(null, true);
    cb(new Error("Only JPG, PNG and WEBP images are allowed."));
  }
});

function auth(req, res, next) {
  if (!req.session.user) return res.redirect("/signin");
  next();
}
function adminOnly(req, res, next) {
  if (!req.session.user) return res.redirect("/signin");
  if (req.session.user.role !== "admin") return res.status(403).send("Administrator access required.");
  next();
}
function validYear(value) {
  const year = Number(value);
  return Number.isInteger(year) && year >= 1950 && year <= new Date().getFullYear() + 10;
}
function removePhoto(photo) {
  if (!photo || !photo.startsWith("/uploads/profiles/")) return;
  const fullPath = path.join(uploadDir, path.basename(photo));
  if (fs.existsSync(fullPath)) fs.unlinkSync(fullPath);
}
async function validateImage(file) {
  if (!file) return true;
  const handle = await fs.promises.open(file.path, "r");
  try {
    const header = Buffer.alloc(12);
    await handle.read(header, 0, 12, 0);
    const jpeg = header[0] === 255 && header[1] === 216 && header[2] === 255;
    const png = header.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]));
    const webp = header.toString("ascii", 0, 4) === "RIFF" && header.toString("ascii", 8, 12) === "WEBP";
    return jpeg || png || webp;
  } finally {
    await handle.close();
  }
}
app.use((req, res, next) => {
  res.locals.currentPath = req.path;
  res.locals.sessionUser = req.session.user || null;
  next();
});

app.get("/", (req, res) => res.redirect(req.session.user ? (req.session.user.role === "admin" ? "/admin" : "/dashboard") : "/signin"));
app.get("/signup", (req, res) => res.render("signup", { title: "Create Account", error: null }));
app.post("/signup", authLimiter, async (req, res, next) => {
  try {
    const p = req.body;
    if (!p.full_name?.trim() || !p.email?.trim() || !p.department?.trim() || !validYear(p.graduation_year) || !p.password) {
      return res.status(400).render("signup", { title: "Create Account", error: "Enter your name, email, department, a valid graduation year and password." });
    }
    if (p.password.length < 8) return res.status(400).render("signup", { title: "Create Account", error: "Password must be at least 8 characters." });
    const email = p.email.trim().toLowerCase();
    const [exists] = await db.execute("SELECT id FROM alumni WHERE email = ?", [email]);
    if (exists.length) return res.status(409).render("signup", { title: "Create Account", error: "Email already registered." });
    const hash = await bcrypt.hash(p.password, 12);
    await db.execute("INSERT INTO alumni(full_name,email,graduation_year,department,password) VALUES(?,?,?,?,?)",
      [p.full_name.trim(), email, p.graduation_year, p.department.trim(), hash]);
    res.redirect("/signin?registered=1");
  } catch (err) { next(err); }
});

app.get("/signin", (req, res) => {
  if (req.session.user) return res.redirect(req.session.user.role === "admin" ? "/admin" : "/dashboard");
  res.render("signin", { title: "Sign In", error: null, message: req.query.registered ? "Account created successfully. Please sign in." : null });
});
app.post("/signin", authLimiter, async (req, res, next) => {
  try {
    const email = (req.body.email || "").trim().toLowerCase();
    const password = req.body.password || "";
    const [rows] = await db.execute("SELECT id,full_name,email,password,profile_photo,role FROM alumni WHERE email=? LIMIT 1", [email]);
    if (!rows.length || !(await bcrypt.compare(password, rows[0].password))) {
      return res.status(401).render("signin", { title: "Sign In", error: "Invalid email or password.", message: null });
    }
    const user = rows[0];
    req.session.regenerate(err => {
      if (err) return next(err);
      req.session.user = { id: user.id, full_name: user.full_name, email: user.email, profile_photo: user.profile_photo, role: user.role || "alumni" };
      req.session.save(saveErr => {
        if (saveErr) return next(saveErr);
        res.redirect(user.role === "admin" ? "/admin" : "/dashboard");
      });
    });
  } catch (err) { next(err); }
});
app.post("/logout", auth, (req, res, next) => {
  req.session.destroy(err => {
    if (err) return next(err);
    res.clearCookie("alumni.sid");
    res.redirect("/signin");
  });
});

app.get("/dashboard", auth, async (req, res, next) => {
  try {
    const [[stats]] = await db.query("SELECT (SELECT COUNT(*) FROM alumni) total_alumni,(SELECT COUNT(*) FROM events) total_events,(SELECT COUNT(*) FROM jobs) total_jobs");
    const [recent] = await db.query("SELECT id,full_name,department,graduation_year,profile_photo FROM alumni ORDER BY id DESC LIMIT 5");
    res.render("dashboard", { title: "Dashboard", stats, recent });
  } catch (err) { next(err); }
});
app.get("/alumni", auth, async (req, res, next) => {
  try {
    const search = String(req.query.search || "").trim().slice(0, 100);
    const page = Math.max(1, Number.parseInt(req.query.page, 10) || 1);
    const pageSize = 12;
    const offset = (page - 1) * pageSize;
    let sql = "SELECT id,full_name,email,phone,department,graduation_year,current_job,company,city,country,profile_photo FROM alumni";
    let countSql = "SELECT COUNT(*) AS total FROM alumni";
    const params = [];
    const countParams = [];
    if (search) {
      const where = " WHERE full_name LIKE ? OR email LIKE ? OR department LIKE ? OR current_job LIKE ? OR city LIKE ?";
      sql += where;
      countSql += where;
      const term = "%" + search + "%";
      params.push(term, term, term, term, term);
      countParams.push(term, term, term, term, term);
    }
    sql += " ORDER BY full_name LIMIT ? OFFSET ?";
    params.push(pageSize, offset);
    const [[count]] = await db.execute(countSql, countParams);
    const [alumni] = await db.execute(sql, params);
    res.render("alumni", { title: "Alumni Directory", alumni, search, page, totalPages: Math.max(1, Math.ceil(count.total / pageSize)) });
  } catch (err) { next(err); }
});

app.get("/profile", auth, async (req, res, next) => {
  try {
    const [rows] = await db.execute("SELECT * FROM alumni WHERE id=?", [req.session.user.id]);
    if (!rows.length) return res.status(404).send("Profile not found.");
    res.render("profile", { title: "My Profile", profile: rows[0], message: req.query.passwordChanged ? "Password changed successfully." : (req.query.updated ? "Profile updated successfully." : null) });
  } catch (err) { next(err); }
});
app.post("/profile", auth, upload.single("profile_photo"), verifyCsrf, async (req, res, next) => {
  const p = req.body;
  let newPhoto = req.file ? "/uploads/profiles/" + req.file.filename : null;
  try {
    if (!p.full_name?.trim() || !p.department?.trim() || !validYear(p.graduation_year)) {
      if (req.file) await fs.promises.unlink(req.file.path).catch(() => {});
      return res.status(400).send("Name, department and a valid graduation year are required.");
    }
    if (req.file && !(await validateImage(req.file))) {
      await fs.promises.unlink(req.file.path).catch(() => {});
      return res.status(400).send("The uploaded file is not a valid JPG, PNG or WEBP image.");
    }
    const [rows] = await db.execute("SELECT profile_photo FROM alumni WHERE id=?", [req.session.user.id]);
    if (!rows.length) {
      if (req.file) await fs.promises.unlink(req.file.path).catch(() => {});
      return res.status(404).send("Profile not found.");
    }
    const oldPhoto = rows[0].profile_photo;
    const photo = newPhoto || oldPhoto || null;
    await db.execute("UPDATE alumni SET full_name=?,phone=?,gender=?,date_of_birth=?,student_id=?,degree=?,department=?,graduation_year=?,current_job=?,company=?,city=?,country=?,address=?,profile_photo=? WHERE id=?",
      [p.full_name.trim(), p.phone || null, p.gender || null, p.date_of_birth || null, p.student_id || null, p.degree || null,
       p.department.trim(), p.graduation_year, p.current_job || null, p.company || null, p.city || null, p.country || "Pakistan",
       p.address || null, photo, req.session.user.id]);
    if (newPhoto) removePhoto(oldPhoto);
    req.session.user.full_name = p.full_name.trim();
    req.session.user.profile_photo = photo;
    res.redirect("/profile?updated=1");
  } catch (err) {
    if (req.file) await fs.promises.unlink(req.file.path).catch(() => {});
    next(err);
  }
});

app.get("/events", auth, async (req, res, next) => {
  try { const [events] = await db.query("SELECT * FROM events ORDER BY event_date ASC"); res.render("events", { title: "Events", events }); }
  catch (err) { next(err); }
});
app.get("/jobs", auth, async (req, res, next) => {
  try { const [jobs] = await db.query("SELECT * FROM jobs ORDER BY posted_at DESC"); res.render("jobs", { title: "Jobs & Opportunities", jobs }); }
  catch (err) { next(err); }
});

// Authenticated password change.
app.get("/change-password", auth, (req, res) => res.render("change-password", { title: "Change Password", error: null }));
app.post("/change-password", auth, async (req, res, next) => {
  try {
    const { current_password, new_password, confirm_password } = req.body;
    if (!current_password || !new_password || new_password.length < 8 || new_password !== confirm_password) {
      return res.status(400).render("change-password", { title: "Change Password", error: "Enter your current password and matching new passwords (at least 8 characters)." });
    }
    const [rows] = await db.execute("SELECT password FROM alumni WHERE id=?", [req.session.user.id]);
    if (!rows.length || !(await bcrypt.compare(current_password, rows[0].password))) {
      return res.status(400).render("change-password", { title: "Change Password", error: "Current password is incorrect." });
    }
    const hash = await bcrypt.hash(new_password, 12);
    await db.execute("UPDATE alumni SET password=? WHERE id=?", [hash, req.session.user.id]);
    const user = req.session.user;
    req.session.regenerate(err => {
      if (err) return next(err);
      req.session.user = user;
      req.session.csrfToken = crypto.randomBytes(32).toString("hex");
      req.session.save(saveErr => saveErr ? next(saveErr) : res.redirect("/profile?passwordChanged=1"));
    });
  } catch (err) { next(err); }
});

// Admin dashboard: management links for all three data types.
app.get("/admin", adminOnly, async (req, res, next) => {
  try {
    const [[stats]] = await db.query("SELECT (SELECT COUNT(*) FROM alumni) alumni_count,(SELECT COUNT(*) FROM events) event_count,(SELECT COUNT(*) FROM jobs) job_count");
    const [alumni] = await db.query("SELECT id,full_name,email,department,graduation_year,role FROM alumni ORDER BY id DESC");
    const [events] = await db.query("SELECT * FROM events ORDER BY event_date DESC");
    const [jobs] = await db.query("SELECT * FROM jobs ORDER BY posted_at DESC");
    res.render("admin", { title: "Admin Dashboard", stats, alumni, events, jobs });
  } catch (err) { next(err); }
});

// Alumni update/delete. New alumni accounts are created through public signup.
app.get("/admin/alumni/:id/edit", adminOnly, async (req, res, next) => {
  try {
    const [rows] = await db.execute("SELECT id,full_name,email,phone,gender,date_of_birth,student_id,degree,department,graduation_year,current_job,company,city,country,address,role FROM alumni WHERE id=?", [req.params.id]);
    if (!rows.length) return res.status(404).send("Alumni record not found.");
    res.render("admin-alumni-edit", { title: "Edit Alumni", person: rows[0] });
  } catch (err) { next(err); }
});
app.post("/admin/alumni/:id", adminOnly, async (req, res, next) => {
  try {
    const p = req.body;
    if (!p.full_name?.trim() || p.full_name.trim().length > 150 || !p.department?.trim() || p.department.trim().length > 150 || !validYear(p.graduation_year)) return res.status(400).send("Enter a name and department (maximum 150 characters) and a valid graduation year.");
    const [[adminCount]] = await db.execute("SELECT COUNT(*) AS total FROM alumni WHERE role='admin'");
    const [targetRows] = await db.execute("SELECT role FROM alumni WHERE id=?", [req.params.id]);
    if (!targetRows.length) return res.status(404).send("Alumni record not found.");
    if (targetRows[0].role === "admin" && p.role !== "admin" && adminCount.total <= 1) {
      return res.status(400).send("The last administrator cannot be demoted.");
    }
    await db.execute("UPDATE alumni SET full_name=?,phone=?,gender=?,date_of_birth=?,student_id=?,degree=?,department=?,graduation_year=?,current_job=?,company=?,city=?,country=?,address=?,role=? WHERE id=?",
      [p.full_name.trim(), p.phone || null, p.gender || null, p.date_of_birth || null, p.student_id || null, p.degree || null,
       p.department.trim(), p.graduation_year, p.current_job || null, p.company || null, p.city || null, p.country || "Pakistan",
       p.address || null, p.role === "admin" ? "admin" : "alumni", req.params.id]);
    if (Number(req.params.id) === Number(req.session.user.id) && p.role !== "admin") {
      req.session.user.role = "alumni";
      return req.session.save(() => res.redirect("/dashboard"));
    }
    res.redirect("/admin");
  } catch (err) { next(err); }
});
app.post("/admin/alumni/:id/delete", adminOnly, async (req, res, next) => {
  try {
    if (Number(req.params.id) === Number(req.session.user.id)) return res.status(400).send("You cannot delete your own administrator account.");
    const [rows] = await db.execute("SELECT profile_photo FROM alumni WHERE id=?", [req.params.id]);
    if (!rows.length) return res.status(404).send("Alumni record not found.");
    await db.execute("DELETE FROM alumni WHERE id=?", [req.params.id]);
    removePhoto(rows[0].profile_photo);
    res.redirect("/admin");
  } catch (err) { next(err); }
});

// Shared create/edit form for events and jobs.
app.get("/admin/events/new", adminOnly, (req, res) => res.render("admin-listing-form", { title: "Add Event", kind: "event", item: null }));
app.get("/admin/events/:id/edit", adminOnly, async (req, res, next) => {
  try { const [rows] = await db.execute("SELECT * FROM events WHERE id=?", [req.params.id]); if (!rows.length) return res.status(404).send("Event not found."); res.render("admin-listing-form", { title: "Edit Event", kind: "event", item: rows[0] }); }
  catch (err) { next(err); }
});
app.post("/admin/events", adminOnly, async (req, res, next) => {
  try {
    const p = req.body;
    if (!p.title?.trim() || !p.event_date || !p.location?.trim() || Number.isNaN(Date.parse(p.event_date))) return res.status(400).send("Enter a valid event title, date and location.");
    await db.execute("INSERT INTO events(title,event_date,location,description) VALUES(?,?,?,?)", [p.title.trim(), p.event_date, p.location.trim(), p.description || null]);
    res.redirect("/admin");
  } catch (err) { next(err); }
});
app.post("/admin/events/:id", adminOnly, async (req, res, next) => {
  try {
    const p = req.body;
    if (!p.title?.trim() || !p.event_date || !p.location?.trim() || Number.isNaN(Date.parse(p.event_date))) return res.status(400).send("Enter a valid event title, date and location.");
    const [result] = await db.execute("UPDATE events SET title=?,event_date=?,location=?,description=? WHERE id=?", [p.title.trim(), p.event_date, p.location.trim(), p.description || null, req.params.id]);
    if (!result.affectedRows) return res.status(404).send("Event not found.");
    res.redirect("/admin");
  } catch (err) { next(err); }
});
app.post("/admin/events/:id/delete", adminOnly, async (req, res, next) => {
  try { await db.execute("DELETE FROM events WHERE id=?", [req.params.id]); res.redirect("/admin"); }
  catch (err) { next(err); }
});

app.get("/admin/jobs/new", adminOnly, (req, res) => res.render("admin-listing-form", { title: "Add Job", kind: "job", item: null }));
app.get("/admin/jobs/:id/edit", adminOnly, async (req, res, next) => {
  try { const [rows] = await db.execute("SELECT * FROM jobs WHERE id=?", [req.params.id]); if (!rows.length) return res.status(404).send("Job not found."); res.render("admin-listing-form", { title: "Edit Job", kind: "job", item: rows[0] }); }
  catch (err) { next(err); }
});
app.post("/admin/jobs", adminOnly, async (req, res, next) => {
  try {
    const p = req.body;
    if (!p.title?.trim() || !p.company?.trim()) return res.status(400).send("Job title and company are required.");
    await db.execute("INSERT INTO jobs(title,company,location,description) VALUES(?,?,?,?)", [p.title.trim(), p.company.trim(), p.location || null, p.description || null]);
    res.redirect("/admin");
  } catch (err) { next(err); }
});
app.post("/admin/jobs/:id", adminOnly, async (req, res, next) => {
  try {
    const p = req.body;
    if (!p.title?.trim() || !p.company?.trim()) return res.status(400).send("Job title and company are required.");
    const [result] = await db.execute("UPDATE jobs SET title=?,company=?,location=?,description=? WHERE id=?", [p.title.trim(), p.company.trim(), p.location || null, p.description || null, req.params.id]);
    if (!result.affectedRows) return res.status(404).send("Job not found.");
    res.redirect("/admin");
  } catch (err) { next(err); }
});
app.post("/admin/jobs/:id/delete", adminOnly, async (req, res, next) => {
  try { await db.execute("DELETE FROM jobs WHERE id=?", [req.params.id]); res.redirect("/admin"); }
  catch (err) { next(err); }
});

app.use((err, req, res, next) => {
  console.error(err);
  if (req.file) fs.promises.unlink(req.file.path).catch(() => {});
  if (err instanceof multer.MulterError) return res.status(400).send(err.code === "LIMIT_FILE_SIZE" ? "Profile image must be 2 MB or smaller." : err.message);
  if (err.code === "ER_DUP_ENTRY") return res.status(409).send("That email or student ID is already registered.");
  if (err.code === "ER_NO_SUCH_TABLE" || err.code === "ER_BAD_FIELD_ERROR") return res.status(500).send("Database schema is outdated. Import the latest database.sql file.");
  res.status(500).send("Something went wrong. Check the server logs.");
});
app.use((req, res) => res.status(404).send("Page not found."));

async function start() {
  try {
    await db.query("SELECT 1");
    await db.query("CREATE TABLE IF NOT EXISTS app_sessions (session_id VARCHAR(128) NOT NULL PRIMARY KEY, data MEDIUMTEXT NOT NULL, expires_at DATETIME NOT NULL, INDEX idx_app_sessions_expiry (expires_at))");
    await db.query("DELETE FROM app_sessions WHERE expires_at <= NOW()");
    console.log("Connected to MySQL.");
    app.listen(PORT, () => console.log("Server listening on http://localhost:" + PORT));
  } catch (err) {
    console.error("MySQL connection failed:", err.message);
    process.exit(1);
  }
}
if (require.main === module) start();
module.exports = { app, db, start };
