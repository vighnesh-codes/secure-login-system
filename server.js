require("dotenv").config();

const path = require("path");
const express = require("express");
const session = require("express-session");
const SQLiteStoreFactory = require("connect-sqlite3");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcrypt");
const db = require("./database/db");
const { requireAuth, redirectIfAuth } = require("./middleware/auth");

const app = express();
const SQLiteStore = SQLiteStoreFactory(session);
const PORT = Number(process.env.PORT || 3000);
const isProduction = process.env.NODE_ENV === "production";

if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
  console.error("SESSION_SECRET is missing or too short. Copy .env.example to .env and set a random secret of at least 32 characters.");
  process.exit(1);
}

if (isProduction) app.set("trust proxy", 1);

app.disable("x-powered-by");
app.use(helmet());
app.use(express.json({ limit: "10kb" }));
app.use(express.urlencoded({ extended: false, limit: "10kb" }));

app.use(session({
  name: "secure_login.sid",
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: new SQLiteStore({
    db: "sessions.sqlite",
    dir: path.join(__dirname, "database")
  }),
  cookie: {
    httpOnly: true,
    secure: isProduction,
    sameSite: "lax",
    maxAge: 1000 * 60 * 60 * 2
  }
}));

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { error: "Too many login attempts. Please try again in 15 minutes." }
});

const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { error: "Too many registration attempts. Please try again later." }
});

app.use(express.static(path.join(__dirname, "public")));

function validEmail(email) {
  return typeof email === "string" &&
    email.length <= 254 &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function validPassword(password) {
  return typeof password === "string" &&
    password.length >= 10 &&
    password.length <= 72;
}

function regenerateSession(req) {
  return new Promise((resolve, reject) => {
    req.session.regenerate(err => err ? reject(err) : resolve());
  });
}

function saveSession(req) {
  return new Promise((resolve, reject) => {
    req.session.save(err => err ? reject(err) : resolve());
  });
}

app.post("/api/register", registerLimiter, async (req, res, next) => {
  try {
    const name = typeof req.body.name === "string" ? req.body.name.trim() : "";
    const email = typeof req.body.email === "string" ? req.body.email.trim().toLowerCase() : "";
    const password = req.body.password;

    if (name.length < 2 || name.length > 60) {
      return res.status(400).json({ error: "Name must be between 2 and 60 characters." });
    }
    if (!validEmail(email)) {
      return res.status(400).json({ error: "Enter a valid email address." });
    }
    if (!validPassword(password)) {
      return res.status(400).json({ error: "Password must be 10–72 characters long." });
    }

    const existing = db.prepare("SELECT id FROM users WHERE email = ?").get(email);
    if (existing) {
      return res.status(409).json({ error: "An account with this email already exists." });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const result = db.prepare(
      "INSERT INTO users (name, email, password_hash, created_at) VALUES (?, ?, ?, ?)"
    ).run(name, email, passwordHash, new Date().toISOString());

    await regenerateSession(req);
    req.session.user = { id: Number(result.lastInsertRowid), name, email };
    await saveSession(req);

    return res.status(201).json({ message: "Account created successfully.", user: req.session.user });
  } catch (error) {
    if (error && error.code === "SQLITE_CONSTRAINT_UNIQUE") {
      return res.status(409).json({ error: "An account with this email already exists." });
    }
    next(error);
  }
});

app.post("/api/login", loginLimiter, async (req, res, next) => {
  try {
    const email = typeof req.body.email === "string" ? req.body.email.trim().toLowerCase() : "";
    const password = req.body.password;

    if (!validEmail(email) || typeof password !== "string" || password.length > 72) {
      return res.status(400).json({ error: "Enter a valid email and password." });
    }

    const user = db.prepare(
      "SELECT id, name, email, password_hash FROM users WHERE email = ?"
    ).get(email);

    // Use the same message for unknown email and incorrect password.
    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: "Invalid email or password." });
    }

    await regenerateSession(req);
    req.session.user = { id: user.id, name: user.name, email: user.email };
    await saveSession(req);

    return res.json({ message: "Login successful.", user: req.session.user });
  } catch (error) {
    next(error);
  }
});

app.get("/api/me", requireAuth, (req, res) => {
  res.json({ user: req.session.user });
});

app.post("/api/logout", requireAuth, (req, res, next) => {
  req.session.destroy(error => {
    if (error) return next(error);
    res.clearCookie("secure_login.sid", {
      httpOnly: true,
      secure: isProduction,
      sameSite: "lax"
    });
    res.json({ message: "You have been logged out." });
  });
});

app.get("/dashboard", requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "dashboard.html"));
});

app.get("/login", redirectIfAuth, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.get("/register", redirectIfAuth, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "register.html"));
});

app.use((req, res) => {
  res.status(404).sendFile(path.join(__dirname, "public", "404.html"), err => {
    if (err && !res.headersSent) res.status(404).send("Page not found.");
  });
});

app.use((error, req, res, next) => {
  console.error(error);
  if (res.headersSent) return next(error);
  res.status(500).json({ error: "An unexpected server error occurred." });
});

app.listen(PORT, () => {
  console.log(`Secure Login System running at http://localhost:${PORT}`);
});
