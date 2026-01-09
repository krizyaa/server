const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const multer = require("multer");

const app = express();

const PORT = process.env.PORT ? Number(process.env.PORT) : 5057;
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_123";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "change_me";
const TOKEN_TTL_SECONDS = 60 * 60 * 24;
const SESSION_TTL_SECONDS = process.env.SESSION_TTL_SECONDS ? Number(process.env.SESSION_TTL_SECONDS) : 120;
const PROTECTED_MOD_REGEX = process.env.PROTECTED_MOD_REGEX ? new RegExp(process.env.PROTECTED_MOD_REGEX, "i") : /^floravisuals-.*\.jar$/i;

const MODS_BASE_URL = process.env.MODS_BASE_URL ? String(process.env.MODS_BASE_URL).replace(/\/+$/, "") : null;

const PROTECTED_MOD_SHA256 = process.env.PROTECTED_MOD_SHA256
  ? String(process.env.PROTECTED_MOD_SHA256).trim().toLowerCase()
  : null;

const MODS_LIST_RAW = process.env.MODS_LIST ? String(process.env.MODS_LIST).trim() : "";

const DB_PATH = process.env.DB_PATH ? String(process.env.DB_PATH) : path.join(__dirname, "db.json");
const PUBLIC_DIR = path.join(__dirname, "public");
const MODS_DIR = process.env.MODS_DIR ? String(process.env.MODS_DIR) : path.join(__dirname, "mods");
const ADMIN_FILE = path.join(PUBLIC_DIR, "admin.html");

app.use(cors());
app.use(express.json({ limit: "512kb" }));
// Hide admin UI file from static hosting (return 404)
app.use((req, res, next) => {
  if (req.path === "/admin.html") return res.status(404).end();
  next();
});

app.use(express.static(PUBLIC_DIR));
app.use("/mods", express.static(MODS_DIR));

function parseCookies(header) {
  const out = {};
  if (!header) return out;
  const parts = header.split(";");
  for (const p of parts) {
    const idx = p.indexOf("=");
    if (idx < 0) continue;
    const k = p.slice(0, idx).trim();
    const v = decodeURIComponent(p.slice(idx + 1).trim());
    out[k] = v;
  }
  return out;
}

function ensureDb() {
  if (!fs.existsSync(DB_PATH)) {
    fs.writeFileSync(DB_PATH, JSON.stringify({ keys: [] }, null, 2), "utf8");
  }
}

function getModsListFromEnv() {
  if (!MODS_LIST_RAW) return null;
  try {
    // Allow JSON: ["a.jar","b.jar"]
    const parsed = JSON.parse(MODS_LIST_RAW);
    if (Array.isArray(parsed)) {
      const items = parsed
        .filter((x) => typeof x === "string")
        .map((s) => s.trim())
        .filter(Boolean);
      return items.length ? items : null;
    }
  } catch {
    // ignore
  }

  // Fallback: comma / newline separated list
  const items = MODS_LIST_RAW
    .split(/[,\n\r]+/)
    .map((s) => s.trim())
    .filter(Boolean);
  return items.length ? items : null;
}

function readDb() {
  ensureDb();
  const raw = fs.readFileSync(DB_PATH, "utf8");
  const data = JSON.parse(raw);
  if (!data || typeof data !== "object") return { keys: [] };
  if (!Array.isArray(data.keys)) data.keys = [];
  data.keys = data.keys
    .map((k) => (typeof k === "string" ? { key: k, createdAt: null } : k))
    .filter((k) => k && typeof k.key === "string" && k.key.trim() !== "")
    .map((k) => ({
      key: String(k.key).trim(),
      createdAt: k.createdAt || null,
      expiresAt: k.expiresAt || null,
      // legacy: "hwid" (string) may exist
      hwid: k.hwid || null,
      // new: hardware fingerprint (string)
      hwidFingerprint: k.hwidFingerprint || null,
      firstUsedAt: k.firstUsedAt || null,
      lastUsedAt: k.lastUsedAt || null
    }))
    .sort((a, b) => a.key.localeCompare(b.key));
  return data;
}

function isExpiredKey(k) {
  if (!k || !k.expiresAt) return false;
  const t = Date.parse(k.expiresAt);
  if (!Number.isFinite(t)) return false;
  return Date.now() > t;
}

function writeDb(data) {
  fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2), "utf8");
}

function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: TOKEN_TTL_SECONDS });
}

// One-time session tokens for launching the game
// token -> { key, hwidFingerprint, exp, used }
const sessions = new Map();

function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString("hex");
}

async function sha256FileLowerHex(filePath) {
  return new Promise((resolve, reject) => {
    const h = crypto.createHash("sha256");
    const s = fs.createReadStream(filePath);
    s.on("data", (chunk) => h.update(chunk));
    s.on("error", reject);
    s.on("end", () => resolve(h.digest("hex").toLowerCase()));
  });
}

function findProtectedModFile() {
  try {
    if (!fs.existsSync(MODS_DIR)) return null;
    const files = fs.readdirSync(MODS_DIR);
    const found = files.find((f) => typeof f === "string" && PROTECTED_MOD_REGEX.test(f));
    return found ? path.join(MODS_DIR, found) : null;
  } catch {
    return null;
  }
}

function authMiddleware(req, res, next) {
  const header = req.headers["authorization"] || "";
  const m = /^Bearer\s+(.+)$/i.exec(header);
  if (!m) return res.status(401).json({ ok: false, error: "missing_token" });

  try {
    const payload = jwt.verify(m[1], JWT_SECRET);
    // IMPORTANT: validate user token against DB so deleted/expired keys are rejected
    if (payload?.type === "user") {
      const key = String(payload.key || "").trim();
      if (!key) return res.status(401).json({ ok: false, error: "invalid_key" });

      const db = readDb();
      const found = db.keys.find((k) => k.key === key);
      if (!found) return res.status(401).json({ ok: false, error: "invalid_key" });
      if (isExpiredKey(found)) return res.status(401).json({ ok: false, error: "key_expired" });

      // If key is bound to hwidFingerprint, enforce it for all authenticated calls too
      if (found.hwidFingerprint && payload.hwidFingerprint && found.hwidFingerprint !== payload.hwidFingerprint) {
        return res.status(401).json({ ok: false, error: "key_used_on_other_pc" });
      }
    }

    req.user = payload;
    next();
  } catch {
    return res.status(401).json({ ok: false, error: "invalid_token" });
  }
}

function adminAuth(req, res, next) {
  const header = req.headers["authorization"] || "";
  const m = /^Bearer\s+(.+)$/i.exec(header);
  const token = m ? m[1] : null;

  // Also allow cookie-based admin token for web panel
  const cookies = parseCookies(req.headers.cookie || "");
  const cookieToken = cookies.admin_token;

  const effectiveToken = token || cookieToken;
  if (!effectiveToken) return res.status(401).json({ ok: false, error: "missing_admin_token" });

  try {
    const payload = jwt.verify(effectiveToken, JWT_SECRET);
    if (!payload || payload.type !== "admin") {
      return res.status(403).json({ ok: false, error: "not_admin" });
    }
    next();
  } catch {
    return res.status(401).json({ ok: false, error: "invalid_admin_token" });
  }
}

app.get("/admin", adminAuth, (req, res) => {
  // Serve admin panel only after auth
  res.sendFile(ADMIN_FILE);
});

app.get("/health", (req, res) => {
  res.json({ ok: true });
});

app.get("/api/admin/mods", adminAuth, (req, res) => {
  try {
    if (!fs.existsSync(MODS_DIR)) fs.mkdirSync(MODS_DIR, { recursive: true });
    const files = fs.readdirSync(MODS_DIR)
      .filter((f) => typeof f === "string" && f.toLowerCase().endsWith(".jar"))
      .sort((a, b) => a.localeCompare(b));
    res.json({ ok: true, files });
  } catch {
    res.status(500).json({ ok: false, error: "mods_list_failed" });
  }
});

const modUpload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => {
      try {
        if (!fs.existsSync(MODS_DIR)) fs.mkdirSync(MODS_DIR, { recursive: true });
      } catch {}
      cb(null, MODS_DIR);
    },
    filename: (req, file, cb) => {
      const original = String(file.originalname || "mod.jar");
      const safe = path.basename(original).replace(/\s+/g, " ");
      cb(null, safe);
    }
  }),
  limits: {
    fileSize: 200 * 1024 * 1024
  },
  fileFilter: (req, file, cb) => {
    const name = String(file.originalname || "").toLowerCase();
    if (!name.endsWith(".jar")) return cb(new Error("only_jar"));
    cb(null, true);
  }
});

app.post("/api/admin/mods/upload", adminAuth, modUpload.single("file"), (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ ok: false, error: "missing_file" });
    res.json({ ok: true, fileName: req.file.filename });
  } catch {
    res.status(500).json({ ok: false, error: "upload_failed" });
  }
});

app.delete("/api/admin/mods/:file", adminAuth, (req, res) => {
  const file = String(req.params.file || "").trim();
  if (!file) return res.status(400).json({ ok: false, error: "missing_file" });
  if (!file.toLowerCase().endsWith(".jar")) return res.status(400).json({ ok: false, error: "only_jar" });
  if (file.includes("..") || file.includes("/") || file.includes("\\")) {
    return res.status(400).json({ ok: false, error: "bad_file" });
  }

  try {
    const p = path.join(MODS_DIR, file);
    if (!fs.existsSync(p)) return res.status(404).json({ ok: false, error: "not_found" });
    fs.unlinkSync(p);
    res.json({ ok: true });
  } catch {
    res.status(500).json({ ok: false, error: "delete_failed" });
  }
});

app.post("/api/auth/verify", (req, res) => {
  const key = String(req.body?.key || "").trim();
  const hwid = String(req.body?.hwid || "").trim();
  // Preferred: sha256(iron_ids + salt) or similar. Must be stable per PC.
  const hwidFingerprint = String(req.body?.hwidFingerprint || "").trim();

  if (!key) return res.status(400).json({ ok: false, error: "missing_key" });
  if (!hwidFingerprint && !hwid) return res.status(400).json({ ok: false, error: "missing_hwid" });

  const db = readDb();
  const found = db.keys.find((k) => k.key === key);
  const valid = !!found;

  if (!valid) return res.status(401).json({ ok: false, error: "invalid_key" });

  if (isExpiredKey(found)) return res.status(401).json({ ok: false, error: "key_expired" });

  const fp = hwidFingerprint || null;

  // Bind by hardware fingerprint (preferred). Fallback to legacy hwid if fingerprint not provided.
  if (fp) {
    if (!found.hwidFingerprint) {
      found.hwidFingerprint = fp;
      found.firstUsedAt = new Date().toISOString();
    } else if (found.hwidFingerprint !== fp) {
      return res.status(401).json({ ok: false, error: "key_used_on_other_pc" });
    }
  } else {
    if (!found.hwid) {
      found.hwid = hwid;
      found.firstUsedAt = new Date().toISOString();
    } else if (found.hwid !== hwid) {
      return res.status(401).json({ ok: false, error: "key_used_on_other_pc" });
    }
  }

  found.lastUsedAt = new Date().toISOString();
  writeDb(db);

  const token = signToken({ type: "user", key, hwid: hwid || null, hwidFingerprint: fp || found.hwidFingerprint || null });
  res.json({ ok: true, token, expiresIn: TOKEN_TTL_SECONDS });
});

app.post("/api/session/start", authMiddleware, async (req, res) => {
  const hwidFingerprint = String(req.body?.hwidFingerprint || req.user?.hwidFingerprint || "").trim();
  if (!hwidFingerprint) return res.status(400).json({ ok: false, error: "missing_hwid" });

  const modSha256 = String(req.body?.modSha256 || "").trim().toLowerCase();
  if (!modSha256) return res.status(400).json({ ok: false, error: "missing_mod_hash" });

  const db = readDb();
  const found = db.keys.find((k) => k.key === req.user?.key);
  if (!found) return res.status(401).json({ ok: false, error: "invalid_key" });
  if (found.hwidFingerprint && found.hwidFingerprint !== hwidFingerprint) {
    return res.status(401).json({ ok: false, error: "key_used_on_other_pc" });
  }

  // Validate protected mod integrity
  if (PROTECTED_MOD_SHA256) {
    if (PROTECTED_MOD_SHA256 !== modSha256) return res.status(403).json({ ok: false, error: "invalid_mod_hash" });
  } else {
    const protectedFile = findProtectedModFile();
    if (!protectedFile) return res.status(400).json({ ok: false, error: "protected_mod_not_found" });

    try {
      const expected = await sha256FileLowerHex(protectedFile);
      if (expected !== modSha256) return res.status(403).json({ ok: false, error: "invalid_mod_hash" });
    } catch {
      return res.status(500).json({ ok: false, error: "mod_hash_failed" });
    }
  }

  const sessionToken = randomToken(24);
  const exp = Date.now() + SESSION_TTL_SECONDS * 1000;
  sessions.set(sessionToken, { key: found.key, hwidFingerprint, exp, used: false });
  res.json({ ok: true, sessionToken, expiresIn: SESSION_TTL_SECONDS });
});

app.post("/api/session/verify", (req, res) => {
  const sessionToken = String(req.body?.sessionToken || "").trim();
  const hwidFingerprint = String(req.body?.hwidFingerprint || "").trim();
  if (!sessionToken) return res.status(400).json({ ok: false, error: "missing_session" });
  if (!hwidFingerprint) return res.status(400).json({ ok: false, error: "missing_hwid" });

  const s = sessions.get(sessionToken);
  if (!s) return res.status(401).json({ ok: false, error: "invalid_session" });
  if (s.used) return res.status(401).json({ ok: false, error: "session_used" });
  if (Date.now() > s.exp) {
    sessions.delete(sessionToken);
    return res.status(401).json({ ok: false, error: "session_expired" });
  }
  if (s.hwidFingerprint !== hwidFingerprint) return res.status(401).json({ ok: false, error: "key_used_on_other_pc" });

  // mark one-time
  s.used = true;
  sessions.set(sessionToken, s);
  const db = readDb();
  const found = db.keys.find((k) => k.key === s.key);
  if (!found) return res.status(401).json({ ok: false, error: "invalid_key" });
  if (isExpiredKey(found)) return res.status(401).json({ ok: false, error: "key_expired" });

  const parsedExpiresAt = found.expiresAt ? Date.parse(found.expiresAt) : NaN;
  const expiresAtMs = Number.isFinite(parsedExpiresAt) ? parsedExpiresAt : null;
  const expiresInSec = expiresAtMs !== null ? Math.max(0, Math.floor((expiresAtMs - Date.now()) / 1000)) : null;

  res.json({
    ok: true,
    key: s.key,
    license: {
      expiresAt: expiresAtMs,
      isLifetime: expiresAtMs === null,
      expiresInSec
    }
  });
});

app.get("/api/modpack", authMiddleware, (req, res) => {
  const baseUrl = `${req.protocol}://${req.get("host")}`;
  const modsBaseUrl = MODS_BASE_URL;

  const envMods = getModsListFromEnv();

  let mods = [];
  try {
    if (envMods) {
      if (!modsBaseUrl) {
        return res.status(500).json({ ok: false, error: "missing_mods_base_url" });
      }

      mods = envMods
        .filter((f) => f.toLowerCase().endsWith(".jar"))
        .sort((a, b) => a.localeCompare(b))
        .map((f) => {
          const encoded = encodeURIComponent(f);
          const url = `${modsBaseUrl}/${encoded}`;
          return { id: f.replace(/\.jar$/i, ""), url, fileName: f };
        });
    } else
    if (fs.existsSync(MODS_DIR)) {
      const files = fs.readdirSync(MODS_DIR);
      mods = files
        .filter((f) => typeof f === "string" && f.toLowerCase().endsWith(".jar"))
        .sort((a, b) => a.localeCompare(b))
        .map((f) => {
          const encoded = encodeURIComponent(f);
          const url = modsBaseUrl ? `${modsBaseUrl}/${encoded}` : `${baseUrl}/mods/${encoded}`;
          return { id: f.replace(/\.jar$/i, ""), url, fileName: f };
        });
    }
  } catch {
    mods = [];
  }

  res.json({
    ok: true,
    minecraft: "1.21.4",
    fabricLoader: "0.16.9",
    mods
  });
});

app.post("/api/admin/login", (req, res) => {
  const password = String(req.body?.password || "");
  if (!password) return res.status(400).json({ ok: false, error: "missing_password" });
  if (password !== ADMIN_PASSWORD) return res.status(401).json({ ok: false, error: "invalid_password" });

  const token = signToken({ type: "admin" });
  // Cookie for web admin panel
  res.setHeader(
    "Set-Cookie",
    `admin_token=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${TOKEN_TTL_SECONDS}`
  );
  res.json({ ok: true, token, expiresIn: TOKEN_TTL_SECONDS });
});

app.post("/api/admin/logout", adminAuth, (req, res) => {
  res.setHeader("Set-Cookie", "admin_token=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax");
  res.json({ ok: true });
});

app.get("/api/admin/keys", adminAuth, (req, res) => {
  const db = readDb();
  res.json({ ok: true, keys: db.keys });
});

app.post("/api/admin/keys", adminAuth, (req, res) => {
  const mode = String(req.body?.mode || "generate").trim();
  const providedKey = String(req.body?.key || "").trim();
  const ttlSecondsRaw = req.body?.ttlSeconds;
  const ttlSeconds = Number.isFinite(Number(ttlSecondsRaw)) ? Number(ttlSecondsRaw) : null;
  const hwidFingerprint = String(req.body?.hwidFingerprint || "").trim() || null;

  const db = readDb();

  let newKey = providedKey;
  if (mode === "generate" || !newKey) {
    newKey = crypto.randomBytes(12).toString("hex").toUpperCase();
  }

  if (db.keys.some((k) => k.key === newKey)) {
    return res.status(409).json({ ok: false, error: "key_exists" });
  }

  const expiresAt = ttlSeconds && ttlSeconds > 0
    ? new Date(Date.now() + ttlSeconds * 1000).toISOString()
    : null;

  db.keys.push({
    key: newKey,
    createdAt: new Date().toISOString(),
    expiresAt,
    hwid: null,
    hwidFingerprint,
    firstUsedAt: null,
    lastUsedAt: null
  });
  writeDb(db);

  res.json({ ok: true, key: newKey });
});

app.post("/api/admin/keys/:key/reset-hwid", adminAuth, (req, res) => {
  const key = String(req.params.key || "").trim();
  if (!key) return res.status(400).json({ ok: false, error: "missing_key" });

  const db = readDb();
  const found = db.keys.find((k) => k.key === key);
  if (!found) return res.status(404).json({ ok: false, error: "not_found" });

  found.hwid = null;
  found.hwidFingerprint = null;
  found.firstUsedAt = null;
  found.lastUsedAt = null;
  writeDb(db);

  res.json({ ok: true });
});

app.delete("/api/admin/keys/:key", adminAuth, (req, res) => {
  const key = String(req.params.key || "").trim();
  if (!key) return res.status(400).json({ ok: false, error: "missing_key" });

  const db = readDb();
  const before = db.keys.length;
  db.keys = db.keys.filter((k) => k.key !== key);
  const after = db.keys.length;

  writeDb(db);

  res.json({ ok: true, removed: before - after });
});

app.listen(PORT, () => {
  console.log(`[server] listening on http://localhost:${PORT}`);
  console.log(`[server] admin panel: http://localhost:${PORT}/admin.html`);
  console.log(`[server] set ADMIN_PASSWORD env var (current: ${ADMIN_PASSWORD === "change_me" ? "change_me" : "(custom)"})`);
});
