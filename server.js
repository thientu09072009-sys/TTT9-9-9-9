import express from "express";
import pg from "pg";
import crypto from "crypto";
import path from "path";
import { fileURLToPath } from "url";

const { Pool } = pg;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

/* =========================================================
   CONFIG
========================================================= */

const PORT = Number(process.env.PORT || 10000);

const DATABASE_URL = String(process.env.DATABASE_URL || "").trim();

const ADMIN_KEY = String(process.env.ADMIN_KEY || "").trim();

const ALLOWED_ORIGINS = String(
  process.env.ALLOWED_ORIGINS || "*"
)
  .split(",")
  .map(x => x.trim())
  .filter(Boolean);

const GAME_SECONDS = 30;
const RESULT_SECONDS = 7;

const TX_PAYOUT = 1.95;
const XD_NORMAL_PAYOUT = 1.95;

const SESSION_DAYS = 30;

/* =========================================================
   BASIC VALIDATION
========================================================= */

if (!DATABASE_URL) {
  console.error("========================================");
  console.error("DATABASE_URL CHUA DUOC CAU HINH");
  console.error("Hay them DATABASE_URL trong Render.");
  console.error("========================================");
}

if (!ADMIN_KEY) {
  console.warn("========================================");
  console.warn("ADMIN_KEY CHUA DUOC CAU HINH");
  console.warn("Hay them ADMIN_KEY trong Render.");
  console.warn("========================================");
}

/* =========================================================
   EXPRESS
========================================================= */

app.use(
  express.json({
    limit: "1mb"
  })
);

/* =========================================================
   CORS
========================================================= */

app.use((req, res, next) => {
  const origin = req.headers.origin;

  if (ALLOWED_ORIGINS.includes("*")) {
    res.setHeader("Access-Control-Allow-Origin", "*");
  } else if (origin && ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
  }

  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type, Authorization, x-admin-key"
  );

  res.setHeader(
    "Access-Control-Allow-Methods",
    "GET,POST,PATCH,PUT,DELETE,OPTIONS"
  );

  if (req.method === "OPTIONS") {
    return res.sendStatus(204);
  }

  next();
});

/* =========================================================
   POSTGRES
========================================================= */

const pool = new Pool({
  connectionString: DATABASE_URL,

  ssl:
    process.env.NODE_ENV === "production"
      ? {
          rejectUnauthorized: false
        }
      : false,

  max: 5,

  idleTimeoutMillis: 30000,

  connectionTimeoutMillis: 10000
});

/* =========================================================
   HELPERS
========================================================= */

const now = () => new Date();

const sha = value =>
  crypto
    .createHash("sha256")
    .update(String(value))
    .digest("hex");

const makeToken = () =>
  crypto.randomBytes(32).toString("hex");

const sleep = ms =>
  new Promise(resolve => setTimeout(resolve, ms));

async function q(sql, params = []) {
  return pool.query(sql, params);
}

/* =========================================================
   PASSWORD
========================================================= */

function makePasswordHash(
  password,
  salt = crypto.randomBytes(16).toString("hex")
) {
  const key = crypto
    .scryptSync(password, salt, 64)
    .toString("hex");

  return `${salt}:${key}`;
}

function verifyPassword(password, stored) {
  try {
    const parts = String(stored || "").split(":");

    if (parts.length !== 2) {
      return false;
    }

    const [salt, expected] = parts;

    if (!salt || !expected) {
      return false;
    }

    const got = crypto
      .scryptSync(password, salt, 64)
      .toString("hex");

    const a = Buffer.from(got, "hex");
    const b = Buffer.from(expected, "hex");

    if (a.length !== b.length) {
      return false;
    }

    return crypto.timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

/* =========================================================
   DATABASE INIT
========================================================= */

async function initDb() {
  /*
   * ================================
   * USERS
   * ================================
   */

  await q(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      username VARCHAR(24) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      ttt BIGINT NOT NULL DEFAULT 0,
      plays BIGINT NOT NULL DEFAULT 0,
      biggest_win BIGINT NOT NULL DEFAULT 0,
      total_won BIGINT NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      last_login_at TIMESTAMPTZ
    )
  `);

  /*
   * DATABASE CŨ:
   * bổ sung những cột còn thiếu.
   */

  await q(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS password_hash TEXT
  `);

  await q(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS ttt BIGINT NOT NULL DEFAULT 0
  `);

  await q(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS plays BIGINT NOT NULL DEFAULT 0
  `);

  await q(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS biggest_win BIGINT NOT NULL DEFAULT 0
  `);

  await q(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS total_won BIGINT NOT NULL DEFAULT 0
  `);

  await q(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS created_at
    TIMESTAMPTZ NOT NULL DEFAULT NOW()
  `);

  await q(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS last_login_at
    TIMESTAMPTZ
  `);


  /*
   * ================================
   * SESSIONS
   * ================================
   */

  await q(`
    CREATE TABLE IF NOT EXISTS sessions (
      token_hash CHAR(64) PRIMARY KEY,
      user_id BIGINT NOT NULL
        REFERENCES users(id)
        ON DELETE CASCADE,
      expires_at TIMESTAMPTZ NOT NULL
    )
  `);

  await q(`
    ALTER TABLE sessions
    ADD COLUMN IF NOT EXISTS expires_at
    TIMESTAMPTZ
  `);


  /*
   * ================================
   * REDEEM CODES
   * ================================
   */

  await q(`
    CREATE TABLE IF NOT EXISTS redeem_codes (
      id BIGSERIAL PRIMARY KEY,
      code VARCHAR(40) UNIQUE NOT NULL,
      reward BIGINT NOT NULL DEFAULT 0,
      max_uses INT NOT NULL DEFAULT 1,
      uses INT NOT NULL DEFAULT 0,
      active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      expires_at TIMESTAMPTZ
    )
  `);

  await q(`
    ALTER TABLE redeem_codes
    ADD COLUMN IF NOT EXISTS reward BIGINT
  `);

  await q(`
    ALTER TABLE redeem_codes
    ADD COLUMN IF NOT EXISTS max_uses INT
  `);

  await q(`
    ALTER TABLE redeem_codes
    ADD COLUMN IF NOT EXISTS uses INT
  `);

  await q(`
    ALTER TABLE redeem_codes
    ADD COLUMN IF NOT EXISTS active BOOLEAN
  `);

  await q(`
    ALTER TABLE redeem_codes
    ADD COLUMN IF NOT EXISTS created_at
    TIMESTAMPTZ
  `);

  await q(`
    ALTER TABLE redeem_codes
    ADD COLUMN IF NOT EXISTS expires_at
    TIMESTAMPTZ
  `);

  /*
   * Giá trị mặc định cho database cũ.
   */

  await q(`
    UPDATE redeem_codes
    SET reward = 0
    WHERE reward IS NULL
  `);

  await q(`
    UPDATE redeem_codes
    SET max_uses = 1
    WHERE max_uses IS NULL
  `);

  await q(`
    UPDATE redeem_codes
    SET uses = 0
    WHERE uses IS NULL
  `);

  await q(`
    UPDATE redeem_codes
    SET active = TRUE
    WHERE active IS NULL
  `);


  /*
   * ================================
   * TÀI XỈU - ROUNDS
   * ================================
   */

  await q(`
    CREATE TABLE IF NOT EXISTS tx_rounds (
      id BIGSERIAL PRIMARY KEY,
      started_at TIMESTAMPTZ NOT NULL,
      ends_at TIMESTAMPTZ NOT NULL,
      status VARCHAR(12) NOT NULL DEFAULT 'open',
      d1 SMALLINT,
      d2 SMALLINT,
      d3 SMALLINT,
      total SMALLINT,
      side VARCHAR(5),
      result_until TIMESTAMPTZ
    )
  `);

  await q(`
    ALTER TABLE tx_rounds
    ADD COLUMN IF NOT EXISTS d1 SMALLINT
  `);

  await q(`
    ALTER TABLE tx_rounds
    ADD COLUMN IF NOT EXISTS d2 SMALLINT
  `);

  await q(`
    ALTER TABLE tx_rounds
    ADD COLUMN IF NOT EXISTS d3 SMALLINT
  `);

  await q(`
    ALTER TABLE tx_rounds
    ADD COLUMN IF NOT EXISTS total SMALLINT
  `);

  await q(`
    ALTER TABLE tx_rounds
    ADD COLUMN IF NOT EXISTS side VARCHAR(5)
  `);

  await q(`
    ALTER TABLE tx_rounds
    ADD COLUMN IF NOT EXISTS result_until
    TIMESTAMPTZ
  `);


  /*
   * ================================
   * TÀI XỈU - BETS
   * ================================
   */

  await q(`
    CREATE TABLE IF NOT EXISTS tx_bets (
      id BIGSERIAL PRIMARY KEY,
      round_id BIGINT NOT NULL
        REFERENCES tx_rounds(id)
        ON DELETE CASCADE,
      user_id BIGINT NOT NULL
        REFERENCES users(id)
        ON DELETE CASCADE,
      side VARCHAR(4) NOT NULL,
      amount BIGINT NOT NULL,
      settled BOOLEAN NOT NULL DEFAULT FALSE,
      win_ttt BIGINT NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await q(`
    ALTER TABLE tx_bets
    ADD COLUMN IF NOT EXISTS settled BOOLEAN
  `);

  await q(`
    ALTER TABLE tx_bets
    ADD COLUMN IF NOT EXISTS win_ttt BIGINT
  `);

  await q(`
    UPDATE tx_bets
    SET settled = FALSE
    WHERE settled IS NULL
  `);

  await q(`
    UPDATE tx_bets
    SET win_ttt = 0
    WHERE win_ttt IS NULL
  `);


  /*
   * ================================
   * TÀI XỈU - HISTORY
   * ================================
   */

  await q(`
    CREATE TABLE IF NOT EXISTS tx_history (
      id BIGSERIAL PRIMARY KEY,
      round_id BIGINT UNIQUE NOT NULL
        REFERENCES tx_rounds(id)
        ON DELETE CASCADE,
      d1 SMALLINT NOT NULL,
      d2 SMALLINT NOT NULL,
      d3 SMALLINT NOT NULL,
      total SMALLINT NOT NULL,
      side VARCHAR(5) NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);


  /*
   * ================================
   * XÓC ĐĨA - ROUNDS
   * ================================
   */

  await q(`
    CREATE TABLE IF NOT EXISTS xd_rounds (
      id BIGSERIAL PRIMARY KEY,
      started_at TIMESTAMPTZ NOT NULL,
      ends_at TIMESTAMPTZ NOT NULL,
      status VARCHAR(12) NOT NULL DEFAULT 'open',
      red_count SMALLINT,
      white_count SMALLINT,
      side VARCHAR(5),
      multiplier NUMERIC(8,2),
      result_until TIMESTAMPTZ
    )
  `);

  await q(`
    ALTER TABLE xd_rounds
    ADD COLUMN IF NOT EXISTS red_count SMALLINT
  `);

  await q(`
    ALTER TABLE xd_rounds
    ADD COLUMN IF NOT EXISTS white_count SMALLINT
  `);

  await q(`
    ALTER TABLE xd_rounds
    ADD COLUMN IF NOT EXISTS side VARCHAR(5)
  `);

  await q(`
    ALTER TABLE xd_rounds
    ADD COLUMN IF NOT EXISTS multiplier NUMERIC(8,2)
  `);

  await q(`
    ALTER TABLE xd_rounds
    ADD COLUMN IF NOT EXISTS result_until
    TIMESTAMPTZ
  `);


  /*
   * ================================
   * XÓC ĐĨA - BETS
   * ================================
   */

  await q(`
    CREATE TABLE IF NOT EXISTS xd_bets (
      id BIGSERIAL PRIMARY KEY,
      round_id BIGINT NOT NULL
        REFERENCES xd_rounds(id)
        ON DELETE CASCADE,
      user_id BIGINT NOT NULL
        REFERENCES users(id)
        ON DELETE CASCADE,
      side VARCHAR(4) NOT NULL,
      amount BIGINT NOT NULL,
      settled BOOLEAN NOT NULL DEFAULT FALSE,
      win_ttt BIGINT NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await q(`
    ALTER TABLE xd_bets
    ADD COLUMN IF NOT EXISTS settled BOOLEAN
  `);

  await q(`
    ALTER TABLE xd_bets
    ADD COLUMN IF NOT EXISTS win_ttt BIGINT
  `);

  await q(`
    UPDATE xd_bets
    SET settled = FALSE
    WHERE settled IS NULL
  `);

  await q(`
    UPDATE xd_bets
    SET win_ttt = 0
    WHERE win_ttt IS NULL
  `);


  /*
   * ================================
   * XÓC ĐĨA - HISTORY
   * ================================
   */

  await q(`
    CREATE TABLE IF NOT EXISTS xd_history (
      id BIGSERIAL PRIMARY KEY,
      round_id BIGINT UNIQUE NOT NULL
        REFERENCES xd_rounds(id)
        ON DELETE CASCADE,
      red_count SMALLINT NOT NULL,
      white_count SMALLINT NOT NULL,
      side VARCHAR(5) NOT NULL,
      multiplier NUMERIC(8,2) NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);


  /*
   * ================================
   * TẠO VÁN ĐẦU TIÊN
   * ================================
   */

  const txExists =
    await q(`
      SELECT id
      FROM tx_rounds
      LIMIT 1
    `);

  if (!txExists.rowCount) {
    await createTxRound();
  }

  const xdExists =
    await q(`
      SELECT id
      FROM xd_rounds
      LIMIT 1
    `);

  if (!xdExists.rowCount) {
    await createXdRound();
  }

  console.log(
    "DATABASE INITIALIZED SUCCESSFULLY"
  );
}
  /*
    ===============================
    TAO VAN DAU TIEN
    ===============================
  */

  const txCount = await q(`
    SELECT 1
    FROM tx_rounds
    LIMIT 1
  `);

  if (!txCount.rowCount) {
    await createTxRound();
  }

  const xdCount = await q(`
    SELECT 1
    FROM xd_rounds
    LIMIT 1
  `);

  if (!xdCount.rowCount) {
    await createXdRound();
  }

  console.log("DATABASE INIT OK");
}

/* =========================================================
   TAO VAN TAI XIU
========================================================= */

async function createTxRound() {
  const started = now();

  const ends = new Date(
    started.getTime() +
      GAME_SECONDS * 1000
  );

  const r = await q(
    `
      INSERT INTO tx_rounds(
        started_at,
        ends_at,
        status
      )
      VALUES(
        $1,
        $2,
        'open'
      )
      RETURNING *
    `,
    [started, ends]
  );

  return r.rows[0];
}

/* =========================================================
   TAO VAN XOC DIA
========================================================= */

async function createXdRound() {
  const started = now();

  const ends = new Date(
    started.getTime() +
      GAME_SECONDS * 1000
  );

  const r = await q(
    `
      INSERT INTO xd_rounds(
        started_at,
        ends_at,
        status
      )
      VALUES(
        $1,
        $2,
        'open'
      )
      RETURNING *
    `,
    [started, ends]
  );

  return r.rows[0];
}

/* =========================================================
   LAY VAN TAI XIU HIEN TAI
========================================================= */

async function getTxRound() {
  let r = await q(`
    SELECT *
    FROM tx_rounds
    ORDER BY id DESC
    LIMIT 1
  `);

  if (!r.rowCount) {
    await createTxRound();

    r = await q(`
      SELECT *
      FROM tx_rounds
      ORDER BY id DESC
      LIMIT 1
    `);
  }

  const round = r.rows[0];

  if (
    round.status === "closed" &&
    round.result_until &&
    new Date(round.result_until) <= now()
  ) {
    await createTxRound();

    r = await q(`
      SELECT *
      FROM tx_rounds
      ORDER BY id DESC
      LIMIT 1
    `);
  }

  return r.rows[0];
}

/* =========================================================
   LAY VAN XOC DIA HIEN TAI
========================================================= */

async function getXdRound() {
  let r = await q(`
    SELECT *
    FROM xd_rounds
    ORDER BY id DESC
    LIMIT 1
  `);

  if (!r.rowCount) {
    await createXdRound();

    r = await q(`
      SELECT *
      FROM xd_rounds
      ORDER BY id DESC
      LIMIT 1
    `);
  }

  const round = r.rows[0];

  if (
    round.status === "closed" &&
    round.result_until &&
    new Date(round.result_until) <= now()
  ) {
    await createXdRound();

    r = await q(`
      SELECT *
      FROM xd_rounds
      ORDER BY id DESC
      LIMIT 1
    `);
  }

  return r.rows[0];
}

/* =========================================================
   TAI / XIU
========================================================= */

function txSide(a, b, c) {
  const total = a + b + c;

  /*
    3 mat giong nhau:
    tong >= 12 -> TAI
    tong < 12  -> XIU
  */

  if (a === b && b === c) {
    return total >= 12
      ? "TÀI"
      : "XỈU";
  }

  return total >= 11
    ? "TÀI"
    : "XỈU";
}

/* =========================================================
   SAFE NUMBER
========================================================= */

function safeInteger(value) {
  const n = Number(value);

  if (!Number.isSafeInteger(n)) {
    return null;
  }

  return n;
}

/* =========================================================
   STARTUP HEALTH
========================================================= */

async function databaseReady() {
  try {
    await q("SELECT 1");
    return true;
  } catch (error) {
    console.error(
      "DATABASE CHECK FAILED:",
      error.message
    );

    return false;
  }
}/* =========================================================
   SETTLE TÀI XỈU
========================================================= */

async function settleTx(round) {
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const locked = await client.query(
      `
        SELECT *
        FROM tx_rounds
        WHERE id=$1
        FOR UPDATE
      `,
      [round.id]
    );

    if (
      !locked.rowCount ||
      locked.rows[0].status !== "open"
    ) {
      await client.query("ROLLBACK");
      return;
    }

    const d1 = crypto.randomInt(1, 7);
    const d2 = crypto.randomInt(1, 7);
    const d3 = crypto.randomInt(1, 7);

    const total = d1 + d2 + d3;

    const side = txSide(
      d1,
      d2,
      d3
    );

    const resultUntil = new Date(
      Date.now() +
        RESULT_SECONDS * 1000
    );

    await client.query(
      `
        UPDATE tx_rounds
        SET
          status='closed',
          d1=$2,
          d2=$3,
          d3=$4,
          total=$5,
          side=$6,
          result_until=$7
        WHERE id=$1
      `,
      [
        round.id,
        d1,
        d2,
        d3,
        total,
        side,
        resultUntil
      ]
    );

    await client.query(
      `
        INSERT INTO tx_history(
          round_id,
          d1,
          d2,
          d3,
          total,
          side
        )
        VALUES(
          $1,
          $2,
          $3,
          $4,
          $5,
          $6
        )
        ON CONFLICT(round_id)
        DO NOTHING
      `,
      [
        round.id,
        d1,
        d2,
        d3,
        total,
        side
      ]
    );

    const bets = await client.query(
      `
        SELECT *
        FROM tx_bets
        WHERE
          round_id=$1
          AND settled=false
        FOR UPDATE
      `,
      [round.id]
    );

    for (const bet of bets.rows) {
      const won =
        bet.side ===
        (side === "TÀI"
          ? "tai"
          : "xiu");

      const winTtt = won
        ? Math.floor(
            Number(bet.amount) *
              TX_PAYOUT
          )
        : 0;

      await client.query(
        `
          UPDATE users
          SET
            ttt=ttt+$1,
            plays=plays+1,
            biggest_win=
              GREATEST(biggest_win,$1),
            total_won=
              total_won+$1
          WHERE id=$2
        `,
        [
          winTtt,
          bet.user_id
        ]
      );

      await client.query(
        `
          UPDATE tx_bets
          SET
            settled=true,
            win_ttt=$1
          WHERE id=$2
        `,
        [
          winTtt,
          bet.id
        ]
      );
    }

    await client.query("COMMIT");

    console.log(
      `[TX] Round ${round.id}: ${d1}-${d2}-${d3} ${side}`
    );
  } catch (error) {
    try {
      await client.query("ROLLBACK");
    } catch {}

    console.error(
      "settleTx:",
      error
    );
  } finally {
    client.release();
  }
}


/* =========================================================
   SETTLE XÓC ĐĨA
========================================================= */

async function settleXd(round) {
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const locked = await client.query(
      `
        SELECT *
        FROM xd_rounds
        WHERE id=$1
        FOR UPDATE
      `,
      [round.id]
    );

    if (
      !locked.rowCount ||
      locked.rows[0].status !== "open"
    ) {
      await client.query("ROLLBACK");
      return;
    }

    /*
      Xóc Đĩa có 4 quân:
      red = số quân đỏ
      white = 4 - red
    */

    const red = crypto.randomInt(0, 5);

    const white = 4 - red;

    const side =
      red % 2 === 0
        ? "CHẴN"
        : "LẺ";

    let multiplier;

    if (red === 0 || red === 4) {
      multiplier = 16;
    } else if (
      red === 1 ||
      red === 3
    ) {
      multiplier = 4;
    } else {
      multiplier = 1.95;
    }

    const resultUntil = new Date(
      Date.now() +
        RESULT_SECONDS * 1000
    );

    await client.query(
      `
        UPDATE xd_rounds
        SET
          status='closed',
          red_count=$2,
          white_count=$3,
          side=$4,
          multiplier=$5,
          result_until=$6
        WHERE id=$1
      `,
      [
        round.id,
        red,
        white,
        side,
        multiplier,
        resultUntil
      ]
    );

    await client.query(
      `
        INSERT INTO xd_history(
          round_id,
          red_count,
          white_count,
          side,
          multiplier
        )
        VALUES(
          $1,
          $2,
          $3,
          $4,
          $5
        )
        ON CONFLICT(round_id)
        DO NOTHING
      `,
      [
        round.id,
        red,
        white,
        side,
        multiplier
      ]
    );

    const bets = await client.query(
      `
        SELECT *
        FROM xd_bets
        WHERE
          round_id=$1
          AND settled=false
        FOR UPDATE
      `,
      [round.id]
    );

    for (const bet of bets.rows) {
      const won =
        bet.side ===
        (side === "CHẴN"
          ? "chan"
          : "le");

      const winTtt = won
        ? Math.floor(
            Number(bet.amount) *
              multiplier
          )
        : 0;

      await client.query(
        `
          UPDATE users
          SET
            ttt=ttt+$1,
            plays=plays+1,
            biggest_win=
              GREATEST(biggest_win,$1),
            total_won=
              total_won+$1
          WHERE id=$2
        `,
        [
          winTtt,
          bet.user_id
        ]
      );

      await client.query(
        `
          UPDATE xd_bets
          SET
            settled=true,
            win_ttt=$1
          WHERE id=$2
        `,
        [
          winTtt,
          bet.id
        ]
      );
    }

    await client.query("COMMIT");

    console.log(
      `[XD] Round ${round.id}: red=${red} white=${white} ${side} x${multiplier}`
    );
  } catch (error) {
    try {
      await client.query("ROLLBACK");
    } catch {}

    console.error(
      "settleXd:",
      error
    );
  } finally {
    client.release();
  }
}


/* =========================================================
   GAME TICK
========================================================= */

let tickRunning = false;

async function tick() {
  if (tickRunning) {
    return;
  }

  tickRunning = true;

  try {
    const timestamp = Date.now();

    const tx = await getTxRound();

    if (
      tx.status === "open" &&
      new Date(tx.ends_at).getTime() <= timestamp
    ) {
      await settleTx(tx);
    }

    const xd = await getXdRound();

    if (
      xd.status === "open" &&
      new Date(xd.ends_at).getTime() <= timestamp
    ) {
      await settleXd(xd);
    }
  } catch (error) {
    console.error(
      "tick:",
      error
    );
  } finally {
    tickRunning = false;
  }
}


/* =========================================================
   AUTH MIDDLEWARE
========================================================= */

async function auth(req, res, next) {
  const authorization =
    String(
      req.headers.authorization || ""
    );

  const token =
    authorization.startsWith("Bearer ")
      ? authorization.slice(7).trim()
      : "";

  if (!token) {
    return res.status(401).json({
      ok: false,
      error: "Chưa đăng nhập."
    });
  }

  try {
    const result = await q(
      `
        SELECT
          u.id,
          u.username,
          u.ttt,
          u.plays,
          u.biggest_win,
          u.total_won,
          u.created_at,
          u.last_login_at,
          s.expires_at
        FROM sessions s
        JOIN users u
          ON u.id=s.user_id
        WHERE s.token_hash=$1
      `,
      [sha(token)]
    );

    if (!result.rowCount) {
      return res.status(401).json({
        ok: false,
        error: "Phiên đăng nhập không hợp lệ."
      });
    }

    const session = result.rows[0];

    if (
      new Date(session.expires_at) <= now()
    ) {
      await q(
        `
          DELETE FROM sessions
          WHERE token_hash=$1
        `,
        [sha(token)]
      );

      return res.status(401).json({
        ok: false,
        error: "Phiên đăng nhập đã hết hạn."
      });
    }

    req.user = session;
    req.token = token;

    next();
  } catch (error) {
    console.error(
      "auth:",
      error
    );

    return res.status(500).json({
      ok: false,
      error: "Lỗi máy chủ."
    });
  }
}


/* =========================================================
   ADMIN MIDDLEWARE
========================================================= */

function admin(req, res, next) {
  const key =
    String(
      req.headers["x-admin-key"] ||
      req.body?.adminKey ||
      req.query?.key ||
      ""
    ).trim();

  if (!ADMIN_KEY) {
    return res.status(503).json({
      ok: false,
      error: "ADMIN_KEY chưa được cấu hình trên Render."
    });
  }

  if (key !== ADMIN_KEY) {
    return res.status(403).json({
      ok: false,
      error: "Sai ADMIN_KEY."
    });
  }

  next();
}


/* =========================================================
   HEALTH
========================================================= */

app.get("/health", async (_req, res) => {
  try {
    await q("SELECT 1");

    res.json({
      ok: true,
      status: "online",
      game: "running",
      database: "connected",
      time: now().toISOString()
    });
  } catch (error) {
    console.error(
      "health:",
      error.message
    );

    res.status(503).json({
      ok: false,
      status: "offline",
      database: "unavailable"
    });
  }
});


/* =========================================================
   REGISTER
========================================================= */

app.post(
  "/api/auth/register",
  async (req, res) => {
    const username =
      String(
        req.body?.username || ""
      ).trim();

    const password =
      String(
        req.body?.password || ""
      );

    if (
      !/^[A-Za-z0-9_]{3,24}$/.test(
        username
      )
    ) {
      return res.status(400).json({
        ok: false,
        error:
          "Tên tài khoản phải có 3-24 ký tự: chữ, số hoặc _."
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        ok: false,
        error:
          "Mật khẩu tối thiểu 6 ký tự."
      });
    }

    try {
      const result = await q(
        `
          INSERT INTO users(
            username,
            password_hash
          )
          VALUES(
            $1,
            $2
          )
          RETURNING
            id,
            username,
            ttt,
            plays,
            biggest_win,
            total_won,
            created_at,
            last_login_at
        `,
        [
          username,
          makePasswordHash(password)
        ]
      );

      const user =
        result.rows[0];

      const token =
        makeToken();

      await q(
        `
          INSERT INTO sessions(
            token_hash,
            user_id,
            expires_at
          )
          VALUES(
            $1,
            $2,
            NOW() +
              ($3 * INTERVAL '1 day')
          )
        `,
        [
          sha(token),
          user.id,
          SESSION_DAYS
        ]
      );

      res.json({
        ok: true,
        token,
        user
      });
    } catch (error) {
      if (error.code === "23505") {
        return res.status(409).json({
          ok: false,
          error:
            "Tài khoản đã tồn tại."
        });
      }

      console.error(
        "register:",
        error
      );

      res.status(500).json({
        ok: false,
        error:
          "Không tạo được tài khoản."
      });
    }
  }
);


/* =========================================================
   LOGIN
========================================================= */

app.post(
  "/api/auth/login",
  async (req, res) => {
    const username =
      String(
        req.body?.username || ""
      ).trim();

    const password =
      String(
        req.body?.password || ""
      );

    if (!username || !password) {
      return res.status(400).json({
        ok: false,
        error:
          "Vui lòng nhập tài khoản và mật khẩu."
      });
    }

    try {
      const result = await q(
        `
          SELECT *
          FROM users
          WHERE lower(username)=lower($1)
          LIMIT 1
        `,
        [username]
      );

      if (!result.rowCount) {
        return res.status(401).json({
          ok: false,
          error:
            "Sai tài khoản hoặc mật khẩu."
        });
      }

      const user =
        result.rows[0];

      if (
        !verifyPassword(
          password,
          user.password_hash
        )
      ) {
        return res.status(401).json({
          ok: false,
          error:
            "Sai tài khoản hoặc mật khẩu."
        });
      }

      const token =
        makeToken();

      await q(
        `
          INSERT INTO sessions(
            token_hash,
            user_id,
            expires_at
          )
          VALUES(
            $1,
            $2,
            NOW() +
              ($3 * INTERVAL '1 day')
          )
        `,
        [
          sha(token),
          user.id,
          SESSION_DAYS
        ]
      );

      await q(
        `
          UPDATE users
          SET last_login_at=NOW()
          WHERE id=$1
        `,
        [user.id]
      );

      const fresh =
        await q(
          `
            SELECT
              id,
              username,
              ttt,
              plays,
              biggest_win,
              total_won,
              created_at,
              last_login_at
            FROM users
            WHERE id=$1
          `,
          [user.id]
        );

      res.json({
        ok: true,
        token,
        user: fresh.rows[0]
      });
    } catch (error) {
      console.error(
        "login:",
        error
      );

      res.status(500).json({
        ok: false,
        error:
          "Lỗi máy chủ."
      });
    }
  }
);


/* =========================================================
   LOGOUT
========================================================= */

app.post(
  "/api/auth/logout",
  auth,
  async (req, res) => {
    try {
      await q(
        `
          DELETE FROM sessions
          WHERE token_hash=$1
        `,
        [sha(req.token)]
      );

      res.json({
        ok: true
      });
    } catch (error) {
      console.error(
        "logout:",
        error
      );

      res.status(500).json({
        ok: false,
        error:
          "Không đăng xuất được."
      });
    }
  }
);


/* =========================================================
   CURRENT USER
========================================================= */

app.get(
  "/api/me",
  auth,
  async (req, res) => {
    try {
      const result =
        await q(
          `
            SELECT
              id,
              username,
              ttt,
              plays,
              biggest_win,
              total_won,
              created_at,
              last_login_at
            FROM users
            WHERE id=$1
          `,
          [req.user.id]
        );

      if (!result.rowCount) {
        return res.status(404).json({
          ok: false,
          error:
            "Không tìm thấy tài khoản."
        });
      }

      res.json({
        ok: true,
        user: result.rows[0]
      });
    } catch (error) {
      console.error(
        "me:",
        error
      );

      res.status(500).json({
        ok: false,
        error:
          "Lỗi máy chủ."
      });
    }
  }
);


/* =========================================================
   RANK
========================================================= */

app.get(
  "/api/rank",
  async (_req, res) => {
    try {
      const result =
        await q(
          `
            SELECT
              username,
              biggest_win,
              total_won,
              ttt
            FROM users
            ORDER BY
              total_won DESC,
              biggest_win DESC,
              id ASC
            LIMIT 20
          `
        );

      res.json({
        ok: true,
        rank: result.rows
      });
    } catch (error) {
      console.error(
        "rank:",
        error
      );

      res.status(500).json({
        ok: false,
        error:
          "Không lấy được bảng xếp hạng."
      });
    }
  }
);/* =========================================================
   TÀI XỈU - STATE
========================================================= */

app.get(
  "/api/tx/state",
  auth,
  async (req, res) => {
    try {
      const round = await getTxRound();

      const history = await q(`
        SELECT
          round_id,
          d1,
          d2,
          d3,
          total,
          side,
          created_at
        FROM tx_history
        ORDER BY id DESC
        LIMIT 30
      `);

      const totalsResult = await q(
        `
          SELECT
            side,
            COALESCE(SUM(amount), 0) AS amount
          FROM tx_bets
          WHERE round_id=$1
          GROUP BY side
        `,
        [round.id]
      );

      const totals = {
        tai: 0,
        xiu: 0
      };

      for (const item of totalsResult.rows) {
        if (
          item.side === "tai" ||
          item.side === "xiu"
        ) {
          totals[item.side] =
            Number(item.amount);
        }
      }

      const myStakeResult =
        await q(
          `
            SELECT
              COALESCE(SUM(amount), 0) AS amount
            FROM tx_bets
            WHERE
              round_id=$1
              AND user_id=$2
              AND settled=false
          `,
          [
            round.id,
            req.user.id
          ]
        );

      res.json({
        ok: true,

        serverNow: Date.now(),

        round: {
          id: round.id,

          status: round.status,

          startedAt:
            new Date(
              round.started_at
            ).getTime(),

          endsAt:
            new Date(
              round.ends_at
            ).getTime(),

          resultUntil:
            round.result_until
              ? new Date(
                  round.result_until
                ).getTime()
              : null,

          dice:
            round.status === "closed"
              ? [
                  round.d1,
                  round.d2,
                  round.d3
                ]
              : null,

          total:
            round.total,

          side:
            round.side
        },

        totals,

        myStake:
          Number(
            myStakeResult.rows[0]
              .amount
          ),

        history:
          history.rows
      });
    } catch (error) {
      console.error(
        "tx/state:",
        error
      );

      res.status(500).json({
        ok: false,
        error:
          "Không lấy được trạng thái Tài Xỉu."
      });
    }
  }
);


/* =========================================================
   TÀI XỈU - BET
========================================================= */

app.post(
  "/api/tx/bet",
  auth,
  async (req, res) => {
    const side =
      String(
        req.body?.side || ""
      ).toLowerCase();

    const amount =
      safeInteger(
        req.body?.amount
      );

    if (
      !["tai", "xiu"].includes(
        side
      )
    ) {
      return res.status(400).json({
        ok: false,
        error:
          "Cửa cược không hợp lệ."
      });
    }

    if (
      amount === null ||
      amount < 1000
    ) {
      return res.status(400).json({
        ok: false,
        error:
          "Số tiền cược tối thiểu là 1.000 TTT."
      });
    }

    const client =
      await pool.connect();

    try {
      await client.query(
        "BEGIN"
      );

      const roundResult =
        await client.query(
          `
            SELECT *
            FROM tx_rounds
            WHERE status='open'
            ORDER BY id DESC
            LIMIT 1
            FOR UPDATE
          `
        );

      if (
        !roundResult.rowCount
      ) {
        await client.query(
          "ROLLBACK"
        );

        return res.status(409).json({
          ok: false,
          error:
            "Hiện không có ván Tài Xỉu."
        });
      }

      const round =
        roundResult.rows[0];

      if (
        new Date(round.ends_at)
          .getTime() <= Date.now()
      ) {
        await client.query(
          "ROLLBACK"
        );

        return res.status(409).json({
          ok: false,
          error:
            "Ván đã hết thời gian cược."
        });
      }

      const userResult =
        await client.query(
          `
            SELECT
              id,
              ttt
            FROM users
            WHERE id=$1
            FOR UPDATE
          `,
          [req.user.id]
        );

      if (
        !userResult.rowCount
      ) {
        await client.query(
          "ROLLBACK"
        );

        return res.status(404).json({
          ok: false,
          error:
            "Không tìm thấy tài khoản."
        });
      }

      const balance =
        Number(
          userResult.rows[0].ttt
        );

      if (balance < amount) {
        await client.query(
          "ROLLBACK"
        );

        return res.status(400).json({
          ok: false,
          error:
            "Không đủ TTT."
        });
      }

      await client.query(
        `
          UPDATE users
          SET ttt=ttt-$1
          WHERE id=$2
        `,
        [
          amount,
          req.user.id
        ]
      );

      await client.query(
        `
          INSERT INTO tx_bets(
            round_id,
            user_id,
            side,
            amount
          )
          VALUES(
            $1,
            $2,
            $3,
            $4
          )
        `,
        [
          round.id,
          req.user.id,
          side,
          amount
        ]
      );

      await client.query(
        "COMMIT"
      );

      res.json({
        ok: true,
        roundId: round.id,
        side,
        amount
      });
    } catch (error) {
      try {
        await client.query(
          "ROLLBACK"
        );
      } catch {}

      console.error(
        "tx/bet:",
        error
      );

      res.status(500).json({
        ok: false,
        error:
          "Không đặt được cược."
      });
    } finally {
      client.release();
    }
  }
);


/* =========================================================
   XÓC ĐĨA - STATE
========================================================= */

app.get(
  "/api/xd/state",
  auth,
  async (req, res) => {
    try {
      const round =
        await getXdRound();

      const history =
        await q(`
          SELECT
            round_id,
            red_count,
            white_count,
            side,
            multiplier,
            created_at
          FROM xd_history
          ORDER BY id DESC
          LIMIT 30
        `);

      const totalsResult =
        await q(
          `
            SELECT
              side,
              COALESCE(SUM(amount), 0) AS amount
            FROM xd_bets
            WHERE round_id=$1
            GROUP BY side
          `,
          [round.id]
        );

      const totals = {
        chan: 0,
        le: 0
      };

      for (
        const item of totalsResult.rows
      ) {
        if (
          item.side === "chan" ||
          item.side === "le"
        ) {
          totals[item.side] =
            Number(item.amount);
        }
      }

      const myStakeResult =
        await q(
          `
            SELECT
              COALESCE(SUM(amount), 0) AS amount
            FROM xd_bets
            WHERE
              round_id=$1
              AND user_id=$2
              AND settled=false
          `,
          [
            round.id,
            req.user.id
          ]
        );

      res.json({
        ok: true,

        serverNow: Date.now(),

        round: {
          id: round.id,

          status: round.status,

          startedAt:
            new Date(
              round.started_at
            ).getTime(),

          endsAt:
            new Date(
              round.ends_at
            ).getTime(),

          resultUntil:
            round.result_until
              ? new Date(
                  round.result_until
                ).getTime()
              : null,

          redCount:
            round.red_count,

          whiteCount:
            round.white_count,

          side:
            round.side,

          multiplier:
            round.multiplier
              ? Number(
                  round.multiplier
                )
              : null
        },

        totals,

        myStake:
          Number(
            myStakeResult.rows[0]
              .amount
          ),

        history:
          history.rows
      });
    } catch (error) {
      console.error(
        "xd/state:",
        error
      );

      res.status(500).json({
        ok: false,
        error:
          "Không lấy được trạng thái Xóc Đĩa."
      });
    }
  }
);


/* =========================================================
   XÓC ĐĨA - BET
========================================================= */

app.post(
  "/api/xd/bet",
  auth,
  async (req, res) => {
    const side =
      String(
        req.body?.side || ""
      ).toLowerCase();

    const amount =
      safeInteger(
        req.body?.amount
      );

    if (
      !["chan", "le"].includes(
        side
      )
    ) {
      return res.status(400).json({
        ok: false,
        error:
          "Cửa cược không hợp lệ."
      });
    }

    if (
      amount === null ||
      amount < 1000
    ) {
      return res.status(400).json({
        ok: false,
        error:
          "Số tiền cược tối thiểu là 1.000 TTT."
      });
    }

    const client =
      await pool.connect();

    try {
      await client.query(
        "BEGIN"
      );

      const roundResult =
        await client.query(
          `
            SELECT *
            FROM xd_rounds
            WHERE status='open'
            ORDER BY id DESC
            LIMIT 1
            FOR UPDATE
          `
        );

      if (
        !roundResult.rowCount
      ) {
        await client.query(
          "ROLLBACK"
        );

        return res.status(409).json({
          ok: false,
          error:
            "Hiện không có ván Xóc Đĩa."
        });
      }

      const round =
        roundResult.rows[0];

      if (
        new Date(round.ends_at)
          .getTime() <= Date.now()
      ) {
        await client.query(
          "ROLLBACK"
        );

        return res.status(409).json({
          ok: false,
          error:
            "Ván đã hết thời gian cược."
        });
      }

      const userResult =
        await client.query(
          `
            SELECT
              id,
              ttt
            FROM users
            WHERE id=$1
            FOR UPDATE
          `,
          [req.user.id]
        );

      if (
        !userResult.rowCount
      ) {
        await client.query(
          "ROLLBACK"
        );

        return res.status(404).json({
          ok: false,
          error:
            "Không tìm thấy tài khoản."
        });
      }

      const balance =
        Number(
          userResult.rows[0].ttt
        );

      if (balance < amount) {
        await client.query(
          "ROLLBACK"
        );

        return res.status(400).json({
          ok: false,
          error:
            "Không đủ TTT."
        });
      }

      await client.query(
        `
          UPDATE users
          SET ttt=ttt-$1
          WHERE id=$2
        `,
        [
          amount,
          req.user.id
        ]
      );

      await client.query(
        `
          INSERT INTO xd_bets(
            round_id,
            user_id,
            side,
            amount
          )
          VALUES(
            $1,
            $2,
            $3,
            $4
          )
        `,
        [
          round.id,
          req.user.id,
          side,
          amount
        ]
      );

      await client.query(
        "COMMIT"
      );

      res.json({
        ok: true,
        roundId: round.id,
        side,
        amount
      });
    } catch (error) {
      try {
        await client.query(
          "ROLLBACK"
        );
      } catch {}

      console.error(
        "xd/bet:",
        error
      );

      res.status(500).json({
        ok: false,
        error:
          "Không đặt được cược."
      });
    } finally {
      client.release();
    }
  }
);


/* =========================================================
   NHẬN CODE THƯỞNG
========================================================= */

app.post(
  "/api/redeem",
  auth,
  async (req, res) => {
    const code =
      String(
        req.body?.code || ""
      )
        .trim()
        .toUpperCase();

    if (!code) {
      return res.status(400).json({
        ok: false,
        error:
          "Vui lòng nhập code."
      });
    }

    const client =
      await pool.connect();

    try {
      await client.query(
        "BEGIN"
      );

      const result =
        await client.query(
          `
            SELECT *
            FROM redeem_codes
            WHERE
              code=$1
              AND active=true
              AND (
                expires_at IS NULL
                OR expires_at > NOW()
              )
            FOR UPDATE
          `,
          [code]
        );

      if (!result.rowCount) {
        await client.query(
          "ROLLBACK"
        );

        return res.status(404).json({
          ok: false,
          error:
            "Code không tồn tại, đã khóa hoặc hết hạn."
        });
      }

      const item =
        result.rows[0];

      if (
        item.max_uses > 0 &&
        item.uses >= item.max_uses
      ) {
        await client.query(
          "ROLLBACK"
        );

        return res.status(409).json({
          ok: false,
          error:
            "Code đã hết lượt sử dụng."
        });
      }

      /*
        Chống trường hợp 2 request
        cùng lúc dùng chung code.
      */

      const nextUses =
        Number(item.uses) + 1;

      const shouldDisable =
        item.max_uses > 0 &&
        nextUses >=
          Number(item.max_uses);

      await client.query(
        `
          UPDATE redeem_codes
          SET
            uses=$1,
            active=
              CASE
                WHEN $2
                THEN false
                ELSE active
              END
          WHERE id=$3
        `,
        [
          nextUses,
          shouldDisable,
          item.id
        ]
      );

      await client.query(
        `
          UPDATE users
          SET ttt=ttt+$1
          WHERE id=$2
        `,
        [
          Number(item.reward),
          req.user.id
        ]
      );

      await client.query(
        "COMMIT"
      );

      const userResult =
        await q(
          `
            SELECT
              id,
              username,
              ttt,
              plays,
              biggest_win,
              total_won
            FROM users
            WHERE id=$1
          `,
          [req.user.id]
        );

      res.json({
        ok: true,

        code,

        reward:
          Number(item.reward),

        user:
          userResult.rows[0]
      });
    } catch (error) {
      try {
        await client.query(
          "ROLLBACK"
        );
      } catch {}

      console.error(
        "redeem:",
        error
      );

      res.status(500).json({
        ok: false,
        error:
          "Không xử lý được code."
      });
    } finally {
      client.release();
    }
  }
);


/* =========================================================
   KIỂM TRA CODE - KHÔNG TIẾT LỘ REWARD
========================================================= */

app.get(
  "/api/redeem/check",
  auth,
  async (req, res) => {
    const code =
      String(
        req.query?.code || ""
      )
        .trim()
        .toUpperCase();

    if (!code) {
      return res.status(400).json({
        ok: false,
        error:
          "Thiếu code."
      });
    }

    try {
      const result =
        await q(
          `
            SELECT
              code,
              reward,
              max_uses,
              uses,
              active,
              expires_at
            FROM redeem_codes
            WHERE code=$1
            LIMIT 1
          `,
          [code]
        );

      if (!result.rowCount) {
        return res.status(404).json({
          ok: false,
          valid: false,
          error:
            "Code không tồn tại."
        });
      }

      const item =
        result.rows[0];

      const expired =
        item.expires_at &&
        new Date(
          item.expires_at
        ) <= now();

      const exhausted =
        item.max_uses > 0 &&
        item.uses >=
          item.max_uses;

      const valid =
        item.active &&
        !expired &&
        !exhausted;

      res.json({
        ok: true,
        valid,

        code: item.code,

        reward:
          valid
            ? Number(item.reward)
            : 0,

        remaining:
          item.max_uses > 0
            ? Math.max(
                0,
                Number(
                  item.max_uses
                ) -
                  Number(
                    item.uses
                  )
              )
            : null,

        expiresAt:
          item.expires_at
            ? new Date(
                item.expires_at
              ).getTime()
            : null
      });
    } catch (error) {
      console.error(
        "redeem/check:",
        error
      );

      res.status(500).json({
        ok: false,
        error:
          "Không kiểm tra được code."
      });
    }
  }
);


/* =========================================================
   XÓA SESSION HẾT HẠN TỰ ĐỘNG
========================================================= */

async function cleanupSessions() {
  try {
    await q(`
      DELETE FROM sessions
      WHERE expires_at <= NOW()
    `);
  } catch (error) {
    console.error(
      "cleanupSessions:",
      error
    );
  }
}


/* =========================================================
   USER STATISTICS
========================================================= */

app.get(
  "/api/me/stats",
  auth,
  async (req, res) => {
    try {
      const userResult =
        await q(
          `
            SELECT
              id,
              username,
              ttt,
              plays,
              biggest_win,
              total_won,
              created_at,
              last_login_at
            FROM users
            WHERE id=$1
          `,
          [req.user.id]
        );

      if (!userResult.rowCount) {
        return res.status(404).json({
          ok: false,
          error:
            "Không tìm thấy tài khoản."
        });
      }

      const txResult =
        await q(
          `
            SELECT
              COUNT(*)::int AS bets,
              COALESCE(
                SUM(amount),
                0
              ) AS total_bet,
              COALESCE(
                SUM(win_ttt),
                0
              ) AS total_win
            FROM tx_bets
            WHERE user_id=$1
          `,
          [req.user.id]
        );

      const xdResult =
        await q(
          `
            SELECT
              COUNT(*)::int AS bets,
              COALESCE(
                SUM(amount),
                0
              ) AS total_bet,
              COALESCE(
                SUM(win_ttt),
                0
              ) AS total_win
            FROM xd_bets
            WHERE user_id=$1
          `,
          [req.user.id]
        );

      res.json({
        ok: true,

        user:
          userResult.rows[0],

        taiXiu:
          txResult.rows[0],

        xocDia:
          xdResult.rows[0]
      });
    } catch (error) {
      console.error(
        "me/stats:",
        error
      );

      res.status(500).json({
        ok: false,
        error:
          "Không lấy được thống kê."
      });
    }
  }
);/* =========================================================
   ADMIN - DANH SÁCH CODE
========================================================= */

app.get(
  "/api/admin/codes",
  admin,
  async (_req, res) => {
    try {
      const result = await q(`
        SELECT
          id,
          code,
          reward,
          max_uses,
          uses,
          active,
          created_at,
          expires_at
        FROM redeem_codes
        ORDER BY id DESC
        LIMIT 500
      `);

      res.json({
        ok: true,
        total: result.rowCount,
        codes: result.rows
      });
    } catch (error) {
      console.error(
        "admin/codes:",
        error
      );

      res.status(500).json({
        ok: false,
        error:
          "Không lấy được danh sách code."
      });
    }
  }
);


/* =========================================================
   ADMIN - TẠO CODE
========================================================= */

app.post(
  "/api/admin/codes",
  admin,
  async (req, res) => {
    const reward =
      safeInteger(
        req.body?.reward
      );

    const maxUses =
      safeInteger(
        req.body?.maxUses ?? 1
      );

    let code =
      String(
        req.body?.code || ""
      )
        .trim()
        .toUpperCase()
        .replace(
          /[^A-Z0-9_-]/g,
          ""
        );

    const expiresAt =
      req.body?.expiresAt
        ? new Date(
            req.body.expiresAt
          )
        : null;

    if (
      reward === null ||
      reward <= 0
    ) {
      return res.status(400).json({
        ok: false,
        error:
          "Reward không hợp lệ."
      });
    }

    if (
      maxUses === null ||
      maxUses < 0
    ) {
      return res.status(400).json({
        ok: false,
        error:
          "Số lượt sử dụng không hợp lệ."
      });
    }

    if (
      expiresAt &&
      Number.isNaN(
        expiresAt.getTime()
      )
    ) {
      return res.status(400).json({
        ok: false,
        error:
          "Ngày hết hạn không hợp lệ."
      });
    }

    /*
      maxUses = 0
      nghĩa là không giới hạn lượt.
    */

    if (!code) {
      code =
        `TTT-${crypto
          .randomBytes(5)
          .toString("hex")
          .toUpperCase()}`;
    }

    if (code.length > 40) {
      return res.status(400).json({
        ok: false,
        error:
          "Code tối đa 40 ký tự."
      });
    }

    try {
      const result =
        await q(
          `
            INSERT INTO redeem_codes(
              code,
              reward,
              max_uses,
              expires_at
            )
            VALUES(
              $1,
              $2,
              $3,
              $4
            )
            RETURNING
              id,
              code,
              reward,
              max_uses,
              uses,
              active,
              created_at,
              expires_at
          `,
          [
            code,
            reward,
            maxUses,
            expiresAt
          ]
        );

      res.json({
        ok: true,
        code:
          result.rows[0]
      });
    } catch (error) {
      if (
        error.code === "23505"
      ) {
        return res.status(409).json({
          ok: false,
          error:
            "Code đã tồn tại."
        });
      }

      console.error(
        "admin/create-code:",
        error
      );

      res.status(500).json({
        ok: false,
        error:
          "Không tạo được code."
      });
    }
  }
);


/* =========================================================
   ADMIN - BẬT / TẮT CODE
========================================================= */

app.post(
  "/api/admin/codes/toggle",
  admin,
  async (req, res) => {
    const id =
      safeInteger(
        req.body?.id
      );

    if (
      id === null ||
      id <= 0
    ) {
      return res.status(400).json({
        ok: false,
        error:
          "ID code không hợp lệ."
      });
    }

    try {
      const result =
        await q(
          `
            UPDATE redeem_codes
            SET active=NOT active
            WHERE id=$1
            RETURNING
              id,
              code,
              reward,
              max_uses,
              uses,
              active,
              created_at,
              expires_at
          `,
          [id]
        );

      if (!result.rowCount) {
        return res.status(404).json({
          ok: false,
          error:
            "Không tìm thấy code."
        });
      }

      res.json({
        ok: true,
        code:
          result.rows[0]
      });
    } catch (error) {
      console.error(
        "admin/toggle-code:",
        error
      );

      res.status(500).json({
        ok: false,
        error:
          "Không cập nhật được code."
      });
    }
  }
);


/* =========================================================
   ADMIN - XÓA CODE
========================================================= */

app.delete(
  "/api/admin/codes/:id",
  admin,
  async (req, res) => {
    const id =
      safeInteger(
        req.params.id
      );

    if (
      id === null ||
      id <= 0
    ) {
      return res.status(400).json({
        ok: false,
        error:
          "ID code không hợp lệ."
      });
    }

    try {
      const result =
        await q(
          `
            DELETE FROM redeem_codes
            WHERE id=$1
            RETURNING id,code
          `,
          [id]
        );

      if (!result.rowCount) {
        return res.status(404).json({
          ok: false,
          error:
            "Không tìm thấy code."
        });
      }

      res.json({
        ok: true,
        deleted:
          result.rows[0]
      });
    } catch (error) {
      console.error(
        "admin/delete-code:",
        error
      );

      res.status(500).json({
        ok: false,
        error:
          "Không xóa được code."
      });
    }
  }
);


/* =========================================================
   ADMIN - DANH SÁCH TÀI KHOẢN
========================================================= */

app.get(
  "/api/admin/users",
  admin,
  async (req, res) => {
    const search =
      String(
        req.query?.search || ""
      ).trim();

    const params = [];

    let where = "";

    if (search) {
      params.push(
        `%${search.toLowerCase()}%`
      );

      where =
        "WHERE lower(u.username) LIKE $1";
    }

    try {
      const result =
        await q(
          `
            SELECT
              u.id,
              u.username,
              u.ttt,
              u.plays,
              u.biggest_win,
              u.total_won,
              u.created_at,
              u.last_login_at,

              COALESCE(
                (
                  SELECT COUNT(*)
                  FROM sessions s
                  WHERE
                    s.user_id=u.id
                    AND s.expires_at>NOW()
                ),
                0
              )::int AS active_sessions

            FROM users u

            ${where}

            ORDER BY u.id DESC
          `,
          params
        );

      res.json({
        ok: true,
        total:
          result.rowCount,
        users:
          result.rows
      });
    } catch (error) {
      console.error(
        "admin/users:",
        error
      );

      res.status(500).json({
        ok: false,
        error:
          "Không lấy được danh sách tài khoản."
      });
    }
  }
);


/* =========================================================
   ADMIN - CHI TIẾT 1 TÀI KHOẢN
========================================================= */

app.get(
  "/api/admin/users/:id",
  admin,
  async (req, res) => {
    const id =
      safeInteger(
        req.params.id
      );

    if (
      id === null ||
      id <= 0
    ) {
      return res.status(400).json({
        ok: false,
        error:
          "ID tài khoản không hợp lệ."
      });
    }

    try {
      const userResult =
        await q(
          `
            SELECT
              id,
              username,
              ttt,
              plays,
              biggest_win,
              total_won,
              created_at,
              last_login_at
            FROM users
            WHERE id=$1
          `,
          [id]
        );

      if (!userResult.rowCount) {
        return res.status(404).json({
          ok: false,
          error:
            "Không tìm thấy tài khoản."
        });
      }

      const txResult =
        await q(
          `
            SELECT
              COUNT(*)::int AS bets,
              COALESCE(
                SUM(amount),
                0
              ) AS total_bet,
              COALESCE(
                SUM(win_ttt),
                0
              ) AS total_win
            FROM tx_bets
            WHERE user_id=$1
          `,
          [id]
        );

      const xdResult =
        await q(
          `
            SELECT
              COUNT(*)::int AS bets,
              COALESCE(
                SUM(amount),
                0
              ) AS total_bet,
              COALESCE(
                SUM(win_ttt),
                0
              ) AS total_win
            FROM xd_bets
            WHERE user_id=$1
          `,
          [id]
        );

      res.json({
        ok: true,

        user:
          userResult.rows[0],

        taiXiu:
          txResult.rows[0],

        xocDia:
          xdResult.rows[0]
      });
    } catch (error) {
      console.error(
        "admin/user-detail:",
        error
      );

      res.status(500).json({
        ok: false,
        error:
          "Không lấy được thông tin tài khoản."
      });
    }
  }
);


/* =========================================================
   ADMIN - KẾT QUẢ TÀI XỈU
========================================================= */

app.get(
  "/api/admin/results/tx",
  admin,
  async (_req, res) => {
    try {
      const result =
        await q(`
          SELECT
            r.id,
            r.started_at,
            r.ends_at,
            r.status,
            r.d1,
            r.d2,
            r.d3,
            r.total,
            r.side,
            r.result_until,

            COALESCE(
              (
                SELECT SUM(b.amount)
                FROM tx_bets b
                WHERE b.round_id=r.id
              ),
              0
            ) AS total_bet,

            COALESCE(
              (
                SELECT SUM(b.win_ttt)
                FROM tx_bets b
                WHERE b.round_id=r.id
              ),
              0
            ) AS total_paid

          FROM tx_rounds r

          ORDER BY r.id DESC

          LIMIT 100
        `);

      res.json({
        ok: true,
        results:
          result.rows
      });
    } catch (error) {
      console.error(
        "admin/results/tx:",
        error
      );

      res.status(500).json({
        ok: false,
        error:
          "Không lấy được kết quả Tài Xỉu."
      });
    }
  }
);


/* =========================================================
   ADMIN - KẾT QUẢ XÓC ĐĨA
========================================================= */

app.get(
  "/api/admin/results/xd",
  admin,
  async (_req, res) => {
    try {
      const result =
        await q(`
          SELECT
            r.id,
            r.started_at,
            r.ends_at,
            r.status,
            r.red_count,
            r.white_count,
            r.side,
            r.multiplier,
            r.result_until,

            COALESCE(
              (
                SELECT SUM(b.amount)
                FROM xd_bets b
                WHERE b.round_id=r.id
              ),
              0
            ) AS total_bet,

            COALESCE(
              (
                SELECT SUM(b.win_ttt)
                FROM xd_bets b
                WHERE b.round_id=r.id
              ),
              0
            ) AS total_paid

          FROM xd_rounds r

          ORDER BY r.id DESC

          LIMIT 100
        `);

      res.json({
        ok: true,
        results:
          result.rows
      });
    } catch (error) {
      console.error(
        "admin/results/xd:",
        error
      );

      res.status(500).json({
        ok: false,
        error:
          "Không lấy được kết quả Xóc Đĩa."
      });
    }
  }
);


/* =========================================================
   ADMIN - TỔNG QUAN
========================================================= */

app.get(
  "/api/admin/overview",
  admin,
  async (_req, res) => {
    try {
      const users =
        await q(`
          SELECT COUNT(*)::int AS total
          FROM users
        `);

      const codes =
        await q(`
          SELECT COUNT(*)::int AS total
          FROM redeem_codes
        `);

      const activeCodes =
        await q(`
          SELECT COUNT(*)::int AS total
          FROM redeem_codes
          WHERE active=true
        `);

      const txRounds =
        await q(`
          SELECT COUNT(*)::int AS total
          FROM tx_rounds
        `);

      const xdRounds =
        await q(`
          SELECT COUNT(*)::int AS total
          FROM xd_rounds
        `);

      const totalTtt =
        await q(`
          SELECT
            COALESCE(
              SUM(ttt),
              0
            ) AS total
          FROM users
        `);

      res.json({
        ok: true,

        users:
          Number(
            users.rows[0].total
          ),

        codes:
          Number(
            codes.rows[0].total
          ),

        activeCodes:
          Number(
            activeCodes.rows[0].total
          ),

        txRounds:
          Number(
            txRounds.rows[0].total
          ),

        xdRounds:
          Number(
            xdRounds.rows[0].total
          ),

        totalTtt:
          Number(
            totalTtt.rows[0].total
          )
      });
    } catch (error) {
      console.error(
        "admin/overview:",
        error
      );

      res.status(500).json({
        ok: false,
        error:
          "Không lấy được tổng quan."
      });
    }
  }
);


/* =========================================================
   ROOT
========================================================= */

app.get(
  "/",
  (_req, res) => {
    res.json({
      ok: true,
      service:
        "TTT9-9-9 server",
      status:
        "online",
      version:
        "4.0"
    });
  }
);


/* =========================================================
   404 API
========================================================= */

app.use(
  (req, res) => {
    res.status(404).json({
      ok: false,
      error:
        "API không tồn tại.",
      path:
        req.path
    });
  }
);


/* =========================================================
   ERROR HANDLER
========================================================= */

app.use(
  (error, _req, res, _next) => {
    console.error(
      "EXPRESS ERROR:",
      error
    );

    res.status(500).json({
      ok: false,
      error:
        "Lỗi máy chủ."
    });
  }
);


/* =========================================================
   START SERVER
========================================================= */

async function start() {
  try {
    if (!DATABASE_URL) {
      console.error(
        "START FAILED: DATABASE_URL chưa được cấu hình."
      );

      process.exit(1);
    }

    await initDb();

    const ready =
      await databaseReady();

    if (!ready) {
      console.error(
        "START FAILED: Database không kết nối được."
      );

      process.exit(1);
    }

    app.listen(
      PORT,
      "0.0.0.0",
      () => {
        console.log(
          "========================================"
        );

        console.log(
          `TTT9-9-9 SERVER LISTENING ON ${PORT}`
        );

        console.log(
          "DATABASE: CONNECTED"
        );

        console.log(
          "GAME: TAI XIU + XOC DIA"
        );

        console.log(
          "AUTH: REGISTER + LOGIN"
        );

        console.log(
          "REDEEM: ENABLED"
        );

        console.log(
          "ADMIN API: ENABLED"
        );

        console.log(
          "========================================"
        );
      }
    );

    /*
      Kiểm tra game mỗi giây.
    */

    setInterval(
      tick,
      1000
    );

    /*
      Dọn session hết hạn
      mỗi 10 phút.
    */

    setInterval(
      cleanupSessions,
      10 * 60 * 1000
    );

    /*
      Chạy tick ngay khi server start.
    */

    await tick();

  } catch (error) {
    console.error(
      "========================================"
    );

    console.error(
      "START FAILED"
    );

    console.error(
      error
    );

    console.error(
      "========================================"
    );

    process.exit(1);
  }
}


/* =========================================================
   START
========================================================= */

start();
