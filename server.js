import express from "express";
import pg from "pg";
import crypto from "crypto";
import path from "path";
import { fileURLToPath } from "url";

const { Pool } = pg;
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();

app.use(express.json({ limit: "1mb" }));
app.use((req,res,next)=>{
  res.setHeader("Access-Control-Allow-Origin","*");
  res.setHeader("Access-Control-Allow-Headers","Content-Type, Authorization, x-admin-key");
  res.setHeader("Access-Control-Allow-Methods","GET,POST,PATCH,DELETE,OPTIONS");
  if(req.method==="OPTIONS") return res.sendStatus(204);
  next();
});


const PORT = Number(process.env.PORT || 10000);
const DATABASE_URL = process.env.DATABASE_URL || "";
const ADMIN_KEY = process.env.ADMIN_KEY || "CHANGE_ME_ADMIN_KEY";

const GAME_SECONDS = 30;
const RESULT_SECONDS = 7;
const TX_PAYOUT = 1.95;
const XD_NORMAL_PAYOUT = 1.95;
const XD_JACKPOT_START = 100000000;
const SESSION_DAYS = 30;

if (!DATABASE_URL) console.error("DATABASE_URL is missing. Add it in Render Environment.");

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: false } : false
});

const now = () => new Date();
const sha = s => crypto.createHash("sha256").update(String(s)).digest("hex");
const makeToken = () => crypto.randomBytes(32).toString("hex");

function makePasswordHash(password, salt = crypto.randomBytes(16).toString("hex")) {
  const key = crypto.scryptSync(password, salt, 64).toString("hex");
  return `${salt}:${key}`;
}
function verifyPassword(password, stored) {
  const [salt, expected] = String(stored || "").split(":");
  if (!salt || !expected) return false;
  const got = crypto.scryptSync(password, salt, 64).toString("hex");
  return crypto.timingSafeEqual(Buffer.from(got), Buffer.from(expected));
}
async function q(sql, params = []) { return pool.query(sql, params); }

async function initDb() {
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMPTZ`);

  await q(`
    CREATE TABLE IF NOT EXISTS users(
      id BIGSERIAL PRIMARY KEY,
      username VARCHAR(24) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      ttt BIGINT NOT NULL DEFAULT 0,
      plays BIGINT NOT NULL DEFAULT 0,
      biggest_win BIGINT NOT NULL DEFAULT 0,
      total_won BIGINT NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  await q(`
    CREATE TABLE IF NOT EXISTS sessions(
      token_hash CHAR(64) PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      expires_at TIMESTAMPTZ NOT NULL
    )
  `);
  await q(`
    CREATE TABLE IF NOT EXISTS redeem_codes(
      id BIGSERIAL PRIMARY KEY,
      code VARCHAR(40) UNIQUE NOT NULL,
      reward BIGINT NOT NULL CHECK(reward > 0),
      max_uses INT NOT NULL DEFAULT 1,
      uses INT NOT NULL DEFAULT 0,
      active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  await q(`
    CREATE TABLE IF NOT EXISTS tx_rounds(
      id BIGSERIAL PRIMARY KEY,
      started_at TIMESTAMPTZ NOT NULL,
      ends_at TIMESTAMPTZ NOT NULL,
      status VARCHAR(12) NOT NULL DEFAULT 'open',
      d1 SMALLINT, d2 SMALLINT, d3 SMALLINT,
      total SMALLINT, side VARCHAR(5),
      result_until TIMESTAMPTZ
    )
  `);
  await q(`
    CREATE TABLE IF NOT EXISTS tx_bets(
      id BIGSERIAL PRIMARY KEY,
      round_id BIGINT NOT NULL REFERENCES tx_rounds(id) ON DELETE CASCADE,
      user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      side VARCHAR(4) NOT NULL CHECK(side IN('tai','xiu')),
      amount BIGINT NOT NULL CHECK(amount > 0),
      settled BOOLEAN NOT NULL DEFAULT FALSE,
      win_ttt BIGINT NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  await q(`
    CREATE TABLE IF NOT EXISTS tx_history(
      id BIGSERIAL PRIMARY KEY,
      round_id BIGINT UNIQUE NOT NULL REFERENCES tx_rounds(id) ON DELETE CASCADE,
      d1 SMALLINT NOT NULL, d2 SMALLINT NOT NULL, d3 SMALLINT NOT NULL,
      total SMALLINT NOT NULL, side VARCHAR(5) NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  await q(`
    CREATE TABLE IF NOT EXISTS xd_rounds(
      id BIGSERIAL PRIMARY KEY,
      started_at TIMESTAMPTZ NOT NULL,
      ends_at TIMESTAMPTZ NOT NULL,
      status VARCHAR(12) NOT NULL DEFAULT 'open',
      red_count SMALLINT, white_count SMALLINT,
      side VARCHAR(5), multiplier NUMERIC(8,2),
      result_until TIMESTAMPTZ
    )
  `);

  // Migrations: add columns that older versions may not have.
  await q(`ALTER TABLE redeem_codes ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ`);
  await q(`ALTER TABLE xd_rounds ADD COLUMN IF NOT EXISTS red_count SMALLINT`);
  await q(`ALTER TABLE xd_rounds ADD COLUMN IF NOT EXISTS white_count SMALLINT`);
  await q(`ALTER TABLE xd_rounds ADD COLUMN IF NOT EXISTS side VARCHAR(5)`);
  await q(`ALTER TABLE xd_rounds ADD COLUMN IF NOT EXISTS multiplier NUMERIC(8,2)`);
  await q(`ALTER TABLE xd_rounds ADD COLUMN IF NOT EXISTS result_until TIMESTAMPTZ`);

  await q(`
    CREATE TABLE IF NOT EXISTS xd_bets(
      id BIGSERIAL PRIMARY KEY,
      round_id BIGINT NOT NULL REFERENCES xd_rounds(id) ON DELETE CASCADE,
      user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      side VARCHAR(4) NOT NULL CHECK(side IN('chan','le')),
      amount BIGINT NOT NULL CHECK(amount > 0),
      settled BOOLEAN NOT NULL DEFAULT FALSE,
      win_ttt BIGINT NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  await q(`
    CREATE TABLE IF NOT EXISTS xd_history(
      id BIGSERIAL PRIMARY KEY,
      round_id BIGINT UNIQUE NOT NULL REFERENCES xd_rounds(id) ON DELETE CASCADE,
      red_count SMALLINT NOT NULL, white_count SMALLINT NOT NULL,
      side VARCHAR(5) NOT NULL, multiplier NUMERIC(8,2) NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  if (!(await q(`SELECT 1 FROM tx_rounds LIMIT 1`)).rowCount) await createTxRound();
  if (!(await q(`SELECT 1 FROM xd_rounds LIMIT 1`)).rowCount) await createXdRound();
}

async function createTxRound() {
  const started = now(), ends = new Date(started.getTime() + GAME_SECONDS * 1000);
  await q(`INSERT INTO tx_rounds(started_at,ends_at,status) VALUES($1,$2,'open')`, [started, ends]);
}
async function createXdRound() {
  const started = now(), ends = new Date(started.getTime() + GAME_SECONDS * 1000);
  await q(`INSERT INTO xd_rounds(started_at,ends_at,status) VALUES($1,$2,'open')`, [started, ends]);
}
async function getTxRound() {
  let r = await q(`SELECT * FROM tx_rounds ORDER BY id DESC LIMIT 1`);
  if (!r.rowCount) { await createTxRound(); r = await q(`SELECT * FROM tx_rounds ORDER BY id DESC LIMIT 1`); }
  const x = r.rows[0];
  if (x.status === "closed" && x.result_until && new Date(x.result_until) <= now()) {
    await createTxRound();
    r = await q(`SELECT * FROM tx_rounds ORDER BY id DESC LIMIT 1`);
  }
  return r.rows[0];
}
async function getXdRound() {
  let r = await q(`SELECT * FROM xd_rounds ORDER BY id DESC LIMIT 1`);
  if (!r.rowCount) { await createXdRound(); r = await q(`SELECT * FROM xd_rounds ORDER BY id DESC LIMIT 1`); }
  const x = r.rows[0];
  if (x.status === "closed" && x.result_until && new Date(x.result_until) <= now()) {
    await createXdRound();
    r = await q(`SELECT * FROM xd_rounds ORDER BY id DESC LIMIT 1`);
  }
  return r.rows[0];
}

function txSide(a,b,c) {
  const total = a+b+c;
  if (a===b && b===c) return total >= 12 ? "TÀI" : "XỈU";
  return total >= 11 ? "TÀI" : "XỈU";
}

async function settleTx(round) {
  const c = await pool.connect();
  try {
    await c.query("BEGIN");
    const locked = await c.query(`SELECT * FROM tx_rounds WHERE id=$1 FOR UPDATE`, [round.id]);
    if (!locked.rowCount || locked.rows[0].status !== "open") { await c.query("ROLLBACK"); return; }
    const d1 = crypto.randomInt(1,7), d2 = crypto.randomInt(1,7), d3 = crypto.randomInt(1,7);
    const total = d1+d2+d3, side = txSide(d1,d2,d3);
    const resultUntil = new Date(Date.now() + RESULT_SECONDS*1000);
    await c.query(`
      UPDATE tx_rounds SET status='closed',d1=$2,d2=$3,d3=$4,total=$5,side=$6,result_until=$7 WHERE id=$1
    `,[round.id,d1,d2,d3,total,side,resultUntil]);
    await c.query(`
      INSERT INTO tx_history(round_id,d1,d2,d3,total,side) VALUES($1,$2,$3,$4,$5,$6)
      ON CONFLICT(round_id) DO NOTHING
    `,[round.id,d1,d2,d3,total,side]);
    const bets = await c.query(`SELECT * FROM tx_bets WHERE round_id=$1 AND settled=false FOR UPDATE`,[round.id]);
    for (const b of bets.rows) {
      const win = b.side === (side==="TÀI" ? "tai" : "xiu") ? Math.floor(Number(b.amount)*TX_PAYOUT) : 0;
      await c.query(`
        UPDATE users SET ttt=ttt+$1,plays=plays+1,biggest_win=GREATEST(biggest_win,$1),total_won=total_won+$1 WHERE id=$2
      `,[win,b.user_id]);
      await c.query(`UPDATE tx_bets SET settled=true,win_ttt=$1 WHERE id=$2`,[win,b.id]);
    }
    await c.query("COMMIT");
  } catch(e) { try { await c.query("ROLLBACK"); } catch {} console.error("settleTx",e); }
  finally { c.release(); }
}
async function settleXd(round) {
  const c = await pool.connect();
  try {
    await c.query("BEGIN");
    const locked = await c.query(`SELECT * FROM xd_rounds WHERE id=$1 FOR UPDATE`,[round.id]);
    if (!locked.rowCount || locked.rows[0].status !== "open") { await c.query("ROLLBACK"); return; }
    const red = crypto.randomInt(0,5), white = 4-red;
    const side = red % 2 === 0 ? "CHẴN" : "LẺ";
    const multiplier = (red===0 || red===4) ? 16 : (red===1 || red===3) ? 4 : XD_NORMAL_PAYOUT;
    const resultUntil = new Date(Date.now() + RESULT_SECONDS*1000);
    await c.query(`
      UPDATE xd_rounds SET status='closed',red_count=$2,white_count=$3,side=$4,multiplier=$5,result_until=$6 WHERE id=$1
    `,[round.id,red,white,side,multiplier,resultUntil]);
    await c.query(`
      INSERT INTO xd_history(round_id,red_count,white_count,side,multiplier)
      VALUES($1,$2,$3,$4,$5) ON CONFLICT(round_id) DO NOTHING
    `,[round.id,red,white,side,multiplier]);
    const bets = await c.query(`SELECT * FROM xd_bets WHERE round_id=$1 AND settled=false FOR UPDATE`,[round.id]);
    for (const b of bets.rows) {
      const win = b.side === (side==="CHẴN" ? "chan" : "le") ? Math.floor(Number(b.amount)*multiplier) : 0;
      await c.query(`
        UPDATE users SET ttt=ttt+$1,plays=plays+1,biggest_win=GREATEST(biggest_win,$1),total_won=total_won+$1 WHERE id=$2
      `,[win,b.user_id]);
      await c.query(`UPDATE xd_bets SET settled=true,win_ttt=$1 WHERE id=$2`,[win,b.id]);
    }
    await c.query("COMMIT");
  } catch(e) { try { await c.query("ROLLBACK"); } catch {} console.error("settleXd",e); }
  finally { c.release(); }
}
async function tick() {
  try {
    const t = Date.now();
    const tx = await getTxRound();
    if (tx.status==="open" && new Date(tx.ends_at).getTime()<=t) await settleTx(tx);
    const xd = await getXdRound();
    if (xd.status==="open" && new Date(xd.ends_at).getTime()<=t) await settleXd(xd);
  } catch(e) { console.error("tick",e); }
}

async function auth(req,res,next) {
  const raw = req.headers.authorization || "";
  const bearer = raw.startsWith("Bearer ") ? raw.slice(7) : "";
  if (!bearer) return res.status(401).json({ok:false,error:"Chưa đăng nhập."});
  try {
    const r = await q(`
      SELECT u.id,u.username,u.ttt,u.plays,u.biggest_win,u.total_won,s.expires_at
      FROM sessions s JOIN users u ON u.id=s.user_id
      WHERE s.token_hash=$1
    `,[sha(bearer)]);
    if (!r.rowCount || new Date(r.rows[0].expires_at) <= now()) {
      return res.status(401).json({ok:false,error:"Phiên đăng nhập hết hạn."});
    }
    req.user = r.rows[0];
    req.token = bearer;
    next();
  } catch(e) { console.error("auth",e); res.status(500).json({ok:false,error:"Lỗi máy chủ."}); }
}

function admin(req,res,next) {
  const key = req.headers["x-admin-key"] || req.body?.adminKey || req.query?.key || "";
  if (!ADMIN_KEY || ADMIN_KEY === "CHANGE_ME_ADMIN_KEY" || key !== ADMIN_KEY) {
    return res.status(403).json({ok:false,error:"Sai ADMIN_KEY."});
  }
  next();
}

app.get("/health", async (_req,res) => {
  try { await q("SELECT 1"); res.json({ok:true,game:"running",time:now().toISOString()}); }
  catch { res.status(503).json({ok:false,error:"Database unavailable"}); }
});

app.post("/api/auth/register", async (req,res) => {
  const username = String(req.body.username||"").trim();
  const password = String(req.body.password||"");
  if (!/^[A-Za-z0-9_]{3,24}$/.test(username)) return res.status(400).json({ok:false,error:"Tên tài khoản 3-24 ký tự."});
  if (password.length < 6) return res.status(400).json({ok:false,error:"Mật khẩu tối thiểu 6 ký tự."});
  try {
    const r = await q(`
      INSERT INTO users(username,password_hash) VALUES($1,$2)
      RETURNING id,username,ttt,plays,biggest_win,total_won,created_at,last_login_at
    `,[username,makePasswordHash(password)]);
    const t = makeToken();
    await q(`
      INSERT INTO sessions(token_hash,user_id,expires_at)
      VALUES($1,$2,NOW()+INTERVAL '${SESSION_DAYS} days')
    `,[sha(t),r.rows[0].id]);
    res.json({ok:true,token:t,user:r.rows[0]});
  } catch(e) {
    if (e.code==="23505") return res.status(409).json({ok:false,error:"Tài khoản đã tồn tại."});
    console.error(e); res.status(500).json({ok:false,error:"Không tạo được tài khoản."});
  }
});

app.post("/api/auth/login", async (req,res) => {
  const username = String(req.body.username||"").trim();
  const password = String(req.body.password||"");
  try {
    const r = await q(`SELECT * FROM users WHERE lower(username)=lower($1)`,[username]);
    if (!r.rowCount || !verifyPassword(password,r.rows[0].password_hash)) {
      return res.status(401).json({ok:false,error:"Sai tài khoản hoặc mật khẩu."});
    }
    const t = makeToken();
    await q(`
      INSERT INTO sessions(token_hash,user_id,expires_at)
      VALUES($1,$2,NOW()+INTERVAL '${SESSION_DAYS} days')
    `,[sha(t),r.rows[0].id]);
    await q(`UPDATE users SET last_login_at=NOW() WHERE id=$1`,[r.rows[0].id]);
    const u = r.rows[0];
    res.json({ok:true,token:t,user:{
      id:u.id,username:u.username,ttt:u.ttt,plays:u.plays,
      biggest_win:u.biggest_win,total_won:u.total_won,
      created_at:u.created_at,last_login_at:new Date().toISOString()
    }});
  } catch(e) { console.error(e); res.status(500).json({ok:false,error:"Lỗi máy chủ."}); }
});

app.post("/api/auth/logout",auth,async(req,res)=>{
  await q(`DELETE FROM sessions WHERE token_hash=$1`,[sha(req.token)]);
  res.json({ok:true});
});
app.get("/api/me",auth,async(req,res)=>{
  const r=await q(`SELECT id,username,ttt,plays,biggest_win,total_won FROM users WHERE id=$1`,[req.user.id]);
  res.json({ok:true,user:r.rows[0]});
});

app.get("/api/rank",async(_req,res)=>{
  const r=await q(`
    SELECT username,biggest_win,total_won,ttt
    FROM users ORDER BY total_won DESC,biggest_win DESC,id ASC LIMIT 20
  `);
  res.json({ok:true,rank:r.rows});
});

app.get("/api/tx/state",auth,async(req,res)=>{
  const r=await getTxRound();
  const h=await q(`SELECT round_id,d1,d2,d3,total,side,created_at FROM tx_history ORDER BY id DESC LIMIT 30`);
  const b=await q(`SELECT side,COALESCE(SUM(amount),0) amount FROM tx_bets WHERE round_id=$1 GROUP BY side`,[r.id]);
  const totals={tai:0,xiu:0};
  for(const x of b.rows) totals[x.side]=Number(x.amount);
  const my=await q(`SELECT COALESCE(SUM(amount),0) amount FROM tx_bets WHERE round_id=$1 AND user_id=$2 AND settled=false`,[r.id,req.user.id]);
  res.json({
    ok:true,serverNow:Date.now(),
    round:{id:r.id,status:r.status,endsAt:new Date(r.ends_at).getTime(),resultUntil:r.result_until?new Date(r.result_until).getTime():null,dice:r.status==="closed"?[r.d1,r.d2,r.d3]:null,total:r.total,side:r.side},
    totals,myStake:Number(my.rows[0].amount),history:h.rows
  });
});

app.post("/api/tx/bet",auth,async(req,res)=>{
  const side=String(req.body.side||"");
  const amount=Math.floor(Number(req.body.amount));
  if(!["tai","xiu"].includes(side)||!Number.isFinite(amount)||amount<1000) return res.status(400).json({ok:false,error:"Cược không hợp lệ."});
  const c=await pool.connect();
  try {
    await c.query("BEGIN");
    const rr=await c.query(`SELECT * FROM tx_rounds WHERE status='open' ORDER BY id DESC LIMIT 1 FOR UPDATE`);
    if(!rr.rowCount||new Date(rr.rows[0].ends_at)<=now()){await c.query("ROLLBACK");return res.status(409).json({ok:false,error:"Ván đã khóa."});}
    const u=await c.query(`SELECT ttt FROM users WHERE id=$1 FOR UPDATE`,[req.user.id]);
    if(Number(u.rows[0].ttt)<amount){await c.query("ROLLBACK");return res.status(400).json({ok:false,error:"Không đủ TTT."});}
    await c.query(`UPDATE users SET ttt=ttt-$1 WHERE id=$2`,[amount,req.user.id]);
    await c.query(`INSERT INTO tx_bets(round_id,user_id,side,amount) VALUES($1,$2,$3,$4)`,[rr.rows[0].id,req.user.id,side,amount]);
    await c.query("COMMIT"); res.json({ok:true});
  } catch(e) { try{await c.query("ROLLBACK")}catch{}; console.error(e); res.status(500).json({ok:false,error:"Không đặt được cược."}); }
  finally { c.release(); }
});

app.get("/api/xd/state",auth,async(req,res)=>{
  const r=await getXdRound();
  const h=await q(`SELECT round_id,red_count,white_count,side,multiplier,created_at FROM xd_history ORDER BY id DESC LIMIT 30`);
  const b=await q(`SELECT side,COALESCE(SUM(amount),0) amount FROM xd_bets WHERE round_id=$1 GROUP BY side`,[r.id]);
  const totals={chan:0,le:0};
  for(const x of b.rows) totals[x.side]=Number(x.amount);
  const my=await q(`SELECT COALESCE(SUM(amount),0) amount FROM xd_bets WHERE round_id=$1 AND user_id=$2 AND settled=false`,[r.id,req.user.id]);
  res.json({
    ok:true,serverNow:Date.now(),
    round:{id:r.id,status:r.status,endsAt:new Date(r.ends_at).getTime(),resultUntil:r.result_until?new Date(r.result_until).getTime():null,redCount:r.red_count,whiteCount:r.white_count,side:r.side,multiplier:r.multiplier},
    totals,myStake:Number(my.rows[0].amount),history:h.rows
  });
});

app.post("/api/xd/bet",auth,async(req,res)=>{
  const side=String(req.body.side||"");
  const amount=Math.floor(Number(req.body.amount));
  if(!["chan","le"].includes(side)||!Number.isFinite(amount)||amount<1000) return res.status(400).json({ok:false,error:"Cược không hợp lệ."});
  const c=await pool.connect();
  try {
    await c.query("BEGIN");
    const rr=await c.query(`SELECT * FROM xd_rounds WHERE status='open' ORDER BY id DESC LIMIT 1 FOR UPDATE`);
    if(!rr.rowCount||new Date(rr.rows[0].ends_at)<=now()){await c.query("ROLLBACK");return res.status(409).json({ok:false,error:"Ván đã khóa."});}
    const u=await c.query(`SELECT ttt FROM users WHERE id=$1 FOR UPDATE`,[req.user.id]);
    if(Number(u.rows[0].ttt)<amount){await c.query("ROLLBACK");return res.status(400).json({ok:false,error:"Không đủ TTT."});}
    await c.query(`UPDATE users SET ttt=ttt-$1 WHERE id=$2`,[amount,req.user.id]);
    await c.query(`INSERT INTO xd_bets(round_id,user_id,side,amount) VALUES($1,$2,$3,$4)`,[rr.rows[0].id,req.user.id,side,amount]);
    await c.query("COMMIT"); res.json({ok:true});
  } catch(e) { try{await c.query("ROLLBACK")}catch{}; console.error(e); res.status(500).json({ok:false,error:"Không đặt được cược."}); }
  finally { c.release(); }
});

app.post("/api/redeem",auth,async(req,res)=>{
  const code=String(req.body.code||"").trim().toUpperCase();
  if(!code) return res.status(400).json({ok:false,error:"Thiếu code."});
  const c=await pool.connect();
  try {
    await c.query("BEGIN");
    const r=await c.query(`
      SELECT * FROM redeem_codes
      WHERE code=$1 AND active=true
        AND (expires_at IS NULL OR expires_at > NOW())
      FOR UPDATE
    `,[code]);
    if(!r.rowCount){await c.query("ROLLBACK");return res.status(404).json({ok:false,error:"Code không tồn tại, đã khóa hoặc hết hạn."});}
    const item=r.rows[0];
    if(item.max_uses>0 && item.uses>=item.max_uses){await c.query("ROLLBACK");return res.status(409).json({ok:false,error:"Code đã hết lượt sử dụng."});}
    await c.query(`UPDATE redeem_codes SET uses=uses+1,active=CASE WHEN uses+1>=max_uses THEN false ELSE active END WHERE id=$1`,[item.id]);
    await c.query(`UPDATE users SET ttt=ttt+$1 WHERE id=$2`,[item.reward,req.user.id]);
    await c.query("COMMIT");
    res.json({ok:true,reward:Number(item.reward),code});
  } catch(e) { try{await c.query("ROLLBACK")}catch{}; console.error(e); res.status(500).json({ok:false,error:"Không xử lý được code."}); }
  finally { c.release(); }
});

/* Admin */
app.get("/api/admin/codes",admin,async(_req,res)=>{
  const r=await q(`SELECT id,code,reward,max_uses,uses,active,created_at FROM redeem_codes ORDER BY id DESC LIMIT 100`);
  res.json({ok:true,codes:r.rows});
});
app.post("/api/admin/codes",admin,async(req,res)=>{
  const reward=Math.floor(Number(req.body.reward));
  const maxUses=Math.max(0,Math.floor(Number(req.body.maxUses ?? 1)));
  const expiresAt=req.body.expiresAt ? new Date(req.body.expiresAt) : null;
  if(!Number.isFinite(reward)||reward<=0) return res.status(400).json({ok:false,error:"Reward không hợp lệ."});
  if(expiresAt && Number.isNaN(expiresAt.getTime())) return res.status(400).json({ok:false,error:"Ngày hết hạn không hợp lệ."});
  let code=String(req.body.code||"").trim().toUpperCase().replace(/[^A-Z0-9_-]/g,"");
  if(!code) code=`TTT-${crypto.randomBytes(5).toString("hex").toUpperCase()}`;
  try {
    const r=await q(`INSERT INTO redeem_codes(code,reward,max_uses,expires_at) VALUES($1,$2,$3,$4) RETURNING *`,[code,reward,maxUses,expiresAt]);
    res.json({ok:true,code:r.rows[0]});
  } catch(e) {
    if(e.code==="23505") return res.status(409).json({ok:false,error:"Code đã tồn tại."});
    console.error(e); res.status(500).json({ok:false,error:"Không tạo được code."});
  }
});
app.post("/api/admin/codes/toggle",admin,async(req,res)=>{
  const id=Number(req.body.id);
  await q(`UPDATE redeem_codes SET active=NOT active WHERE id=$1`,[id]);
  res.json({ok:true});
});
app.get("/api/admin/users",admin,async(req,res)=>{
  const search=String(req.query.search||"").trim();
  const params=[];
  let where="";
  if(search){
    params.push("%"+search.toLowerCase()+"%");
    where="WHERE lower(username) LIKE $1";
  }
  const r=await q(`
    SELECT
      u.id,
      u.username,
      u.ttt,
      u.plays,
      u.biggest_win,
      u.total_won,
      u.created_at,
      u.last_login_at,
      COALESCE((
        SELECT COUNT(*)
        FROM sessions s
        WHERE s.user_id=u.id AND s.expires_at>NOW()
      ),0)::int AS active_sessions
    FROM users u
    ${where}
    ORDER BY u.id DESC
  `,params);
  res.json({ok:true,total:r.rowCount,users:r.rows});
});

app.get("/",(_req,res)=>res.sendFile(path.join(__dirname,"index.html")));
app.get("/admin",(_req,res)=>res.sendFile(path.join(__dirname,"admin.html")));

async function start(){
  try {
    await initDb();
    app.listen(PORT,()=>console.log(`TTT9-9-9 server listening on ${PORT}`));
    setInterval(tick,1000);
    await tick();
  } catch(e) {
    console.error("START FAILED",e);
    process.exit(1);
  }
}
start();
