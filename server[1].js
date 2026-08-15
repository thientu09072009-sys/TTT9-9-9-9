const express = require("express");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const cors = require("cors");

const app = express();
app.set("trust proxy", 1);
app.use(express.json({limit:"64kb"}));

const PORT = Number(process.env.PORT || 3000);
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "CHANGE_ME_NOW";
const DATA_FILE = process.env.DATA_FILE || path.join(__dirname, "data", "codes.json");
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || "*")
  .split(",").map(x => x.trim()).filter(Boolean);

app.use(cors({
  origin(origin, cb) {
    if (!origin || ALLOWED_ORIGINS.includes("*") || ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
    cb(new Error("CORS origin not allowed"));
  },
  methods: ["GET","POST","PATCH","DELETE","OPTIONS"],
  allowedHeaders: ["Content-Type","x-admin-password"],
}));

function ensureData() {
  fs.mkdirSync(path.dirname(DATA_FILE), {recursive:true});
  if (!fs.existsSync(DATA_FILE)) fs.writeFileSync(DATA_FILE, "[]", "utf8");
}
function loadCodes() {
  ensureData();
  try { return JSON.parse(fs.readFileSync(DATA_FILE,"utf8")); }
  catch { return []; }
}
function saveCodes(codes) {
  ensureData();
  const tmp=DATA_FILE+".tmp";
  fs.writeFileSync(tmp, JSON.stringify(codes,null,2), "utf8");
  fs.renameSync(tmp, DATA_FILE);
}
function cleanCode(v) {
  return String(v || "").trim().toUpperCase().replace(/\s+/g,"");
}
function isAdmin(req) {
  return String(req.get("x-admin-password") || "") === ADMIN_PASSWORD;
}
function safeCode(c) {
  return {
    code:c.code, reward:c.reward, maxUses:c.maxUses, usedCount:c.usedCount,
    expiresAt:c.expiresAt, active:c.active, createdAt:c.createdAt
  };
}
function requireAdmin(req,res,next) {
  if (!isAdmin(req)) return res.status(401).json({ok:false,error:"Mật khẩu Admin sai."});
  next();
}

app.get("/api/health", (_req,res)=>res.json({ok:true,service:"SCT CODE SERVER",time:new Date().toISOString()}));

app.get("/api/codes", requireAdmin, (_req,res)=>{
  res.json(loadCodes().map(safeCode));
});

app.post("/api/codes", requireAdmin, (req,res)=>{
  const code=cleanCode(req.body.code);
  const reward=Number(req.body.reward);
  const maxUses=Number(req.body.maxUses || 0);
  const expiresAt=req.body.expiresAt ? new Date(req.body.expiresAt).toISOString() : null;

  if (!/^[A-Z0-9_-]{3,40}$/.test(code)) return res.status(400).json({ok:false,error:"Code phải 3–40 ký tự A-Z, 0-9, _ hoặc -."});
  if (!Number.isFinite(reward) || reward <= 0 || reward > 1e15) return res.status(400).json({ok:false,error:"Số điểm không hợp lệ."});
  if (!Number.isInteger(maxUses) || maxUses < 0 || maxUses > 1e9) return res.status(400).json({ok:false,error:"Lượt sử dụng không hợp lệ."});
  if (expiresAt && Number.isNaN(Date.parse(expiresAt))) return res.status(400).json({ok:false,error:"Ngày hết hạn không hợp lệ."});

  const codes=loadCodes();
  if (codes.some(x=>x.code===code)) return res.status(409).json({ok:false,error:"Code đã tồn tại."});

  const item={id:crypto.randomUUID(),code,reward, maxUses, usedCount:0,
    expiresAt, active:true, createdAt:new Date().toISOString(), devices:[]};
  codes.push(item); saveCodes(codes);
  res.status(201).json({ok:true,code:safeCode(item)});
});

app.patch("/api/codes/:code", requireAdmin, (req,res)=>{
  const code=cleanCode(req.params.code);
  const codes=loadCodes(); const item=codes.find(x=>x.code===code);
  if(!item) return res.status(404).json({ok:false,error:"Không tìm thấy code."});
  if (typeof req.body.active==="boolean") item.active=req.body.active;
  if (req.body.resetUses) { item.usedCount=0; item.devices=[]; }
  saveCodes(codes); res.json({ok:true,code:safeCode(item)});
});

app.delete("/api/codes/:code", requireAdmin, (req,res)=>{
  const code=cleanCode(req.params.code);
  const codes=loadCodes(); const next=codes.filter(x=>x.code!==code);
  if(next.length===codes.length) return res.status(404).json({ok:false,error:"Không tìm thấy code."});
  saveCodes(next); res.json({ok:true});
});

app.post("/api/redeem", (req,res)=>{
  const code=cleanCode(req.body.code);
  const deviceId=String(req.body.deviceId || "").trim().slice(0,128);
  if(!code) return res.status(400).json({ok:false,error:"Chưa nhập code."});
  if(!deviceId) return res.status(400).json({ok:false,error:"Thiếu deviceId."});

  const codes=loadCodes();
  const item=codes.find(x=>x.code===code);
  if(!item || !item.active) return res.status(404).json({ok:false,error:"Code không tồn tại hoặc đã tắt."});
  if(item.expiresAt && Date.now() > Date.parse(item.expiresAt)) return res.status(410).json({ok:false,error:"Code đã hết hạn."});
  if(item.maxUses>0 && item.usedCount>=item.maxUses) return res.status(409).json({ok:false,error:"Code đã hết lượt sử dụng."});
  if(item.devices.includes(deviceId)) return res.status(409).json({ok:false,error:"Thiết bị này đã nhập code rồi."});

  item.usedCount++;
  item.devices.push(deviceId);
  saveCodes(codes);
  res.json({ok:true,reward:item.reward,code:item.code,usedCount:item.usedCount,maxUses:item.maxUses});
});

app.use((err,_req,res,_next)=>{
  if(err && /CORS/.test(err.message)) return res.status(403).json({ok:false,error:"Origin không được phép."});
  console.error(err);
  res.status(500).json({ok:false,error:"Lỗi server."});
});

app.listen(PORT,()=>console.log(`SCT Code Server listening on port ${PORT}`));
