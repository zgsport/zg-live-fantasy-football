const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');
const app = express();
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '12kb' }));
app.use(express.urlencoded({ extended: false, limit: '12kb' }));
app.use(rateLimit({ windowMs: 60_000, limit: 180, standardHeaders: true, legacyHeaders: false }));
const dataDir = process.env.DATA_DIR || path.join(__dirname, 'data');
fs.mkdirSync(dataDir, { recursive: true });
const db = new Database(path.join(dataDir, 'questions.sqlite'));
db.pragma('journal_mode = WAL');
db.exec(`CREATE TABLE IF NOT EXISTS questions (
 id INTEGER PRIMARY KEY AUTOINCREMENT, type TEXT NOT NULL CHECK(type IN ('start-sit','trade')),
 username TEXT NOT NULL, league TEXT DEFAULT '', details TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
 created_at TEXT NOT NULL DEFAULT (datetime('now')), answer TEXT DEFAULT ''
)`);
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';
const OVERLAY_KEY = process.env.OVERLAY_KEY || '';
const sessions = new Map();
function admin(req,res,next){
 const token=(req.get('x-admin-token') || req.query.token || '').toString();
 if (!ADMIN_PASSWORD) return res.status(503).json({error:'Admin login is not configured. Set ADMIN_PASSWORD in environment variables.'});
 if (!token || sessions.get(token)!==true) return res.status(401).json({error:'Please log in again.'});
 next();
}
function overlayAuth(req,res,next){ if(OVERLAY_KEY && req.query.key!==OVERLAY_KEY) return res.status(403).json({error:'Invalid overlay key'}); next(); }
app.use(express.static(path.join(__dirname,'public')));
app.get('/',(_,res)=>res.sendFile(path.join(__dirname,'public','submit.html')));
app.get('/admin',(_,res)=>res.sendFile(path.join(__dirname,'public','admin.html')));
app.get('/overlay',(_,res)=>res.sendFile(path.join(__dirname,'public','overlay.html')));
app.post('/api/questions', rateLimit({windowMs:60_000,limit:8,standardHeaders:true,legacyHeaders:false}), (req,res)=>{
 const type=String(req.body.type||''); const username=String(req.body.username||'').trim().slice(0,32);
 const league=String(req.body.league||'').trim().slice(0,60); const details=String(req.body.details||'').trim().slice(0,700);
 if(!['start-sit','trade'].includes(type)||!username||details.length<4) return res.status(400).json({error:'Add your username and a question.'});
 const info=db.prepare('INSERT INTO questions(type,username,league,details) VALUES(?,?,?,?)').run(type,username,league,details);
 res.json({ok:true,id:info.lastInsertRowid});
});
app.post('/api/login',(req,res)=>{
 if(!ADMIN_PASSWORD) return res.status(503).json({error:'Set ADMIN_PASSWORD in the hosting environment first.'});
 if(String(req.body.password||'')!==ADMIN_PASSWORD) return res.status(401).json({error:'Incorrect password.'});
 const token=require('crypto').randomBytes(32).toString('hex'); sessions.set(token,true);
 res.json({ok:true,token});
});
app.post('/api/logout',admin,(req,res)=>{sessions.delete(req.get('x-admin-token'));res.json({ok:true});});
app.get('/api/admin/questions',admin,(req,res)=>{
 const status=String(req.query.status||'all');
 const rows=status==='all'?db.prepare('SELECT * FROM questions ORDER BY id DESC LIMIT 250').all():db.prepare('SELECT * FROM questions WHERE status=? ORDER BY id DESC LIMIT 250').all(status);
 res.json(rows);
});
app.patch('/api/admin/questions/:id',admin,(req,res)=>{
 const id=Number(req.params.id), status=String(req.body.status||'');
 if(!Number.isInteger(id)||!['pending','accepted','rejected','answered'].includes(status)) return res.status(400).json({error:'Invalid update.'});
 const answer=String(req.body.answer||'').trim().slice(0,400);
 const r=db.prepare('UPDATE questions SET status=?, answer=? WHERE id=?').run(status,answer,id);
 if(!r.changes) return res.status(404).json({error:'Question not found.'}); res.json({ok:true});
});
app.get('/api/overlay/current',overlayAuth,(_,res)=>{
 const row=db.prepare("SELECT id,type,username,league,details,status,answer,created_at FROM questions WHERE status IN ('accepted','answered') ORDER BY id DESC LIMIT 1").get();
 res.json(row||null);
});
app.get('/health',(_,res)=>res.json({ok:true}));
const port=process.env.PORT||3000; app.listen(port,'0.0.0.0',()=>console.log(`ZG Live listening on ${port}`));
