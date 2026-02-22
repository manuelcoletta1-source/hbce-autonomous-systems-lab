'use strict';

const $ = (id) => document.getElementById(id);
const canvas = $('sim');
const ctx = canvas.getContext('2d');

const ui = {
  // presets
  policyPack: $('policyPack'),
  scenarioPack: $('scenarioPack'),
  btnApplyPolicy: $('btnApplyPolicy'),
  btnApplyScenario: $('btnApplyScenario'),
  btnShare: $('btnShare'),
  seed: $('seed'),

  // tuning
  mode: $('mode'),
  speed: $('speed'),
  minDist: $('minDist'),
  maxSpeed: $('maxSpeed'),
  noTouch: $('noTouch'),
  boundary: $('boundary'),
  obsBuffer: $('obsBuffer'),
  hardStop: $('hardStop'),

  // status
  status: $('status'),
  policyState: $('policyState'),
  tOp: $('tOp'),
  tDr: $('tDr'),
  tDist: $('tDist'),
  tVel: $('tVel'),
  tAct: $('tAct'),
  tViol: $('tViol'),
  tPack: $('tPack'),

  // log
  log: $('log'),
  btnReset: $('btnReset'),
  btnEmit: $('btnEmit'),
  btnClearLog: $('btnClearLog'),
  btnCopyLog: $('btnCopyLog'),
  btnRandomObs: $('btnRandomObs'),
  btnClearObs: $('btnClearObs'),
};

const clamp = (v, a, b) => Math.max(a, Math.min(b, v));
const len = (x, y) => Math.hypot(x, y);
const nowISO = () => new Date().toISOString();
const fmt = (n) => Number.isFinite(n) ? n.toFixed(1) : '—';

function hex(buf){ return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2,'0')).join(''); }
async function sha256(str){
  const data = new TextEncoder().encode(str);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return hex(digest);
}

// Deterministic PRNG (Mulberry32)
function mulberry32(seed){
  let a = seed >>> 0;
  return function(){
    a |= 0; a = (a + 0x6D2B79F5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const world = {
  w: canvas.width,
  h: canvas.height,
  op: { x: canvas.width * 0.28, y: canvas.height * 0.56, r: 10 },
  dr: { x: canvas.width * 0.66, y: canvas.height * 0.46, r: 9, vx: 0, vy: 0 },
  ex: { x: canvas.width * 0.70, y: canvas.height * 0.58, dir: 1, t: 0 },
  obstacles: [],
  lastAction: '—',
  lastViolation: '—',
  activePack: 'HUMAN_PROXIMITY',
  activeScenario: 'OFFICE',
  mouseInside: false,
};

const ledger = {
  proto: 'HBCE-SIM-AUDIT-LOG-v1',
  policy: ['APPEND_ONLY', 'HASH_CHAIN', 'AUDIT_FIRST', 'FAIL_CLOSED'],
  entries: [],
  head: 'GENESIS'
};

const STORAGE_KEY = 'HBCE_CONTROL_CORE_STATE_V1';

// ---- persistence ----
function persistState(){
  const state = {
    ts: nowISO(),
    activePack: world.activePack,
    activeScenario: world.activeScenario,
    seed: Number(ui.seed.value || 0),
    cfg: readCfg(),
    ledger: { ...ledger },
    obstacles: world.obstacles,
  };
  try{
    localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
  }catch(_e){
    // ignore
  }
}

function loadState(){
  try{
    const raw = localStorage.getItem(STORAGE_KEY);
    if(!raw) return null;
    return JSON.parse(raw);
  }catch(_e){
    return null;
  }
}

// ---- UI helpers ----
function renderLog(){
  ui.log.textContent = JSON.stringify({
    proto: ledger.proto,
    policy: ledger.policy,
    head: ledger.head,
    entries: ledger.entries.slice(-80)
  }, null, 2);
}
function setStatus(text){ ui.status.textContent = `STATUS: ${text}`; }
function setPolicy(pass){
  ui.policyState.textContent = `POLICY: ${pass ? 'PASS' : 'DENY'}`;
  ui.policyState.classList.remove('pill--ok','pill--deny');
  ui.policyState.classList.add(pass ? 'pill--ok' : 'pill--deny');
}

// ---- CRITICAL FIX: append queue (prevents hash-chain fork) ----
let APPEND_QUEUE = Promise.resolve();

function appendEvent(event){
  APPEND_QUEUE = APPEND_QUEUE.then(async () => {
    const prev = ledger.head;
    const payload = { ts: nowISO(), ...event, prev_hash: prev };
    const h = await sha256(JSON.stringify(payload));
    ledger.entries.push({ ...payload, hash: h });
    ledger.head = h;
    renderLog();
    persistState();
  }).catch((_e) => {
    // fail-closed for audit: we do not mutate state on error
  });

  return APPEND_QUEUE;
}

/** Presets */
const POLICY_PACKS = {
  HUMAN_PROXIMITY: { speed: 2.4, minDist: 90, maxSpeed: 260, noTouch: 24, boundary: 14, obsBuffer: 34, hardStop: 'YES' },
  WAREHOUSE:       { speed: 3.6, minDist: 70, maxSpeed: 420, noTouch: 16, boundary: 10, obsBuffer: 30, hardStop: 'YES' },
  INSPECTION:      { speed: 2.0, minDist: 80, maxSpeed: 210, noTouch: 22, boundary: 16, obsBuffer: 38, hardStop: 'YES' },
  LAB_CLEANROOM:   { speed: 1.8, minDist: 110, maxSpeed: 180, noTouch: 30, boundary: 18, obsBuffer: 44, hardStop: 'YES' },
};

const SCENARIO_PACKS = {
  OFFICE: () => ([
    { x: 380, y: 130, w: 160, h: 70 },
    { x: 640, y: 330, w: 190, h: 80 },
    { x: 220, y: 360, w: 130, h: 70 },
  ]),
  WAREHOUSE: () => ([
    { x: 220, y: 120, w: 520, h: 60 },
    { x: 240, y: 260, w: 500, h: 60 },
    { x: 260, y: 400, w: 480, h: 60 },
  ]),
  CORRIDOR: () => ([
    { x: 200, y: 80,  w: 580, h: 60 },
    { x: 200, y: 420, w: 580, h: 60 },
    { x: 420, y: 180, w: 140, h: 200 },
  ]),
  CLUTTERED: () => randomObstacles(7, Number(ui.seed.value || 1)),
};

function applyPolicyPack(name){
  const p = POLICY_PACKS[name];
  if(!p) return;
  world.activePack = name;

  ui.speed.value = p.speed;
  ui.minDist.value = p.minDist;
  ui.maxSpeed.value = p.maxSpeed;
  ui.noTouch.value = p.noTouch;
  ui.boundary.value = p.boundary;
  ui.obsBuffer.value = p.obsBuffer;
  ui.hardStop.value = p.hardStop;

  ui.tPack.textContent = `${world.activePack} / ${world.activeScenario}`;
  appendEvent({ type:'POLICY_PACK_APPLIED', pack: name, cfg: p });
  setStatus(`POLICY PACK: ${name}`);
  persistState();
}

function applyScenarioPack(name){
  const fn = SCENARIO_PACKS[name];
  if(!fn) return;
  world.activeScenario = name;
  world.obstacles = fn();
  appendEvent({ type:'SCENARIO_PACK_APPLIED', scenario: name, obstacles: world.obstacles.length, seed: Number(ui.seed.value || 0) });
  setStatus(`SCENARIO: ${name}`);
  ui.tPack.textContent = `${world.activePack} / ${world.activeScenario}`;
  persistState();
}

function randomObstacles(count, seed){
  const rnd = mulberry32((seed || 1) >>> 0);
  const obs = [];
  for(let i=0;i<count;i++){
    const w = 80 + rnd()*170;
    const h = 50 + rnd()*120;
    obs.push({
      x: 30 + rnd()*(world.w - w - 60),
      y: 30 + rnd()*(world.h - h - 60),
      w, h
    });
  }
  return obs;
}

/** Share link: ?p=PACK&s=SCENARIO&seed=123 */
function applyFromURL(){
  const u = new URL(location.href);
  const p = u.searchParams.get('p');
  const s = u.searchParams.get('s');
  const seed = u.searchParams.get('seed');

  if(seed){
    const n = clamp(parseInt(seed,10) || 1, 1, 999999999);
    ui.seed.value = String(n);
  }
  if(p && POLICY_PACKS[p]) ui.policyPack.value = p;
  if(s && SCENARIO_PACKS[s]) ui.scenarioPack.value = s;
}

async function copyShareLink(){
  const base = location.origin + location.pathname;
  const u = new URL(base);
  u.searchParams.set('p', ui.policyPack.value);
  u.searchParams.set('s', ui.scenarioPack.value);
  u.searchParams.set('seed', String(Number(ui.seed.value || 1)));
  await navigator.clipboard.writeText(u.toString());
  setStatus('SHARE LINK COPIED');
}

/** Input */
canvas.addEventListener('mousemove', (e) => {
  const rect = canvas.getBoundingClientRect();
  const sx = canvas.width / rect.width;
  const sy = canvas.height / rect.height;
  world.op.x = clamp((e.clientX - rect.left) * sx, 0, world.w);
  world.op.y = clamp((e.clientY - rect.top) * sy, 0, world.h);
  world.mouseInside = true;
});
canvas.addEventListener('mouseleave', () => { world.mouseInside = false; });

/** Geometry */
function roundRect(c, x, y, w, h, r){
  const rr = Math.min(r, w/2, h/2);
  c.beginPath();
  c.moveTo(x+rr, y);
  c.arcTo(x+w, y, x+w, y+h, rr);
  c.arcTo(x+w, y+h, x, y+h, rr);
  c.arcTo(x, y+h, x, y, rr);
  c.arcTo(x, y, x+w, y, rr);
  c.closePath();
}
function pointInRect(px, py, r){
  return px >= r.x && px <= (r.x + r.w) && py >= r.y && py <= (r.y + r.h);
}
function obstacleRepulsion(px, py, buffer){
  let rx = 0, ry = 0;
  const margin = buffer;
  for(const o of world.obstacles){
    const cx = clamp(px, o.x - margin, o.x + o.w + margin);
    const cy = clamp(py, o.y - margin, o.y + o.h + margin);
    const dx = px - cx;
    const dy = py - cy;
    const d = len(dx, dy);
    if(d < margin && d > 0.0001){
      const strength = (margin - d) / margin;
      rx += (dx / d) * strength * 2.4;
      ry += (dy / d) * strength * 2.4;
    }
  }
  return { x: rx, y: ry };
}

/** Explore */
function stepExplore(dt){
  const ex = world.ex;
  ex.t += dt;
  ex.x += ex.dir * 70 * dt;
  ex.y += Math.sin(ex.t * 0.7) * 12 * dt;
  if(ex.x < 80){ ex.x = 80; ex.dir = 1; }
  if(ex.x > world.w - 80){ ex.x = world.w - 80; ex.dir = -1; }
  ex.y = clamp(ex.y, 70, world.h - 70);
}

/** Policy */
function evaluatePolicy(nextX, nextY, vmag, cfg){
  if(nextX < cfg.boundary || nextX > world.w - cfg.boundary || nextY < cfg.boundary || nextY > world.h - cfg.boundary){
    return { pass:false, code:'BOUNDARY_VIOLATION' };
  }
  if(vmag > cfg.maxSpeed){
    return { pass:false, code:'MAX_SPEED_EXCEEDED' };
  }
  const dx = world.op.x - nextX;
  const dy = world.op.y - nextY;
  const dist = len(dx, dy);
  const denyRadius = world.op.r + cfg.noTouch;
  if(dist < denyRadius){
    return { pass:false, code:'NO_TOUCH_VIOLATION' };
  }
  for(const o of world.obstacles){
    const expanded = { x: o.x - cfg.obsBuffer, y: o.y - cfg.obsBuffer, w: o.w + 2*cfg.obsBuffer, h: o.h + 2*cfg.obsBuffer };
    if(pointInRect(nextX, nextY, expanded)){
      return { pass:false, code:'OBSTACLE_BUFFER_VIOLATION' };
    }
  }
  return { pass:true, code:'OK' };
}

function readCfg(){
  return {
    speed: clamp(parseFloat(ui.speed.value || '3.2'), 0.2, 12),
    minDist: clamp(parseFloat(ui.minDist.value || '60'), 10, 240),
    maxSpeed: clamp(parseFloat(ui.maxSpeed.value || '380'), 20, 1200),
    noTouch: clamp(parseFloat(ui.noTouch.value || '14'), 0, 120),
    boundary: clamp(parseFloat(ui.boundary.value || '10'), 0, 160),
    obsBuffer: clamp(parseFloat(ui.obsBuffer.value || '26'), 0, 160),
    hardStop: (ui.hardStop.value === 'YES'),
  };
}

/** Core update */
function update(dt){
  const mode = ui.mode.value;
  const cfg = readCfg();

  const dr = world.dr;
  const op = world.op;

  let tx = dr.x, ty = dr.y;
  let action = 'HOLD';

  if(mode === 'FOLLOW'){
    const dx = op.x - dr.x;
    const dy = op.y - dr.y;
    const dist = len(dx, dy);
    if(dist > cfg.minDist){
      tx = op.x; ty = op.y; action = 'APPROACH';
    } else {
      if(dist > 0.001){
        tx = dr.x - (dx / dist) * (cfg.minDist - dist + 1);
        ty = dr.y - (dy / dist) * (cfg.minDist - dist + 1);
      }
      action = 'BACK_OFF';
    }
  }

  if(mode === 'HOVER'){
    tx = dr.x; ty = dr.y; action = 'HOVER';
  }

  if(mode === 'EXPLORE_SAFE'){
    stepExplore(dt);
    tx = world.ex.x; ty = world.ex.y; action = 'EXPLORE';
  }

  const vx = tx - dr.x;
  const vy = ty - dr.y;
  const vl = Math.max(0.0001, len(vx, vy));
  let ux = vx / vl;
  let uy = vy / vl;

  const rep = obstacleRepulsion(dr.x, dr.y, cfg.obsBuffer);
  ux += rep.x;
  uy += rep.y;

  const ul = Math.max(0.0001, len(ux, uy));
  ux /= ul; uy /= ul;

  const desiredSpeed = clamp(cfg.speed * 120, 0, cfg.maxSpeed);
  let vx_ps = ux * desiredSpeed;
  let vy_ps = uy * desiredSpeed;

  if(vl < 10){
    vx_ps *= 0.25;
    vy_ps *= 0.25;
    if(mode !== 'EXPLORE_SAFE') action = 'SETTLE';
  }

  const nextX = dr.x + vx_ps * dt;
  const nextY = dr.y + vy_ps * dt;
  const vmag = len(vx_ps, vy_ps);

  const pol = evaluatePolicy(nextX, nextY, vmag, cfg);
  setPolicy(pol.pass);

  if(!pol.pass){
    world.lastViolation = pol.code;
    if(cfg.hardStop){
      dr.vx = 0; dr.vy = 0;
      if(world.lastAction !== 'DENY'){
        appendEvent({
          type:'POLICY_DENY',
          code: pol.code,
          mode,
          action,
          pack: world.activePack,
          scenario: world.activeScenario,
          seed: Number(ui.seed.value || 0),
          operator:{x:op.x,y:op.y},
          drone:{x:dr.x,y:dr.y},
          cfg
        });
      }
      world.lastAction = 'DENY';
      setStatus(`DENY (${pol.code})`);
    } else {
      dr.vx = vx_ps; dr.vy = vy_ps;
      dr.x = clamp(nextX, 0, world.w);
      dr.y = clamp(nextY, 0, world.h);
      if(world.lastAction !== 'DENY_LOG_ONLY'){
        appendEvent({
          type:'POLICY_VIOLATION_LOG_ONLY',
          code: pol.code,
          mode,
          action,
          pack: world.activePack,
          scenario: world.activeScenario,
          seed: Number(ui.seed.value || 0),
          operator:{x:op.x,y:op.y},
          drone_next:{x:dr.x,y:dr.y},
          cfg
        });
      }
      world.lastAction = 'DENY_LOG_ONLY';
      setStatus(`VIOLATION LOGGED (${pol.code})`);
    }
  } else {
    world.lastViolation = '—';
    dr.vx = vx_ps; dr.vy = vy_ps;
    dr.x = clamp(nextX, 0, world.w);
    dr.y = clamp(nextY, 0, world.h);
    world.lastAction = action;
    setStatus(mode);
  }

  const distOD = len(op.x - dr.x, op.y - dr.y);
  ui.tOp.textContent = `x=${fmt(op.x)} y=${fmt(op.y)}`;
  ui.tDr.textContent = `x=${fmt(dr.x)} y=${fmt(dr.y)}`;
  ui.tDist.textContent = `${fmt(distOD)} px`;
  ui.tVel.textContent = `${fmt(len(dr.vx, dr.vy))} px/s`;
  ui.tAct.textContent = world.lastAction;
  ui.tViol.textContent = world.lastViolation;
  ui.tPack.textContent = `${world.activePack} / ${world.activeScenario}`;
}

/** Render */
function draw(){
  ctx.clearRect(0,0,world.w,world.h);

  ctx.save();
  ctx.globalAlpha = 0.22;
  ctx.beginPath();
  for(let x=0; x<=world.w; x+=40){ ctx.moveTo(x,0); ctx.lineTo(x,world.h); }
  for(let y=0; y<=world.h; y+=40){ ctx.moveTo(0,y); ctx.lineTo(world.w,y); }
  ctx.strokeStyle = 'rgba(255,255,255,0.10)';
  ctx.stroke();
  ctx.restore();

  for(const o of world.obstacles){
    ctx.save();
    ctx.fillStyle = 'rgba(255,255,255,0.06)';
    ctx.strokeStyle = 'rgba(255,255,255,0.14)';
    roundRect(ctx, o.x, o.y, o.w, o.h, 10);
    ctx.fill();
    ctx.stroke();
    ctx.restore();
  }

  const cfg = readCfg();
  const op = world.op;
  const dr = world.dr;

  ctx.save();
  ctx.beginPath();
  ctx.arc(op.x, op.y, cfg.minDist, 0, Math.PI*2);
  ctx.setLineDash([8,8]);
  ctx.strokeStyle = 'rgba(124,255,178,0.22)';
  ctx.stroke();
  ctx.restore();

  ctx.save();
  ctx.beginPath();
  ctx.arc(op.x, op.y, op.r + cfg.noTouch, 0, Math.PI*2);
  ctx.setLineDash([6,10]);
  ctx.strokeStyle = 'rgba(255,204,102,0.26)';
  ctx.stroke();
  ctx.restore();

  ctx.save();
  ctx.beginPath();
  ctx.moveTo(op.x, op.y);
  ctx.lineTo(dr.x, dr.y);
  ctx.strokeStyle = 'rgba(255,255,255,0.16)';
  ctx.stroke();
  ctx.restore();

  ctx.save();
  ctx.beginPath();
  ctx.arc(op.x, op.y, op.r, 0, Math.PI*2);
  ctx.fillStyle = 'rgba(141,215,255,0.70)';
  ctx.fill();
  ctx.strokeStyle = 'rgba(255,255,255,0.24)';
  ctx.stroke();
  ctx.restore();

  ctx.save();
  ctx.beginPath();
  ctx.arc(dr.x, dr.y, dr.r, 0, Math.PI*2);
  ctx.fillStyle = 'rgba(255,255,255,0.82)';
  ctx.fill();
  ctx.strokeStyle = 'rgba(141,215,255,0.35)';
  ctx.stroke();
  ctx.restore();

  if(ui.mode.value === 'EXPLORE_SAFE'){
    ctx.save();
    ctx.beginPath();
    ctx.arc(world.ex.x, world.ex.y, 6, 0, Math.PI*2);
    ctx.fillStyle = 'rgba(255,255,255,0.35)';
    ctx.fill();
    ctx.restore();
  }

  if(!world.mouseInside){
    ctx.save();
    ctx.fillStyle = 'rgba(255,255,255,0.34)';
    ctx.font = '14px ui-sans-serif, system-ui';
    ctx.fillText('Move mouse inside the canvas to move the Operator Target.', 18, 28);
    ctx.restore();
  }
}

/** UI actions */
ui.btnReset.addEventListener('click', async () => {
  world.op.x = world.w * 0.28;
  world.op.y = world.h * 0.56;
  world.dr.x = world.w * 0.66;
  world.dr.y = world.h * 0.46;
  world.dr.vx = 0; world.dr.vy = 0;
  world.ex.x = world.w * 0.70;
  world.ex.y = world.h * 0.58;
  world.ex.dir = 1;
  world.ex.t = 0;
  world.lastAction = 'RESET';
  world.lastViolation = '—';
  await appendEvent({ type:'RESET', note:'Reset operator/drone positions' });
  setStatus('READY');
});

ui.btnEmit.addEventListener('click', async () => {
  const cfg = readCfg();
  await appendEvent({
    type:'MANUAL_EVENT',
    mode: ui.mode.value,
    pack: world.activePack,
    scenario: world.activeScenario,
    seed: Number(ui.seed.value || 0),
    cfg,
    operator: { x: world.op.x, y: world.op.y },
    drone: { x: world.dr.x, y: world.dr.y },
    action: world.lastAction,
    violation: world.lastViolation
  });
  setStatus('EVENT EMITTED');
});

ui.btnClearLog.addEventListener('click', async () => {
  // IMPORTANT: to guarantee chain integrity, clear also resets head and entries atomically
  ledger.entries = [];
  ledger.head = 'GENESIS';
  renderLog();
  persistState();
  await appendEvent({ type:'LOG_RESET', note:'Ledger cleared and chain restarted from GENESIS' });
  setStatus('LOG CLEARED');
});

ui.btnCopyLog.addEventListener('click', async () => {
  const json = JSON.stringify({ ...ledger }, null, 2);
  await navigator.clipboard.writeText(json);
  setStatus('LOG COPIED');
});

ui.btnRandomObs.addEventListener('click', async () => {
  world.obstacles = randomObstacles(5, Number(ui.seed.value || 1));
  await appendEvent({ type:'OBSTACLES_RANDOMIZED', count: world.obstacles.length, seed: Number(ui.seed.value || 0) });
  setStatus('OBSTACLES RANDOMIZED');
});

ui.btnClearObs.addEventListener('click', async () => {
  world.obstacles = [];
  await appendEvent({ type:'OBSTACLES_CLEARED' });
  setStatus('OBSTACLES CLEARED');
});

ui.btnApplyPolicy.addEventListener('click', () => applyPolicyPack(ui.policyPack.value));
ui.btnApplyScenario.addEventListener('click', () => applyScenarioPack(ui.scenarioPack.value));
ui.btnShare.addEventListener('click', copyShareLink);

ui.seed.addEventListener('change', () => {
  persistState();
});

/** boot */
let last = performance.now();

async function boot(){
  applyFromURL();

  const saved = loadState();
  if(saved && !location.search){
    try{
      ui.seed.value = String(saved.seed ?? ui.seed.value);
      if(saved.activePack && POLICY_PACKS[saved.activePack]) ui.policyPack.value = saved.activePack;
      if(saved.activeScenario && SCENARIO_PACKS[saved.activeScenario]) ui.scenarioPack.value = saved.activeScenario;

      if(saved.ledger && Array.isArray(saved.ledger.entries)){
        ledger.entries = saved.ledger.entries;
        ledger.head = saved.ledger.head || 'GENESIS';
      }
      if(Array.isArray(saved.obstacles)){
        world.obstacles = saved.obstacles;
      }
    }catch(_e){}
  }

  applyScenarioPack(ui.scenarioPack.value);
  applyPolicyPack(ui.policyPack.value);

  await appendEvent({ type:'BOOT', note:'Control Core booted (append queue enabled)' });
  renderLog();
  requestAnimationFrame(loop);
}

function loop(){
  const t = performance.now();
  const dt = clamp((t - last) / 1000, 0, 0.05);
  last = t;
  update(dt);
  draw();
  requestAnimationFrame(loop);
}

boot();
