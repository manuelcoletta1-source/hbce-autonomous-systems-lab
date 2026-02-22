'use strict';

const $ = (id) => document.getElementById(id);
const canvas = $('sim');
const ctx = canvas.getContext('2d');

const ui = {
  mode: $('mode'),
  speed: $('speed'),
  minDist: $('minDist'),
  maxSpeed: $('maxSpeed'),
  noTouch: $('noTouch'),
  boundary: $('boundary'),
  obsBuffer: $('obsBuffer'),
  hardStop: $('hardStop'),

  status: $('status'),
  policyState: $('policyState'),

  tOp: $('tOp'),
  tDr: $('tDr'),
  tDist: $('tDist'),
  tVel: $('tVel'),
  tAct: $('tAct'),
  tViol: $('tViol'),

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

function hex(buf){
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2,'0')).join('');
}
async function sha256(str){
  const data = new TextEncoder().encode(str);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return hex(digest);
}

const world = {
  w: canvas.width,
  h: canvas.height,
  op: { x: canvas.width * 0.28, y: canvas.height * 0.56, r: 10 },
  dr: { x: canvas.width * 0.66, y: canvas.height * 0.46, r: 9, vx: 0, vy: 0 },
  ex: { x: canvas.width * 0.70, y: canvas.height * 0.58, dir: 1, t: 0 },
  obstacles: [
    { x: 390, y: 120, w: 160, h: 70 },
    { x: 650, y: 330, w: 190, h: 80 },
    { x: 220, y: 360, w: 130, h: 70 },
  ],
  lastAction: '—',
  lastViolation: '—',
  mouseInside: false,
};

const ledger = {
  proto: 'HBCE-SIM-AUDIT-LOG-v1',
  policy: ['APPEND_ONLY', 'HASH_CHAIN', 'AUDIT_FIRST', 'FAIL_CLOSED'],
  entries: [],
  head: 'GENESIS'
};

async function appendEvent(event){
  const prev = ledger.head;
  const payload = { ts: nowISO(), ...event, prev_hash: prev };
  const h = await sha256(JSON.stringify(payload));
  ledger.entries.push({ ...payload, hash: h });
  ledger.head = h;
  renderLog();
}

function renderLog(){
  ui.log.textContent = JSON.stringify({
    proto: ledger.proto,
    policy: ledger.policy,
    head: ledger.head,
    entries: ledger.entries.slice(-70)
  }, null, 2);
}

function setStatus(text){ ui.status.textContent = `STATUS: ${text}`; }
function setPolicy(pass){
  ui.policyState.textContent = `POLICY: ${pass ? 'PASS' : 'DENY'}`;
  ui.policyState.classList.remove('pill--ok','pill--deny');
  ui.policyState.classList.add(pass ? 'pill--ok' : 'pill--deny');
}

canvas.addEventListener('mousemove', (e) => {
  const rect = canvas.getBoundingClientRect();
  const sx = canvas.width / rect.width;
  const sy = canvas.height / rect.height;
  world.op.x = clamp((e.clientX - rect.left) * sx, 0, world.w);
  world.op.y = clamp((e.clientY - rect.top) * sy, 0, world.h);
  world.mouseInside = true;
});
canvas.addEventListener('mouseleave', () => { world.mouseInside = false; });

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
function stepExplore(dt){
  const ex = world.ex;
  ex.t += dt;
  ex.x += ex.dir * 70 * dt;
  ex.y += Math.sin(ex.t * 0.7) * 12 * dt;
  if(ex.x < 80){ ex.x = 80; ex.dir = 1; }
  if(ex.x > world.w - 80){ ex.x = world.w - 80; ex.dir = -1; }
  ex.y = clamp(ex.y, 70, world.h - 70);
}

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

function update(dt){
  const mode = ui.mode.value;
  const cfg = {
    speed: clamp(parseFloat(ui.speed.value || '3.2'), 0.2, 12),
    minDist: clamp(parseFloat(ui.minDist.value || '60'), 10, 240),
    maxSpeed: clamp(parseFloat(ui.maxSpeed.value || '380'), 20, 1200),
    noTouch: clamp(parseFloat(ui.noTouch.value || '14'), 0, 80),
    boundary: clamp(parseFloat(ui.boundary.value || '10'), 0, 120),
    obsBuffer: clamp(parseFloat(ui.obsBuffer.value || '26'), 0, 120),
    hardStop: (ui.hardStop.value === 'YES'),
  };

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
        appendEvent({ type:'POLICY_DENY', code: pol.code, mode, action, operator:{x:op.x,y:op.y}, drone:{x:dr.x,y:dr.y}, cfg });
      }
      world.lastAction = 'DENY';
      setStatus(`DENY (${pol.code})`);
    } else {
      dr.vx = vx_ps; dr.vy = vy_ps;
      dr.x = clamp(nextX, 0, world.w);
      dr.y = clamp(nextY, 0, world.h);
      if(world.lastAction !== 'DENY_LOG_ONLY'){
        appendEvent({ type:'POLICY_VIOLATION_LOG_ONLY', code: pol.code, mode, action, operator:{x:op.x,y:op.y}, drone_next:{x:dr.x,y:dr.y}, cfg });
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
}

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

  const minDist = clamp(parseFloat(ui.minDist.value || '60'), 10, 240);
  const noTouch = clamp(parseFloat(ui.noTouch.value || '14'), 0, 80);
  const op = world.op;
  const dr = world.dr;

  ctx.save();
  ctx.beginPath();
  ctx.arc(op.x, op.y, minDist, 0, Math.PI*2);
  ctx.setLineDash([8,8]);
  ctx.strokeStyle = 'rgba(124,255,178,0.22)';
  ctx.stroke();
  ctx.restore();

  ctx.save();
  ctx.beginPath();
  ctx.arc(op.x, op.y, op.r + noTouch, 0, Math.PI*2);
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
  await appendEvent({
    type:'MANUAL_EVENT',
    mode: ui.mode.value,
    cfg: {
      speed: Number(ui.speed.value),
      minDist: Number(ui.minDist.value),
      maxSpeed: Number(ui.maxSpeed.value),
      noTouch: Number(ui.noTouch.value),
      boundary: Number(ui.boundary.value),
      obsBuffer: Number(ui.obsBuffer.value),
      hardStop: ui.hardStop.value
    },
    operator: { x: world.op.x, y: world.op.y },
    drone: { x: world.dr.x, y: world.dr.y },
    action: world.lastAction,
    violation: world.lastViolation
  });
  setStatus('EVENT EMITTED');
});

ui.btnClearLog.addEventListener('click', () => {
  ledger.entries = [];
  ledger.head = 'GENESIS';
  renderLog();
  setStatus('LOG CLEARED');
});

ui.btnCopyLog.addEventListener('click', async () => {
  const json = JSON.stringify({ ...ledger }, null, 2);
  await navigator.clipboard.writeText(json);
  setStatus('LOG COPIED');
});

ui.btnRandomObs.addEventListener('click', async () => {
  world.obstacles = randomObstacles(4);
  await appendEvent({ type:'OBSTACLES_RANDOMIZED', count: world.obstacles.length });
  setStatus('OBSTACLES RANDOMIZED');
});

ui.btnClearObs.addEventListener('click', async () => {
  world.obstacles = [];
  await appendEvent({ type:'OBSTACLES_CLEARED' });
  setStatus('OBSTACLES CLEARED');
});

function randomObstacles(count = 4){
  const obs = [];
  for(let i=0;i<count;i++){
    const w = 90 + Math.random()*160;
    const h = 55 + Math.random()*110;
    obs.push({
      x: 40 + Math.random()*(world.w - w - 80),
      y: 40 + Math.random()*(world.h - h - 80),
      w, h
    });
  }
  return obs;
}

let last = performance.now();
async function boot(){
  await appendEvent({ type:'BOOT', note:'Control Core booted (FAIL-CLOSED enabled)' });
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
