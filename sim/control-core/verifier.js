'use strict';

const STORAGE_KEY = 'HBCE_CONTROL_CORE_STATE_V1';

const $ = (id) => document.getElementById(id);

function safeParse(raw){
  try{ return JSON.parse(raw); }catch(_e){ return null; }
}

function hex(buf){
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2,'0')).join('');
}

async function sha256(str){
  const data = new TextEncoder().encode(str);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return hex(digest);
}

function setText(id, v){ $(id).textContent = (v ?? '—'); }

function writeDiag(obj){
  $('diag').textContent = JSON.stringify(obj, null, 2);
}

function buildReplayLink(pack){
  const base = location.origin + location.pathname.replace(/\/verifier\.html$/, '/');
  const u = new URL(base);
  const replay = pack?.replay || {};
  if(replay.policy_pack) u.searchParams.set('p', replay.policy_pack);
  if(replay.scenario_pack) u.searchParams.set('s', replay.scenario_pack);
  if(Number.isFinite(replay.seed)) u.searchParams.set('seed', String(replay.seed));
  return u.toString();
}

/** Verify ledger chain: prev_hash -> hash for each entry */
async function verifyLedgerChain(ledger){
  if(!ledger || !Array.isArray(ledger.entries)) {
    return { ok:false, reason:'MISSING_LEDGER' };
  }
  let prev = 'GENESIS';
  for(let i=0;i<ledger.entries.length;i++){
    const e = ledger.entries[i];
    const { hash, ...payload } = e;

    if(payload.prev_hash !== prev){
      return { ok:false, reason:`PREV_HASH_MISMATCH_AT_${i}`, expected_prev: prev, found_prev: payload.prev_hash };
    }

    const recomputed = await sha256(JSON.stringify(payload));
    if(recomputed !== hash){
      return { ok:false, reason:`HASH_MISMATCH_AT_${i}`, expected_hash: recomputed, found_hash: hash };
    }
    prev = hash;
  }
  return { ok:true, head: prev, entries: ledger.entries.length };
}

/**
 * Verify evidence pack hash:
 * - If pack_hash exists: compare
 * - If missing: return DRAFT with suggested recomputed hash
 */
async function verifyPackHash(pack){
  if(!pack || pack.proto !== 'HBCE-EVIDENCE-PACK-v1'){
    return { ok:false, status:'INVALID', reason:'NOT_EVIDENCE_PACK_V1' };
  }

  // Recompute from payload without pack_hash (canonical for v1)
  const { pack_hash, ...payload } = pack;
  const recomputed = await sha256(JSON.stringify(payload));

  if(!pack_hash){
    return { ok:false, status:'DRAFT_MISSING_PACK_HASH', reason:'MISSING_PACK_HASH', recomputed };
  }

  const ok = (recomputed === pack_hash);
  return { ok, status: ok ? 'OK' : 'MISMATCH', pack_hash, recomputed };
}

/** Build a canonical Evidence Pack v1 from state (and compute pack_hash) */
async function buildPackFromState(state){
  const payload = {
    proto: 'HBCE-EVIDENCE-PACK-v1',
    kind: 'CONTROL_CORE_SIM_EVIDENCE',
    ts: new Date().toISOString(),
    replay: {
      policy_pack: state.activePack,
      scenario_pack: state.activeScenario,
      seed: state.seed,
      cfg: state.cfg
    },
    environment: { obstacles: state.obstacles || [] },
    ledger: state.ledger || null
  };
  const pack_hash = await sha256(JSON.stringify(payload));
  return { ...payload, pack_hash };
}

async function runVerify(){
  const raw = $('input').value.trim();
  const pack = safeParse(raw);

  if(!pack){
    setText('rStatus', 'INVALID_JSON');
    setText('rPackHash', '—');
    setText('rRecomputed', '—');
    setText('rLedger', '—');
    setText('rEntries', '—');
    writeDiag({ error:'Invalid JSON. Paste a full Evidence Pack.' });
    return;
  }

  const ph = await verifyPackHash(pack);
  const lc = await verifyLedgerChain(pack.ledger);

  // Status rules:
  // - VALID only if pack hash OK + ledger OK
  // - DRAFT if missing pack_hash but ledger OK (we show suggested hash)
  let status = 'INVALID';
  if(ph.status === 'OK' && lc.ok) status = 'VALID';
  else if(ph.status === 'DRAFT_MISSING_PACK_HASH' && lc.ok) status = 'DRAFT';
  else status = 'INVALID';

  setText('rStatus', status);

  setText('rPackHash', ph.pack_hash || '—');
  setText('rRecomputed', ph.recomputed || '—');
  setText('rLedger', lc.ok ? 'OK' : `BROKEN (${lc.reason})`);
  setText('rEntries', lc.entries ?? '—');

  setText('rPolicy', pack?.replay?.policy_pack ?? '—');
  setText('rScenario', pack?.replay?.scenario_pack ?? '—');
  setText('rSeed', (pack?.replay?.seed ?? '—'));

  writeDiag({
    status,
    pack_hash_check: ph,
    ledger_chain_check: lc,
    replay: pack.replay,
    meta: { proto: pack.proto, kind: pack.kind, ts: pack.ts }
  });

  $('btnCopyReplayLink').dataset.link = buildReplayLink(pack);
}

async function loadFromLocalStorage(){
  const raw = localStorage.getItem(STORAGE_KEY);
  const state = safeParse(raw || '');

  if(!state || !state.ledger){
    $('input').value = '';
    writeDiag({ error:'No local state found. Open Control Core first, then Evidence Pack.' });
    return;
  }

  // Build a FULL pack with pack_hash so Verify can return VALID
  const pack = await buildPackFromState(state);
  $('input').value = JSON.stringify(pack, null, 2);

  writeDiag({
    loaded: 'localStorage',
    note: 'Built full Evidence Pack v1 (including pack_hash) from local state. Click Verify.'
  });
}

async function copyReplayLink(){
  const link = $('btnCopyReplayLink').dataset.link;
  if(!link){
    await runVerify();
  }
  const final = $('btnCopyReplayLink').dataset.link;
  if(final){
    await navigator.clipboard.writeText(final);
    writeDiag({ copied_replay_link: final });
  }
}

$('btnVerify').addEventListener('click', runVerify);
$('btnLoadFromLocal').addEventListener('click', () => { loadFromLocalStorage(); });
$('btnClear').addEventListener('click', () => {
  $('input').value = '';
  writeDiag({ cleared:true });
  setText('rStatus','—');
  setText('rPackHash','—');
  setText('rRecomputed','—');
  setText('rLedger','—');
  setText('rEntries','—');
  setText('rPolicy','—');
  setText('rScenario','—');
  setText('rSeed','—');
});

$('btnCopyReplayLink').addEventListener('click', copyReplayLink);

// Auto-verify convenience
if(location.hash === '#autoverify'){
  setTimeout(() => { if($('input').value.trim()) runVerify(); }, 80);
}
