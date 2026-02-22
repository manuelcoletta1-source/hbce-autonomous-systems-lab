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
    // Recompute entry hash from the same material used in core.js:
    // payload = { ts, ...event, prev_hash }
    // entry = { ...payload, hash }
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

/** Verify evidence pack hash: pack_hash == sha256(JSON.stringify(payload_without_pack_hash)) */
async function verifyPackHash(pack){
  if(!pack || pack.proto !== 'HBCE-EVIDENCE-PACK-v1'){
    return { ok:false, reason:'NOT_EVIDENCE_PACK_V1' };
  }
  if(!pack.pack_hash){
    return { ok:false, reason:'MISSING_PACK_HASH' };
  }
  const { pack_hash, ...payload } = pack;
  const recomputed = await sha256(JSON.stringify(payload));
  return { ok: (recomputed === pack_hash), pack_hash, recomputed };
}

async function runVerify(){
  const raw = $('input').value.trim();
  const pack = safeParse(raw);

  if(!pack){
    setText('rStatus', 'INVALID_JSON');
    writeDiag({ error:'Invalid JSON. Paste a full Evidence Pack.' });
    return;
  }

  const ph = await verifyPackHash(pack);
  const lc = await verifyLedgerChain(pack.ledger);

  const ok = ph.ok && lc.ok;

  setText('rStatus', ok ? 'VALID' : 'INVALID');
  setText('rPackHash', ph.pack_hash || '—');
  setText('rRecomputed', ph.recomputed || '—');
  setText('rLedger', lc.ok ? 'OK' : `BROKEN (${lc.reason})`);
  setText('rEntries', lc.entries ?? '—');

  setText('rPolicy', pack?.replay?.policy_pack ?? '—');
  setText('rScenario', pack?.replay?.scenario_pack ?? '—');
  setText('rSeed', (pack?.replay?.seed ?? '—'));

  writeDiag({ pack_hash_check: ph, ledger_chain_check: lc, replay: pack.replay, meta: { proto: pack.proto, kind: pack.kind, ts: pack.ts } });

  // store replay link on button
  $('btnCopyReplayLink').dataset.link = buildReplayLink(pack);
}

function loadFromLocalStorage(){
  const raw = localStorage.getItem(STORAGE_KEY);
  const state = safeParse(raw || '');
  if(!state || !state.ledger){
    $('input').value = '';
    writeDiag({ error:'No local state found. Open Control Core first, then Evidence Pack.' });
    return;
  }
  // Rebuild a pack identical to evidence-pack.js (minus pack_hash, we’ll recompute in verify)
  const draft = {
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
  // Note: pack_hash added only for verification round-trip
  $('input').value = JSON.stringify(draft, null, 2);
  writeDiag({ loaded:'localStorage draft (no pack_hash yet). Click Verify to compute and compare once you paste final pack.' });
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
$('btnLoadFromLocal').addEventListener('click', loadFromLocalStorage);
$('btnClear').addEventListener('click', () => { $('input').value = ''; writeDiag({ cleared:true }); });

$('btnCopyReplayLink').addEventListener('click', copyReplayLink);

// tiny UX: auto-verify if URL has #autoverify and textarea has content
if(location.hash === '#autoverify'){
  setTimeout(() => { if($('input').value.trim()) runVerify(); }, 80);
}
