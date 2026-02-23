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

/**
 * Canonical serialization: stable_sorted_keys
 * - objects: keys sorted lexicographically
 * - arrays: preserved order
 * - primitives: JSON.stringify
 */
function stable(obj){
  if(obj === null || typeof obj !== 'object') return JSON.stringify(obj);
  if(Array.isArray(obj)) return '[' + obj.map(stable).join(',') + ']';
  const keys = Object.keys(obj).sort();
  return '{' + keys.map(k => JSON.stringify(k) + ':' + stable(obj[k])).join(',') + '}';
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

/** Verify ledger chain (hash = sha256(JSON.stringify(payload)) by design of ledger entries) */
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

    // Ledger entries are already authored with JSON.stringify(payload) in Control Core.
    // We must verify them with the SAME rule.
    const recomputed = await sha256(JSON.stringify(payload));
    if(recomputed !== hash){
      return { ok:false, reason:`HASH_MISMATCH_AT_${i}`, expected_hash: recomputed, found_hash: hash };
    }
    prev = hash;
  }
  return { ok:true, head: prev, entries: ledger.entries.length };
}

/** Verify pack hash (canonical = stable_sorted_keys) */
async function verifyPackHash(pack){
  if(!pack || pack.proto !== 'HBCE-EVIDENCE-PACK-v1'){
    return { ok:false, status:'INVALID', reason:'NOT_EVIDENCE_PACK_V1' };
  }

  const { pack_hash, ...payload } = pack;

  // canonical v3 rule:
  // - exclude pack_hash
  // - exclude signature (optional)
  delete payload.signature;

  const recomputed = await sha256(stable(payload));

  if(!pack_hash){
    return { ok:false, status:'DRAFT_MISSING_PACK_HASH', reason:'MISSING_PACK_HASH', recomputed };
  }
  const ok = (recomputed === pack_hash);
  return { ok, status: ok ? 'OK' : 'MISMATCH', pack_hash, recomputed };
}

/** Verify optional signature */
async function verifySignature(pack){
  const sig = pack?.signature;
  if(!sig) return { ok:false, status:'MISSING', reason:'NO_SIGNATURE_OBJECT' };
  if(sig.algo !== 'Ed25519') return { ok:false, status:'UNSIGNED', reason: sig.reason || 'NOT_ED25519' };
  if(sig.signed !== 'pack_hash') return { ok:false, status:'INVALID', reason:'SIGNED_FIELD_NOT_pack_hash' };
  if(!sig.publicKey_b64u || !sig.sig_b64u) return { ok:false, status:'INVALID', reason:'MISSING_SIGNATURE_FIELDS' };

  // NOTE: signature verification depends on crypto.js implementation (HBCE_CRYPTO).
  // If missing, we fail-closed on signature only, but pack can still be VALID if hash+ledger OK.
  if(typeof HBCE_CRYPTO === 'undefined'){
    return { ok:false, status:'ERROR', reason:'HBCE_CRYPTO not loaded (crypto.js missing)' };
  }

  try{
    const pub = await HBCE_CRYPTO.importEd25519Public(sig.publicKey_b64u);
    const ok = await HBCE_CRYPTO.verifyEd25519(pub, pack.pack_hash, sig.sig_b64u);
    return { ok, status: ok ? 'OK' : 'BAD_SIG' };
  }catch(e){
    return { ok:false, status:'ERROR', reason:String(e?.message || e) };
  }
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
  const sg = await verifySignature(pack);

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
    pack_hash_match: ph.ok,
    ledger_ok: lc.ok,
    canonical: 'stable_sorted_keys',
    hash: 'SHA256',
    engine: 'HBCE verifier v3 (canonical stable)',
    signature_check: sg,
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

  $('input').value = '';
  writeDiag({ note:'Use Evidence Pack page to build pack, then paste here.' });
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

if(location.hash === '#autoverify'){
  setTimeout(() => { if($('input').value.trim()) runVerify(); }, 80);
}
