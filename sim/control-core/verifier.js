'use strict';

/**
 * HBCE Verifier v1 (self-contained)
 * - pack_hash: SHA-256(stableStringify(payloadWithout(pack_hash, signature)))
 * - ledger chain: SHA-256(JSON.stringify(entryPayloadWithout(hash)))
 *   (kept as JSON.stringify to match Control Core generation)
 */

const $ = (id) => document.getElementById(id);

function safeParse(raw){
  try { return JSON.parse(raw); } catch { return null; }
}

function hex(buf){
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2,'0')).join('');
}

async function sha256Hex(str){
  const data = new TextEncoder().encode(str);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return hex(digest);
}

/** Stable stringify with sorted keys (canonical for pack hashing) */
function stableStringify(v){
  if(v === null) return 'null';
  const t = typeof v;
  if(t === 'number') return Number.isFinite(v) ? String(v) : 'null';
  if(t === 'boolean') return v ? 'true' : 'false';
  if(t === 'string') return JSON.stringify(v);
  if(Array.isArray(v)) return '[' + v.map(stableStringify).join(',') + ']';
  if(t === 'object'){
    const keys = Object.keys(v).sort();
    return '{' + keys.map(k => JSON.stringify(k) + ':' + stableStringify(v[k])).join(',') + '}';
  }
  return 'null';
}

function setText(id, v){ $(id).textContent = (v ?? '—'); }
function writeDiag(obj){ $('diag').textContent = JSON.stringify(obj, null, 2); }

function buildReplayLink(pack){
  const replay = pack?.replay || {};
  const base = location.origin + location.pathname.replace(/\/verifier\.html$/, '/');
  const u = new URL(base);
  if(replay.policy_pack) u.searchParams.set('p', replay.policy_pack);
  if(replay.scenario_pack) u.searchParams.set('s', replay.scenario_pack);
  if(Number.isFinite(replay.seed)) u.searchParams.set('seed', String(replay.seed));
  return u.toString();
}

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

    // IMPORTANT: match Control Core hashing
    const recomputed = await sha256Hex(JSON.stringify(payload));
    if(recomputed !== hash){
      return { ok:false, reason:`HASH_MISMATCH_AT_${i}`, expected_hash: recomputed, found_hash: hash };
    }
    prev = hash;
  }
  return { ok:true, head: prev, entries: ledger.entries.length };
}

async function verifyPackHash(pack){
  if(!pack || pack.proto !== 'HBCE-EVIDENCE-PACK-v1'){
    return { ok:false, status:'INVALID', reason:'NOT_EVIDENCE_PACK_V1' };
  }
  const pack_hash = pack.pack_hash;
  const payload = JSON.parse(JSON.stringify(pack));
  delete payload.pack_hash;
  delete payload.signature;

  const recomputed = await sha256Hex(stableStringify(payload));
  if(!pack_hash){
    return { ok:false, status:'DRAFT', reason:'MISSING_PACK_HASH', recomputed };
  }
  const ok = (recomputed === pack_hash);
  return { ok, status: ok ? 'OK' : 'MISMATCH', pack_hash, recomputed };
}

async function verifyOptionalSignature(pack){
  const sig = pack?.signature;
  if(!sig) return { ok:false, status:'MISSING' };

  if(sig.algo === 'NONE') return { ok:true, status:'UNSIGNED' };

  // We only validate Ed25519 if the browser supports it.
  if(sig.algo !== 'Ed25519') return { ok:false, status:'INVALID', reason:'UNSUPPORTED_ALGO' };
  if(sig.signed !== 'pack_hash') return { ok:false, status:'INVALID', reason:'SIGNED_FIELD_NOT_pack_hash' };
  if(!sig.publicKey_b64u || !sig.sig_b64u) return { ok:false, status:'INVALID', reason:'MISSING_SIGNATURE_FIELDS' };

  // Try WebCrypto Ed25519 (not universal on Android builds)
  try{
    const pub = await importEd25519Public(sig.publicKey_b64u);
    const ok = await verifyEd25519(pub, pack.pack_hash, sig.sig_b64u);
    return { ok, status: ok ? 'OK' : 'BAD_SIG' };
  }catch(e){
    return { ok:false, status:'ERROR', reason:String(e?.message || e) };
  }
}

/* --- Minimal Ed25519 helpers (WebCrypto). If unsupported -> throws. --- */
function b64uToBytes(b64u){
  const b64 = b64u.replace(/-/g,'+').replace(/_/g,'/') + '==='.slice((b64u.length + 3) % 4);
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for(let i=0;i<bin.length;i++) out[i] = bin.charCodeAt(i);
  return out;
}
async function importEd25519Public(publicKey_b64u){
  const raw = b64uToBytes(publicKey_b64u);
  return crypto.subtle.importKey('raw', raw, { name:'Ed25519' }, true, ['verify']);
}
async function verifyEd25519(publicKey, messageStr, sig_b64u){
  const sig = b64uToBytes(sig_b64u);
  const msg = new TextEncoder().encode(messageStr);
  const ok = await crypto.subtle.verify({ name:'Ed25519' }, publicKey, sig, msg);
  return !!ok;
}

let AUTO = false;
let lastReplayLink = '';

async function runVerify(){
  const raw = $('input').value.trim();
  const pack = safeParse(raw);

  if(!pack){
    setText('rStatus', 'INVALID_JSON');
    writeDiag({ error:'Invalid JSON. Paste a full HBCE Evidence Pack.' });
    return;
  }

  const ph = await verifyPackHash(pack);
  const lc = await verifyLedgerChain(pack.ledger);
  const sg = await verifyOptionalSignature(pack);

  const status = (ph.status === 'OK' && lc.ok) ? 'VALID' : 'INVALID';

  setText('rStatus', status === 'VALID' ? 'VALID' : 'INVALID');
  $('rStatus').className = status === 'VALID' ? 'pill-ok' : 'pill-bad';

  setText('rPackHash', ph.pack_hash || '—');
  setText('rRecomputed', ph.recomputed || '—');
  setText('rLedger', lc.ok ? 'OK' : `BROKEN (${lc.reason})`);
  setText('rEntries', lc.entries ?? '—');

  setText('rPolicy', pack?.replay?.policy_pack ?? '—');
  setText('rScenario', pack?.replay?.scenario_pack ?? '—');
  setText('rSeed', (pack?.replay?.seed ?? '—'));

  setText('rSig', sg.status + (sg.reason ? ` (${sg.reason})` : ''));

  lastReplayLink = buildReplayLink(pack);

  writeDiag({
    status,
    pack_hash_check: ph,
    ledger_chain_check: lc,
    signature_check: sg,
    replay: pack.replay,
    canonical: 'stable_sorted_keys',
    ledger_recompute: 'JSON.stringify(payload)',
    meta: { proto: pack.proto, kind: pack.kind, ts: pack.ts }
  });
}

async function copyReplayLink(){
  if(!lastReplayLink) await runVerify();
  if(!lastReplayLink) return;
  await navigator.clipboard.writeText(lastReplayLink);
  writeDiag({ copied_replay_link: lastReplayLink });
}

function clearAll(){
  $('input').value = '';
  lastReplayLink = '';
  setText('rStatus','—'); $('rStatus').className='';
  setText('rPackHash','—');
  setText('rRecomputed','—');
  setText('rLedger','—');
  setText('rEntries','—');
  setText('rPolicy','—');
  setText('rScenario','—');
  setText('rSeed','—');
  setText('rSig','—');
  writeDiag({ cleared:true });
}

function setAuto(){
  AUTO = !AUTO;
  $('btnAuto').textContent = 'Auto-verify on paste: ' + (AUTO ? 'ON' : 'OFF');
}

$('btnVerify').addEventListener('click', runVerify);
$('btnClear').addEventListener('click', clearAll);
$('btnCopyReplay').addEventListener('click', copyReplayLink);
$('btnAuto').addEventListener('click', setAuto);

// Android-safe auto verify: debounce on input changes
let t = null;
$('input').addEventListener('input', () => {
  if(!AUTO) return;
  clearTimeout(t);
  t = setTimeout(() => runVerify(), 120);
});
