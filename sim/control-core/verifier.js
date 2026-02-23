'use strict';

/*
  HBCE • Evidence Pack Verifier (browser-only)
  - Deterministic pack_hash recomputation (stable canonical JSON: sorted keys)
  - Ledger hash-chain verification (keeps JSON.stringify(payload) to match Control Core log hashing)
  - Optional Ed25519 signature verification (if HBCE_CRYPTO is available)
  - FAIL overlay hook: showOverlay()/closeOverlay() if present
*/

const STORAGE_KEY = 'HBCE_CONTROL_CORE_STATE_V1';

// --- DOM helpers ---
const $ = (id) => document.getElementById(id);

function setText(id, v){
  const el = $(id);
  if(el) el.textContent = (v ?? '—');
}

function writeDiag(obj){
  const el = $('diag');
  if(el) el.textContent = JSON.stringify(obj, null, 2);
}

function safeParse(raw){
  try { return JSON.parse(raw); } catch(_e){ return null; }
}

// --- crypto helpers ---
function hex(buf){
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}

async function sha256(str){
  const data = new TextEncoder().encode(str);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return hex(digest);
}

/*
  Stable canonical stringify (sorted keys) to avoid “same object, different key order” hash mismatch.
  IMPORTANT: This must match your pack producer(s). If producers use stable ordering, verifier must too.
*/
function stableStringify(value){
  if(value === null) return 'null';

  const t = typeof value;

  if(t === 'number'){
    // JSON.stringify(NaN) => null. Keep JSON semantics.
    return Number.isFinite(value) ? String(value) : 'null';
  }
  if(t === 'boolean') return value ? 'true' : 'false';
  if(t === 'string') return JSON.stringify(value);

  if(Array.isArray(value)){
    return '[' + value.map(stableStringify).join(',') + ']';
  }

  if(t === 'object'){
    const keys = Object.keys(value).sort();
    return '{' + keys.map(k => JSON.stringify(k) + ':' + stableStringify(value[k])).join(',') + '}';
  }

  // functions / undefined are not valid JSON; JSON.stringify would drop them in objects.
  // In stable canonicalization we treat them as null to be fail-closed.
  return 'null';
}

// --- replay link helper ---
function buildReplayLink(pack){
  // target Control Core root folder
  const base = location.origin + location.pathname.replace(/\/verifier\.html$/, '/');
  const u = new URL(base);
  const replay = pack?.replay || {};
  if(replay.policy_pack) u.searchParams.set('p', replay.policy_pack);
  if(replay.scenario_pack) u.searchParams.set('s', replay.scenario_pack);
  if(Number.isFinite(replay.seed)) u.searchParams.set('seed', String(replay.seed));
  return u.toString();
}

// --- FAIL overlay hooks (optional) ---
function showFailOverlay(){
  // Prefer page-level helpers if defined (from verifier.html)
  if(typeof window.showOverlay === 'function') return window.showOverlay();
  const ov = $('failOverlay');
  if(ov) ov.style.display = 'flex';
}

function hideFailOverlay(){
  if(typeof window.closeOverlay === 'function') return window.closeOverlay();
  const ov = $('failOverlay');
  if(ov) ov.style.display = 'none';
}

// --- Ledger chain verification ---
// IMPORTANT: This intentionally uses JSON.stringify(payload), because your Control Core ledger hashes
// were generated that way. If you change ledger hashing to stableStringify, update both sides together.
async function verifyLedgerChain(ledger){
  if(!ledger || !Array.isArray(ledger.entries)){
    return { ok:false, reason:'MISSING_LEDGER' };
  }

  let prev = 'GENESIS';

  for(let i = 0; i < ledger.entries.length; i++){
    const e = ledger.entries[i];
    if(!e || typeof e !== 'object'){
      return { ok:false, reason:`ENTRY_NOT_OBJECT_AT_${i}` };
    }

    const { hash, ...payload } = e;

    if(payload.prev_hash !== prev){
      return {
        ok:false,
        reason:`PREV_HASH_MISMATCH_AT_${i}`,
        expected_prev: prev,
        found_prev: payload.prev_hash
      };
    }

    const recomputed = await sha256(JSON.stringify(payload));

    if(recomputed !== hash){
      return {
        ok:false,
        reason:`HASH_MISMATCH_AT_${i}`,
        expected_hash: recomputed,
        found_hash: hash
      };
    }

    prev = hash;
  }

  // Some packs keep ledger.head. We can check it (fail-closed optional).
  if(ledger.head && ledger.head !== prev){
    return { ok:false, reason:'LEDGER_HEAD_MISMATCH', expected_head: prev, found_head: ledger.head, entries: ledger.entries.length };
  }

  return { ok:true, head: prev, entries: ledger.entries.length };
}

// --- Pack hash verification ---
async function verifyPackHash(pack){
  if(!pack || pack.proto !== 'HBCE-EVIDENCE-PACK-v1'){
    return { ok:false, status:'INVALID', reason:'NOT_EVIDENCE_PACK_V1' };
  }

  const { pack_hash, ...payload } = pack;

  // v1 canonical: hash material excludes pack_hash and excludes signature
  delete payload.signature;

  const recomputed = await sha256(stableStringify(payload));

  if(!pack_hash){
    return { ok:false, status:'DRAFT_MISSING_PACK_HASH', reason:'MISSING_PACK_HASH', recomputed };
  }

  const ok = (recomputed === pack_hash);
  return { ok, status: ok ? 'OK' : 'MISMATCH', pack_hash, recomputed };
}

// --- Optional signature verification (Ed25519) ---
// Requires crypto.js providing HBCE_CRYPTO.importEd25519Public + verifyEd25519.
async function verifySignature(pack){
  const sig = pack?.signature;

  if(!sig){
    return { ok:false, status:'MISSING', reason:'NO_SIGNATURE_OBJECT' };
  }

  if(sig.algo !== 'Ed25519'){
    // Treat as "unsigned" rather than hard fail; pack validity is hash+ledger.
    return { ok:false, status:'UNSIGNED', reason: sig.reason || 'NOT_ED25519' };
  }

  if(sig.signed !== 'pack_hash'){
    return { ok:false, status:'INVALID', reason:'SIGNED_FIELD_NOT_pack_hash' };
  }

  if(!sig.publicKey_b64u || !sig.sig_b64u){
    return { ok:false, status:'INVALID', reason:'MISSING_SIGNATURE_FIELDS' };
  }

  if(typeof window.HBCE_CRYPTO?.importEd25519Public !== 'function' || typeof window.HBCE_CRYPTO?.verifyEd25519 !== 'function'){
    return { ok:false, status:'ERROR', reason:'HBCE_CRYPTO_NOT_AVAILABLE' };
  }

  try{
    const pub = await window.HBCE_CRYPTO.importEd25519Public(sig.publicKey_b64u);
    const ok = await window.HBCE_CRYPTO.verifyEd25519(pub, pack.pack_hash, sig.sig_b64u);
    return { ok, status: ok ? 'OK' : 'BAD_SIG' };
  }catch(e){
    return { ok:false, status:'ERROR', reason:String(e?.message || e) };
  }
}

// --- Main verify runner ---
async function runVerify(){
  const inputEl = $('input');
  const raw = (inputEl?.value || '').trim();

  const pack = safeParse(raw);

  if(!pack){
    setText('status', 'INVALID_JSON');
    setText('ph', '—');
    setText('rc', '—');
    setText('lg', '—');
    setText('en', '—');
    writeDiag({ error:'Invalid JSON. Paste a full Evidence Pack.' });
    showFailOverlay();
    return;
  }

  const ph = await verifyPackHash(pack);
  const lc = await verifyLedgerChain(pack.ledger);
  const sg = await verifySignature(pack);

  let status = 'INVALID';

  if(ph.status === 'OK' && lc.ok){
    status = 'VALID';
  }else if(ph.status === 'DRAFT_MISSING_PACK_HASH' && lc.ok){
    status = 'DRAFT';
  }else{
    status = 'INVALID';
  }

  // UI
  setText('status', status);
  setText('ph', ph.pack_hash || '—');
  setText('rc', ph.recomputed || '—');
  setText('lg', lc.ok ? 'OK' : `BROKEN (${lc.reason})`);
  setText('en', (lc.entries ?? '—'));

  // Fail overlay behavior: only for INVALID
  if(status === 'VALID') hideFailOverlay();
  if(status === 'INVALID') showFailOverlay();

  // Diagnostics
  writeDiag({
    status,
    pack_hash_check: ph,
    ledger_chain_check: lc,
    signature_check: sg,
    replay: pack.replay || null,
    replay_link: buildReplayLink(pack),
    meta: { proto: pack.proto, kind: pack.kind, ts: pack.ts || null },
    canonical: 'stable_sorted_keys',
    hash: 'SHA-256'
  });

  // Store replay link on a dataset if a button exists (optional in some layouts)
  const btn = $('btnCopyReplayLink');
  if(btn) btn.dataset.link = buildReplayLink(pack);
}

// --- Optional extras (if your layout has these buttons) ---
async function copyReplayLink(){
  const btn = $('btnCopyReplayLink');
  let link = btn?.dataset?.link;

  if(!link){
    await runVerify();
    link = btn?.dataset?.link;
  }

  if(link){
    await navigator.clipboard.writeText(link);
    writeDiag({ copied_replay_link: link });
  }
}

function clearAll(){
  const inputEl = $('input');
  if(inputEl) inputEl.value = '';
  hideFailOverlay();
  writeDiag({ cleared:true });
}

// --- Event wiring (robust on mobile) ---
function wire(){
  // Expose for inline HTML buttons (if present)
  window.verify = runVerify;
  window.clearAll = clearAll;

  // If layout has these IDs, wire them too
  const btnVerify = $('btnVerify');
  if(btnVerify) btnVerify.addEventListener('click', runVerify, { passive:true });

  const btnClear = $('btnClear');
  if(btnClear) btnClear.addEventListener('click', clearAll, { passive:true });

  const btnCopy = $('btnCopyReplayLink');
  if(btnCopy) btnCopy.addEventListener('click', copyReplayLink, { passive:true });

  // Optional autoverify
  if(location.hash === '#autoverify'){
    setTimeout(() => {
      const inputEl = $('input');
      if(inputEl && inputEl.value.trim()) runVerify();
    }, 80);
  }
}

if(document.readyState === 'loading'){
  document.addEventListener('DOMContentLoaded', wire);
}else{
  wire();
}
