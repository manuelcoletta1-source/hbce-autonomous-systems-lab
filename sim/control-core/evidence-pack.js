'use strict';

const STORAGE_KEY = 'HBCE_CONTROL_CORE_STATE_V1';
const KEYSTORE = 'HBCE_KEYS_V1';

const $ = (id) => document.getElementById(id);

function safeParse(raw){
  try{ return JSON.parse(raw); }catch(_e){ return null; }
}

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

  // pack_hash = sha256(JSON.stringify(payload_without_pack_hash))
  const pack_hash = await HBCE_CRYPTO.sha256Hex(JSON.stringify(payload));
  const pack = { ...payload, pack_hash };

  // Optional signature (fail-visible)
  const ks = safeParse(localStorage.getItem(KEYSTORE) || '');
  if(ks && ks.algo === 'Ed25519' && ks.privateKey_pkcs8_b64u && ks.publicKey_b64u){
    try{
      const priv = await HBCE_CRYPTO.importEd25519Private(ks.privateKey_pkcs8_b64u);
      const sig = await HBCE_CRYPTO.signEd25519(priv, pack.pack_hash);
      pack.signature = {
        algo: 'Ed25519',
        signed: 'pack_hash',
        publicKey_b64u: ks.publicKey_b64u,
        sig_b64u: sig
      };
    }catch(_e){
      pack.signature = {
        algo: 'UNSIGNED',
        reason: 'SIGN_FAILED_ON_THIS_BROWSER',
      };
    }
  } else {
    pack.signature = {
      algo: 'UNSIGNED',
      reason: 'NO_KEYS',
    };
  }

  return pack;
}

async function maybeInitKeys(){
  // Create keys once if Ed25519 is supported
  const exists = safeParse(localStorage.getItem(KEYSTORE) || '');
  if(exists && exists.publicKey_b64u) return;

  const ok = await HBCE_CRYPTO.ed25519Support();
  if(!ok) return;

  const kp = await HBCE_CRYPTO.generateEd25519();
  localStorage.setItem(KEYSTORE, JSON.stringify(kp));
}

async function loadState(){
  const raw = localStorage.getItem(STORAGE_KEY);
  const state = safeParse(raw || '');
  return state;
}

async function renderPack(){
  await maybeInitKeys();

  const state = await loadState();
  if(!state || !state.ledger){
    $('out').textContent = JSON.stringify({ error:'No Control Core state found. Open Control Core first.' }, null, 2);
    return;
  }

  const pack = await buildPackFromState(state);
  $('out').textContent = JSON.stringify(pack, null, 2);
}

async function copyOut(){
  await navigator.clipboard.writeText($('out').textContent);
  $('status').textContent = 'Copied.';
}

$('btnBuild').addEventListener('click', renderPack);
$('btnCopy').addEventListener('click', copyOut);

// auto-build
renderPack();
