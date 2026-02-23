'use strict';

const STORAGE_LAST_RECEIPT = 'HBCE_BINDING_LAST_RECEIPT_V1';

const $ = (id) => document.getElementById(id);

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

function hex(buf){
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2,'0')).join('');
}
async function sha256Hex(str){
  const data = new TextEncoder().encode(str);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return hex(digest);
}

function setStatus(txt, ok=true){
  $('status').innerHTML = ok ? `<span class="ok">${txt}</span>` : `<span class="bad">${txt}</span>`;
}

function nowIso(){
  return new Date().toISOString();
}

function loadTs(){
  $('ts').value = nowIso();
}

let lastReceipt = null;

async function createReceipt(){
  loadTs();

  const seedNum = Number(String($('seed').value).trim());
  if(!Number.isFinite(seedNum)){
    lastReceipt = null;
    $('out').textContent = '{}';
    return setStatus('Seed must be a number', false);
  }

  const receipt = {
    proto: 'HBCE-BINDING-RECEIPT-v1',
    kind: 'JOKER_C2_BINDING',
    ts: String($('ts').value).trim(),
    binding: {
      operator_id: String($('operator_id').value).trim(),
      ai_id: String($('ai_id').value).trim(),
      policy_pack: String($('policy_pack').value).trim(),
      scenario_pack: String($('scenario_pack').value).trim(),
      seed: seedNum,
      scope: String($('scope').value).trim()
    },
    policy: ['HASH_ONLY','APPEND_ONLY','AUDIT_FIRST','FAIL_CLOSED'],
    prev_head: 'GENESIS'
  };

  const material = JSON.parse(JSON.stringify(receipt));
  const receipt_hash = await sha256Hex(stableStringify(material));
  receipt.receipt_hash = receipt_hash;

  lastReceipt = receipt;
  localStorage.setItem(STORAGE_LAST_RECEIPT, JSON.stringify(receipt));

  $('out').textContent = JSON.stringify(receipt, null, 2);
  setStatus('CREATED ✔');
}

async function copyReceipt(){
  if(!lastReceipt){
    const raw = localStorage.getItem(STORAGE_LAST_RECEIPT);
    if(raw) lastReceipt = JSON.parse(raw);
  }
  if(!lastReceipt) return setStatus('No receipt to copy', false);
  await navigator.clipboard.writeText(JSON.stringify(lastReceipt, null, 2));
  setStatus('Copied');
}

function clearAll(){
  lastReceipt = null;
  $('out').textContent = '{}';
  $('status').textContent = '—';
}

$('btnCreate').addEventListener('click', createReceipt);
$('btnCopy').addEventListener('click', copyReceipt);
$('btnClear').addEventListener('click', clearAll);

loadTs();
