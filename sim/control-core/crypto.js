'use strict';

/**
 * HBCE Crypto v1 (Browser, no backend)
 * - Ed25519 signing via WebCrypto if available (not universal on all Android builds)
 * - Fallback: unsigned mode (fail-visible), still allows pack_hash verification
 */

function b64uFromBytes(bytes){
  let s = '';
  for(const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}

function bytesFromB64u(b64u){
  const b64 = b64u.replace(/-/g,'+').replace(/_/g,'/') + '==='.slice((b64u.length + 3) % 4);
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for(let i=0;i<bin.length;i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function sha256Hex(str){
  const data = new TextEncoder().encode(str);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return [...new Uint8Array(digest)].map(b=>b.toString(16).padStart(2,'0')).join('');
}

async function cryptoSupport(){
  return !!(window.crypto && crypto.subtle);
}

async function ed25519Support(){
  // Ed25519 is not guaranteed everywhere; attempt a keygen probe.
  if(!(await cryptoSupport())) return false;
  try{
    const kp = await crypto.subtle.generateKey({ name:'Ed25519' }, true, ['sign','verify']);
    // immediate dispose by letting it go out of scope
    return !!kp;
  }catch(_e){
    return false;
  }
}

async function generateEd25519(){
  const kp = await crypto.subtle.generateKey({ name:'Ed25519' }, true, ['sign','verify']);
  const pub = await crypto.subtle.exportKey('raw', kp.publicKey);
  const priv = await crypto.subtle.exportKey('pkcs8', kp.privateKey);
  return {
    algo: 'Ed25519',
    publicKey_b64u: b64uFromBytes(new Uint8Array(pub)),
    privateKey_pkcs8_b64u: b64uFromBytes(new Uint8Array(priv)),
  };
}

async function importEd25519Public(rawB64u){
  const raw = bytesFromB64u(rawB64u);
  return crypto.subtle.importKey('raw', raw, { name:'Ed25519' }, true, ['verify']);
}

async function importEd25519Private(pkcs8B64u){
  const pkcs8 = bytesFromB64u(pkcs8B64u);
  return crypto.subtle.importKey('pkcs8', pkcs8, { name:'Ed25519' }, false, ['sign']);
}

async function signEd25519(privateKey, messageStr){
  const sig = await crypto.subtle.sign({ name:'Ed25519' }, privateKey, new TextEncoder().encode(messageStr));
  return b64uFromBytes(new Uint8Array(sig));
}

async function verifyEd25519(publicKey, messageStr, sigB64u){
  const sig = bytesFromB64u(sigB64u);
  const ok = await crypto.subtle.verify({ name:'Ed25519' }, publicKey, sig, new TextEncoder().encode(messageStr));
  return !!ok;
}

// Exports
window.HBCE_CRYPTO = {
  sha256Hex,
  cryptoSupport,
  ed25519Support,
  generateEd25519,
  importEd25519Public,
  importEd25519Private,
  signEd25519,
  verifyEd25519,
};
