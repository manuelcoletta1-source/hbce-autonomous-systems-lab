<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>HBCE • Evidence Verifier</title>
<meta name="theme-color" content="#0b0f14">

<style>
body{background:#0b0f14;color:#e6edf3;font-family:system-ui;margin:0;padding:20px}
.wrap{max-width:1100px;margin:auto}
.box{border:1px solid #2b3137;border-radius:12px;padding:14px;margin-bottom:14px;background:#11161c}
textarea{width:100%;min-height:220px;background:#0d1117;color:#e6edf3;border:1px solid #30363d;border-radius:8px;padding:10px;font-family:monospace}
button{padding:10px 14px;border-radius:8px;border:1px solid #444;background:#161b22;color:white;cursor:pointer}
button:hover{background:#1f2630}
pre{background:#0d1117;padding:12px;border-radius:8px;overflow:auto}
.ok{color:#3fb950}
.bad{color:#ff6b6b}
</style>
</head>

<body>
<div class="wrap">

<h2>HBCE • Autonomous Systems Lab</h2>
<h3>Evidence Pack Verifier</h3>
<p>Hash integrity • ledger chain • deterministic replay</p>

<div class="box">
<textarea id="input" placeholder="Paste HBCE Evidence Pack JSON"></textarea>
</div>

<div class="box">
<button onclick="verify()">Verify</button>
<button onclick="clearAll()">Clear</button>
</div>

<div class="box">
<h3>Result</h3>
<div>Status: <span id="status">—</span></div>
<div>Pack Hash: <span id="ph">—</span></div>
<div>Recomputed: <span id="rc">—</span></div>
<div>Ledger: <span id="lg">—</span></div>
<div>Entries: <span id="en">—</span></div>
</div>

<div class="box">
<h3>Diagnostics</h3>
<pre id="diag"></pre>
</div>

</div>

<script>
function stable(obj){
 if(obj===null||typeof obj!=="object") return JSON.stringify(obj);
 if(Array.isArray(obj)) return "["+obj.map(stable).join(",")+"]";
 return "{"+Object.keys(obj).sort()
   .map(k=>JSON.stringify(k)+":"+stable(obj[k]))
   .join(",")+"}";
}

function hex(buf){
 return [...new Uint8Array(buf)].map(b=>b.toString(16).padStart(2,"0")).join("");
}

async function sha256(str){
 const data=new TextEncoder().encode(str);
 const digest=await crypto.subtle.digest("SHA-256",data);
 return hex(digest);
}

function set(id,v){document.getElementById(id).textContent=v;}
function diag(o){document.getElementById("diag").textContent=JSON.stringify(o,null,2);}

async function verifyLedger(ledger){
 if(!ledger||!Array.isArray(ledger.entries)) return {ok:false,reason:"NO_LEDGER"};
 let prev="GENESIS";
 for(let i=0;i<ledger.entries.length;i++){
   const e=ledger.entries[i];
   const {hash,...payload}=e;
   if(payload.prev_hash!==prev) return {ok:false,reason:"CHAIN_BREAK_"+i};
   const h=await sha256(JSON.stringify(payload));
   if(h!==hash) return {ok:false,reason:"HASH_FAIL_"+i};
   prev=hash;
 }
 return {ok:true,entries:ledger.entries.length};
}

async function verify(){
 try{
  const raw=document.getElementById("input").value.trim();
  const pack=JSON.parse(raw);

  if(pack.proto!=="HBCE-EVIDENCE-PACK-v1"){
    set("status","INVALID");
    return diag({error:"Not HBCE pack"});
  }

  const original=pack.pack_hash;

  const clone=JSON.parse(JSON.stringify(pack));
  delete clone.pack_hash;
  delete clone.signature;

  const recomputed=await sha256(stable(clone));

  const ledger=await verifyLedger(pack.ledger);

  const ok=(original===recomputed)&&ledger.ok;

  set("status", ok?"VALID":"INVALID");
  set("ph",original||"—");
  set("rc",recomputed||"—");
  set("lg",ledger.ok?"OK":"BROKEN");
  set("en",ledger.entries||"—");

  diag({
    pack_hash_match: original===recomputed,
    ledger_ok: ledger.ok,
    canonical:"stable()",
    hash:"SHA-256",
    note:"Bridge and Verifier now use identical canonical hashing"
  });

 }catch(e){
  set("status","INVALID JSON");
  diag({error:String(e)});
 }
}

function clearAll(){
 document.getElementById("input").value="";
 diag({cleared:true});
}
</script>
</body>
</html>
