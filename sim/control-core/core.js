const canvas = document.getElementById("sim");
const ctx = canvas.getContext("2d");

let manuel = {x:200,y:250};
let drone = {x:600,y:250};

let logChain = [];
let lastHash = "GENESIS";

canvas.addEventListener("mousemove",e=>{
const rect = canvas.getBoundingClientRect();
manuel.x = (e.clientX-rect.left)*(canvas.width/rect.width);
manuel.y = (e.clientY-rect.top)*(canvas.height/rect.height);
});

function draw(){
ctx.clearRect(0,0,canvas.width,canvas.height);

// line
ctx.beginPath();
ctx.moveTo(manuel.x,manuel.y);
ctx.lineTo(drone.x,drone.y);
ctx.strokeStyle="#444";
ctx.stroke();

// manuel
ctx.beginPath();
ctx.arc(manuel.x,manuel.y,8,0,6.28);
ctx.fillStyle="#00d9ff";
ctx.fill();

// drone
ctx.beginPath();
ctx.arc(drone.x,drone.y,8,0,6.28);
ctx.fillStyle="#ffffff";
ctx.fill();
}

function update(){
const mode=document.getElementById("mode").value;
const speed=document.getElementById("speed").value;

if(mode==="follow"){
let dx=manuel.x-drone.x;
let dy=manuel.y-drone.y;
drone.x+=dx*0.02*speed;
drone.y+=dy*0.02*speed;
}

if(mode==="hover"){
}

if(mode==="explore"){
drone.x+=Math.sin(Date.now()/700)*0.8*speed;
drone.y+=Math.cos(Date.now()/900)*0.8*speed;
}
}

function loop(){
update();
draw();
requestAnimationFrame(loop);
}
loop();

async function hash(str){
const buf=new TextEncoder().encode(str);
const digest=await crypto.subtle.digest("SHA-256",buf);
return Array.from(new Uint8Array(digest)).map(b=>b.toString(16).padStart(2,"0")).join("");
}

async function emitEvent(){
let event={
time:new Date().toISOString(),
mode:document.getElementById("mode").value,
manuel,
drone,
prev:lastHash
};

let h=await hash(JSON.stringify(event));
event.hash=h;
lastHash=h;
logChain.push(event);

document.getElementById("log").textContent=
JSON.stringify(logChain,null,2);
}
