// =============================================================================
// net/web_page.h — the management page served at http://<device>/ (net/web.cpp)
// Self-contained: no external scripts, fonts or images.
// =============================================================================
#pragma once

static const char WEB_PAGE[] PROGMEM = R"HTML(<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AuthKey</title>
<style>
:root{--bg:#f4f5f7;--card:#fff;--fg:#1b1d21;--muted:#646a73;--line:#e2e5ea;--acc:#2f6fed;--ok:#1a7f45;--bad:#c0392b;--warn:#b26a00}
@media (prefers-color-scheme:dark){:root{--bg:#111316;--card:#1b1e23;--fg:#e8eaed;--muted:#9aa1ab;--line:#2c3138;--acc:#6d9bff;--ok:#3ccf7a;--bad:#ff6b5e;--warn:#f0b04a}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.45 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
main{max-width:760px;margin:0 auto;padding:16px}
h1{font-size:20px;margin:4px 0 12px;display:flex;align-items:center;gap:8px}h1 small{font-weight:400;color:var(--muted);font-size:13px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px 16px;margin:0 0 12px}
.card h2{font-size:15px;margin:0 0 10px;display:flex;justify-content:space-between;align-items:center}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:8px 16px}
.k{color:var(--muted);font-size:12px}.v{font-weight:600;overflow-wrap:anywhere}
.ok{color:var(--ok)}.bad{color:var(--bad)}.warn{color:var(--warn)}.muted{color:var(--muted)}
button{font:inherit;border:1px solid var(--line);background:var(--card);color:var(--fg);border-radius:8px;padding:7px 12px;cursor:pointer}
button.primary{background:var(--acc);border-color:var(--acc);color:#fff}button.danger{color:var(--bad)}
button:disabled{opacity:.5;cursor:default}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
ul{list-style:none;margin:0;padding:0}li{display:flex;justify-content:space-between;align-items:center;gap:8px;padding:7px 0;border-top:1px solid var(--line)}
li:first-child{border-top:0}li .name{overflow-wrap:anywhere}
input,textarea{font:inherit;width:100%;padding:8px;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--fg)}
textarea{min-height:70px;font-family:ui-monospace,Consolas,monospace;font-size:12px}
pre{margin:0;font:12px/1.5 ui-monospace,Consolas,monospace;white-space:pre-wrap;max-height:320px;overflow:auto}
.hidden{display:none}#msg{position:fixed;left:50%;bottom:16px;transform:translateX(-50%);background:var(--fg);color:var(--bg);padding:8px 14px;border-radius:8px;opacity:0;transition:opacity .2s}
#msg.show{opacity:.95}details summary{cursor:pointer;color:var(--muted);font-size:13px}
</style></head><body><main>
<h1>AuthKey <small id="fw"></small></h1>

<div class="card"><h2>Device <span class="muted" id="clock"></span></h2>
<div class="grid">
<div><div class="k">WiFi</div><div class="v" id="wifi">-</div></div>
<div><div class="k">Bluetooth</div><div class="v" id="bt">-</div></div>
<div><div class="k">Passkeys</div><div class="v" id="pk">-</div></div>
<div><div class="k">TOTP accounts</div><div class="v" id="tc">-</div></div>
<div><div class="k">Up</div><div class="v" id="up">-</div></div>
</div></div>

<div class="card" id="campusCard"><h2>Campus internet (IITG) <span id="cmode" class="muted"></span></h2>
<div class="grid">
<div><div class="k">State</div><div class="v" id="cstate">-</div></div>
<div><div class="k">Last result</div><div class="v" id="clast">-</div></div>
<div><div class="k">Next</div><div class="v" id="cnext">-</div></div>
<div><div class="k">This boot</div><div class="v" id="ccount">-</div></div>
</div>
<div class="row auth hidden" style="margin-top:10px">
<button class="primary" onclick="portal('login')">Log in now</button>
<button onclick="portal('logout')">Log out</button>
<button id="cauto" onclick="portal(S.campus.auto?'off':'on')">Auto-login</button>
</div></div>

<div class="card" id="lockCard"><h2>Manage</h2>
<p class="muted" style="margin:0 0 10px">Event log, campus controls, passkeys, authenticator codes and phone sign-in need you to allow this browser on the device.</p>
<div class="row"><button class="primary" id="unlockBtn" onclick="unlock()">Allow this browser</button><span id="unlockMsg" class="muted"></span></div></div>

<div class="auth hidden">
<div class="card"><h2>Event log <button onclick="loadLog()">Refresh</button></h2><pre id="log"></pre></div>

<div class="card"><h2>Passkeys <span class="muted" id="pkcap"></span></h2><ul id="pklist"></ul></div>

<div class="card"><h2>Authenticator (TOTP)</h2><ul id="totplist"></ul>
<details style="margin-top:8px"><summary>Add from an otpauth:// link</summary>
<div class="row" style="margin-top:8px"><input id="otp" placeholder="otpauth://totp/Site:me?secret=...&amp;issuer=Site" autocomplete="off"><button onclick="addTotp()">Add</button></div></details></div>

<div class="card"><h2>Phone sign-in (QR)</h2>
<p class="muted" style="margin:0 0 8px">For a phone or PC showing a passkey QR code ("use another device"). Paste the QR's text (it starts with <b>FIDO:/</b>); the AuthKey then signs in like a phone would. On Android: screenshot the QR, open it in Google Lens, copy the text. Experimental: Android may close its QR dialog when you switch apps.</p>
<textarea id="qr" placeholder="FIDO:/1234..."></textarea>
<div class="row" style="margin-top:8px"><button class="primary" onclick="sendQr()">Send to the AuthKey</button><button onclick="stopQr()">Stop</button><span id="hy" class="muted"></span></div></div>

<div class="row" style="justify-content:flex-end"><button onclick="lock()">Lock this browser</button></div>
</div>
</main><div id="msg"></div>
<script>
const $=id=>document.getElementById(id);let S=null,authed=false;
function msg(t){const m=$('msg');m.textContent=t;m.classList.add('show');clearTimeout(m._t);m._t=setTimeout(()=>m.classList.remove('show'),2500)}
async function api(p,o={}){const r=await fetch(p,Object.assign({credentials:'same-origin'},o,{headers:Object.assign({'X-AuthKey':'1'},o.headers||{})}));
let j={};try{j=await r.json()}catch(e){}if(!r.ok)throw new Error(j.error||('HTTP '+r.status));return j}
const post=(p,body)=>api(p,{method:'POST',body:body||''});
function esc(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
function dur(s){s=Math.max(0,s|0);const h=s/3600|0,m=(s%3600)/60|0;return h?h+'h '+m+'m':m?m+'m '+(s%60)+'s':s+'s'}
async function status(){try{S=await api('/api/status')}catch(e){return}
$('fw').textContent='v'+S.fw;$('clock').textContent=S.clock;
$('wifi').textContent=S.wifi.ssid?S.wifi.ssid+' ('+S.wifi.rssi+' dBm)':'not connected';
$('bt').textContent=S.bt.links+' link(s), '+S.bt.bonds+' paired'+(S.bt.keyboard?', keyboard: '+S.bt.keyboardHosts+' host(s)':'');
$('pk').textContent=S.passkeys+' / '+S.passkeyCapacity;$('tc').textContent=S.totp;$('up').textContent=dur(S.uptime);
const c=S.campus;$('campusCard').classList.toggle('hidden',!c.have);
const st=$('cstate');st.textContent=c.state+(c.user?' ('+c.user+')':'');st.className='v '+(c.online?'ok':c.paused?'warn':'bad');
$('cmode').textContent=c.auto?(c.paused?'paused':'auto-login on'):'manual';
$('clast').textContent=c.last||'-';$('cnext').textContent=(c.online&&c.owns?'refresh in ':'check in ')+dur(c.next);
$('ccount').textContent=c.logins+' login(s), '+c.refreshes+' refresh(es)';$('cauto').textContent='Auto-login: '+(c.auto?'ON':'off');
$('hy').textContent=S.hybrid;
if(S.auth!==authed){authed=S.auth;document.querySelectorAll('.auth').forEach(e=>e.classList.toggle('hidden',!authed));$('lockCard').classList.toggle('hidden',authed);if(authed)loadAll()}}
async function unlock(){$('unlockBtn').disabled=true;$('unlockMsg').textContent='Press OK on the AuthKey...';
try{const r=await post('/api/session');for(let i=0;i<40;i++){await new Promise(z=>setTimeout(z,1000));const p=await api('/api/session?id='+r.id);
if(p.state==='allowed'){$('unlockMsg').textContent='';await status();break}
if(p.state!=='waiting'){$('unlockMsg').textContent=p.state==='denied'?'Denied on the device.':'Timed out.';break}}}
catch(e){$('unlockMsg').textContent=e.message}$('unlockBtn').disabled=false}
async function lock(){await post('/api/logout');authed=false;S=null;location.reload()}
async function loadLog(){const j=await api('/api/log');$('log').textContent=j.lines.slice().reverse().join('\n')||'(empty)'}
async function loadPk(){const j=await api('/api/passkeys');j.passkeys.sort((a,b)=>b.order-a.order);
$('pklist').innerHTML=j.passkeys.map(p=>'<li><span class="name"><b>'+esc(p.rp)+'</b><br><span class="muted">'+esc(p.user||p.display||'(no name)')+'</span></span><button class="danger" onclick="delPk('+p.slot+',\''+esc(p.rp).replace(/'/g,'')+'\')">Delete</button></li>').join('')||'<li class="muted">No passkeys stored on the device.</li>'}
async function loadTotp(){const j=await api('/api/totp');
$('totplist').innerHTML=j.accounts.map(a=>'<li><span class="name">'+esc(a.name)+' <span class="muted">'+a.digits+' digits, '+a.period+'s, '+(a.algo==1?'SHA1':'SHA'+a.algo)+'</span></span><button class="danger" onclick="delTotp('+a.i+')">Delete</button></li>').join('')||'<li class="muted">No accounts.</li>'}
function loadAll(){loadLog().catch(()=>{});loadPk().catch(()=>{});loadTotp().catch(()=>{})}
async function portal(d){try{await post('/api/portal?do='+d);msg({login:'Logging in...',logout:'Logged out; auto-login paused',on:'Auto-login on',off:'Auto-login off'}[d]);setTimeout(()=>{status();loadLog()},1500)}catch(e){msg(e.message)}}
async function delPk(slot,rp){if(!confirm('Delete the passkey for '+rp+'? You will not be able to sign in to it with this key any more.'))return;
try{await post('/api/passkeys/delete?slot='+slot);msg('Deleted');loadPk();status()}catch(e){msg(e.message)}}
async function delTotp(i){if(!confirm('Delete this authenticator account from the device?'))return;try{await post('/api/totp/delete?i='+i);msg('Deleted');loadTotp();status()}catch(e){msg(e.message)}}
async function addTotp(){const v=$('otp').value.trim();if(!v)return;try{await post('/api/totp/add',v);$('otp').value='';msg('Added');loadTotp();status()}catch(e){msg(e.message)}}
async function sendQr(){const v=$('qr').value.trim();if(!v)return;try{await post('/api/hybrid',v);msg('Sent; watch the AuthKey screen');$('qr').value=''}catch(e){msg(e.message)}}
async function stopQr(){try{await post('/api/hybrid','stop')}catch(e){}}
status();setInterval(status,3000);setInterval(()=>{if(authed)loadLog().catch(()=>{})},15000);
</script></body></html>)HTML";
