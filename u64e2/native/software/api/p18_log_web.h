#ifndef P18_LOG_WEB_H
#define P18_LOG_WEB_H
/* Static shell only. No live data, configuration or credentials are embedded. */
static const char p18_log_web[]=R"P18HTML(<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>WiC64 log</title>
<style>
:root{color-scheme:dark;font-family:system-ui,sans-serif;background:#101721;color:#edf3fa}body{max-width:1100px;margin:32px auto;padding:0 20px}h1{font-size:1.7rem;margin-bottom:6px}p{color:#afbed1;line-height:1.5}.card{background:#192433;border:1px solid #35465b;border-radius:12px;padding:18px;margin:18px 0}.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}label{display:flex;align-items:center;gap:8px}input,button,select{font:inherit;padding:9px 11px;border:1px solid #526680;border-radius:7px;background:#111c2b;color:inherit}button{cursor:pointer}button:hover{background:#294360}button:disabled{opacity:.5;cursor:default}.primary{background:#245d87}#password{min-width:220px}#command{width:4ch}#status{min-height:1.5em;color:#b8dbff}#summary{font-size:.85rem;color:#afbed1}pre{overflow:auto;min-height:240px;max-height:60vh;background:#0b111a;padding:14px;border-radius:8px;font:12px/1.6 ui-monospace,monospace;white-space:pre}small{color:#afbed1}.log-1{color:#55d6ef}.log-2{color:#8cdd86}.log-3{color:#ff6f7a}.danger{border-color:#bb6976}a{color:#b8dbff}
</style></head><body><h1>WiC64 log</h1><p>Live diagnostics while your C64 keeps running. Classic WiC64 diagnostics, with bounded packet dumps and protected values redacted.</p>
<form id="login" class="card"><div class="row"><label>Ultimate network password <input id="password" type="password" autocomplete="off" spellcheck="false"></label><button class="primary" type="submit">Connect</button></div><p><small>Leave empty if no network password is configured. The password stays in this page's memory and is forgotten on disconnect.</small></p></form>
<div class="card"><div class="row"><button id="pause" type="button" disabled>Pause</button><button id="disconnect" type="button" disabled>Disconnect</button><button id="download" type="button" disabled>Download text</button><label>Level <select id="level"><option value="off">Off</option><option value="error">Errors</option><option value="info" selected>Info</option><option value="debug">Debug</option></select></label><button id="apply" type="button" disabled>Apply settings</button><button id="clear" class="danger" type="button" disabled>Clear log</button></div>
<p><label><input id="previews" type="checkbox"> Capture Hex/ASCII (up to 128 bytes per entry)</label><small>Off by default after loading the CFW. Enable, apply settings, then repeat the request. Earlier entries cannot gain bytes that were not captured. Application data may be private; recognized protected values stay redacted.</small></p>
<p id="capture" role="status">Capture state unavailable while disconnected.</p>
<div class="row" style="margin-top:16px"><label>Command $<input id="command" maxlength="2" placeholder="all" spellcheck="false"></label><label><input id="errors" type="checkbox"> Errors only</label></div><p id="status" role="status">Disconnected.</p><div id="summary">No data loaded.</div><pre id="events" aria-label="Log entries"></pre></div>
<script>
(()=>{'use strict';
const el=id=>document.getElementById(id),levelNames=['off','error','info','debug'];
let password='',connected=false,paused=false,settingsDirty=false,settingsRevision=0,controlJob=null,session=0,generation=0,after=0,entries=[],timer=null,pending=null,controller=null;
const message=text=>{el('status').textContent=text;};
const errorText=error=>error.name==='AbortError'?'Read timed out; retrying.':/^HTTP [0-9]{3}\./.test(error.message)?error.message:'Log request failed. Check the connection or response.';
function buttons(){for(const id of ['pause','disconnect','download','apply','clear'])el(id).disabled=!connected;el('pause').textContent=paused?'Resume':'Pause';el('apply').disabled=!connected||controlJob!==null;el('clear').disabled=!connected||controlJob!==null;}
function stop(text='Disconnected.') {++session;connected=false;paused=false;password='';el('password').value='';clearTimeout(timer);timer=null;if(controller)controller.abort();buttons();el('capture').textContent='Capture state unavailable while disconnected.';message(text);}
function captureState(level,enabled){el('capture').textContent=!enabled?'Hex/ASCII capture is Off. Enable it, apply settings, then repeat the request.':level<2?'Hex/ASCII is enabled, but this level suppresses packet entries. Choose Info or Debug and apply settings.':'Hex/ASCII capture is On (up to 128 bytes per entry). New requests only; recognized protected data stays redacted.';}
function number(value){return Number.isInteger(value)&&value>=0&&value<=2147483647;}
function render(){
 const filter=el('command').value.trim(),valid=!filter||/^[0-9a-f]{1,2}$/i.test(filter),command=filter?parseInt(filter,16):-1;
 const output=el('events');output.textContent='';
 for(const e of entries)if(valid&&(command<0||e.command===command)&&(!el('errors').checked||e.color===3)){
  const row=document.createElement('span');row.className='log-'+e.color;row.textContent=e.lines.join('\n')+'\n';output.appendChild(row);
 }
}
async function api(path,method='GET',text=false){
 if(pending)throw new Error('A request is already running.');
 const current=new AbortController();controller=current;
 const timeout=setTimeout(()=>current.abort(),4000);
 const job=(async()=>{const response=await fetch(path,{method,headers:{'X-Password':password},cache:'no-store',credentials:'omit',redirect:'error',signal:current.signal});
  if(response.status===401||response.status===403){stop('Authentication failed. Connect again.');throw new Error('Authentication failed.');}
  if(!response.ok)throw new Error(`HTTP ${response.status}. Try again.`);
  if(text){const value=await response.text();if(value.length>65536)throw new Error('Log download exceeds the limit.');return value;}
  return await response.json();})();pending=job;
 try{return await job;}finally{clearTimeout(timeout);if(pending===job){pending=null;controller=null;}}
}
function accept(data){const s=data&&data.wic64_log;
 if(!s||s.contract!=='U64-WIC64-LOG-2'||s.schema!==2||!number(s.generation)||!s.generation||!number(s.next_after)||!Array.isArray(s.entries)||!Number.isInteger(s.page_size)||s.page_size<1||s.page_size>32||s.entries.length>s.page_size||!Number.isInteger(s.capacity)||s.capacity<s.page_size||s.capacity>128||!number(s.dropped)||!number(s.overwritten)||!Number.isInteger(s.level)||s.level<0||s.level>3||typeof s.available!=='boolean'||typeof s.previews_enabled!=='boolean'||typeof s.reset!=='boolean'||typeof s.more!=='boolean'||s.line_capacity!==256||s.max_record_lines!==12)throw new Error('Invalid log response.');
 let previous=0;
 for(const e of s.entries){
  for(const key of ['seq','tick_ms','request_id','length','elapsed_ms','tls_tx','tls_rx','http_status','command','protocol','event','phase','lifecycle','status','error','level'])if(!number(e[key]))throw new Error('Invalid log entry.');
  if(!e.seq||e.seq<=previous||e.seq>s.next_after||!Number.isInteger(e.engine_error)||e.engine_error<-2147483648||e.engine_error>2147483647||!Number.isInteger(e.color)||e.color<0||e.color>3||!Array.isArray(e.lines)||!e.lines.length||e.lines.length>s.max_record_lines||e.lines.some(line=>typeof line!=='string'||!line.length||line.length>=s.line_capacity||!/^[\x20-\x7e]+$/.test(line)))throw new Error('Invalid formatted log entry.');
  previous=e.seq;
 }
 if(s.reset||generation!==s.generation)entries=[];generation=s.generation;
 for(const e of s.entries)if(!entries.length||e.seq>entries[entries.length-1].seq)entries.push(e);
 entries=entries.slice(-s.capacity);after=s.next_after;if(!settingsDirty){el('level').value=levelNames[s.level];el('previews').checked=s.previews_enabled;}
 captureState(s.level,s.previews_enabled);
 el('summary').textContent=`Generation ${generation} · latest ${entries.length}/${s.capacity} records · overwritten ${s.overwritten} · dropped ${s.dropped}${s.reset?' · cursor restarted':''}${s.available?'':' · logging unavailable'}`;render();
}
async function poll(){if(!connected||paused)return;const mine=session;
 try{if(!pending&&!controlJob){const data=await api(`/v1/machine:wic64_log?generation=${generation}&after=${after}`);if(mine!==session||paused)return;accept(data);message(paused?'Paused. The C64 and RAM log keep running.':'Live · refresh every 750 ms.');}}
 catch(error){if(mine===session&&connected){generation=after=0;message(errorText(error));}}
 finally{if(mine===session&&connected&&!paused){clearTimeout(timer);timer=setTimeout(poll,750);}}
}
el('login').addEventListener('submit',async event=>{event.preventDefault();const next=el('password').value;el('password').value='';stop();if(pending){try{await pending;}catch(_){}}
 password=next;connected=true;paused=false;settingsDirty=false;generation=after=0;entries=[];buttons();render();message('Connecting...');poll();});
el('disconnect').addEventListener('click',()=>stop());
el('pause').addEventListener('click',()=>{paused=!paused;clearTimeout(timer);buttons();if(paused)message('Paused. The C64 and RAM log keep running.');else poll();});
async function control(query){
 if(!connected||controlJob)return;
 const mine=session,revision=settingsRevision,owner={};controlJob=owner;buttons();
 try{
  // One explicit control may wait behind the bounded read. Never silently
  // discard Apply just because the live poll owns the only fetch slot.
  if(pending){message('Waiting for the current log read before applying settings...');try{await pending;}catch(_){}}
  if(mine!==session||!connected)return;
  const data=await api('/v1/machine:wic64_log_control?'+query,'PUT');if(mine!==session)return;
  const state=data&&data.wic64_log;
  if(query.startsWith('level=')){
   if(settingsRevision===revision){settingsDirty=false;if(state&&Number.isInteger(state.level)&&state.level>=0&&state.level<4)el('level').value=levelNames[state.level];if(state&&typeof state.previews_enabled==='boolean')el('previews').checked=state.previews_enabled;}
   if(state&&Number.isInteger(state.level)&&state.level>=0&&state.level<4&&typeof state.previews_enabled==='boolean')captureState(state.level,state.previews_enabled);
  }
  if(query==='clear=1'){generation=after=0;entries=[];render();}
  message(query==='clear=1'?'Log cleared. Capture settings unchanged.':settingsDirty?'Earlier settings applied. Your newer changes still need Apply settings.':'Log control applied. Repeat the request to capture new data.');
 }catch(error){if(mine===session&&connected)message(errorText(error));}
 finally{if(controlJob===owner)controlJob=null;buttons();}
}
el('clear').addEventListener('click',()=>{if(connected&&confirm('Clear the retained WiC64 RAM log?'))control('clear=1');});
el('apply').addEventListener('click',()=>{const value=el('level').value;if(levelNames.includes(value))control('level='+value+'&previews='+(el('previews').checked?'1':'0'));});
el('download').addEventListener('click',async()=>{if(!connected||pending)return;const mine=session;try{const text=await api('/v1/machine:wic64_log_text','GET',true);if(mine!==session)return;const url=URL.createObjectURL(new Blob([text],{type:'text/plain;charset=utf-8'}));const link=document.createElement('a');link.href=url;link.download='wic64-log.txt';link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);message('Text log downloaded.');}catch(error){if(mine===session&&connected)message(errorText(error));}});
function settingsChanged(){settingsDirty=true;++settingsRevision;message('Settings changed. Click Apply settings.');}
el('level').addEventListener('change',settingsChanged);el('previews').addEventListener('change',settingsChanged);
el('command').addEventListener('input',render);el('errors').addEventListener('change',render);
window.addEventListener('pagehide',()=>stop());buttons();
})();
</script></body></html>)P18HTML";
#endif
