const ROUTE_TTL_SECONDS = 3600;
const MAX_BODY = 16384;
const PREFIX = "/p/";
const HOP = ["connection","keep-alive","proxy-authenticate","proxy-authorization","te","trailer","transfer-encoding","upgrade"];

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (!allowedOrigin(request.headers.get("Origin"), env.ALLOWED_ORIGIN)) return respond({ok:false,error:"origin_not_allowed"},403,request,env);
    if (request.method === "OPTIONS") return new Response(null,{status:204,headers:cors(request,env)});
    if (url.pathname === "/health" && request.method === "GET") return respond({ok:true,service:"apiyer-proxy",kv:!!env.ROUTES,keyConfigured:!!env.PROXY_API_KEY},200,request,env);
    if (url.pathname === "/" && request.method === "GET") return respond({ok:true,register:"POST /api/register",proxy:"/p/:backend/*"},200,request,env);
    if (url.pathname === "/api/register" && request.method === "POST") return register(request,env);
    if (url.pathname === "/api/unregister" && request.method === "POST") return unregister(request,env);
    if (url.pathname === "/api/routes" && request.method === "GET") {
      if (!authorized(request,env,"")) return respond({ok:false,error:"unauthorized"},401,request,env);
      if (!env.ROUTES) return respond({ok:false,error:"kv_binding_missing"},503,request,env);
      const list = await env.ROUTES.list({prefix:"route:",limit:1000});
      return respond({ok:true,routes:list.keys.map(k=>({backend:k.name.slice(6),metadata:k.metadata||{}})),listComplete:!!list.list_complete},200,request,env);
    }
    if (url.pathname.startsWith(PREFIX)) return proxy(request,env,url);
    return respond({ok:false,error:"not_found"},404,request,env);
  }
};

function respond(data,status,request,env) {
  const headers = new Headers({"content-type":"application/json; charset=utf-8","cache-control":"no-store","x-content-type-options":"nosniff"});
  addCors(headers,request,env);
  return new Response(JSON.stringify(data),{status,headers});
}
function cors(request,env) { const h=new Headers(); addCors(h,request,env); return h; }
function allowedOrigin(origin,configured) { return !origin || !configured || configured.trim()==="*" || configured.split(",").map(x=>x.trim()).includes(origin); }
function addCors(headers,request,env) {
  const configured=(env.ALLOWED_ORIGIN||"*").trim(), origin=request.headers.get("Origin");
  if(configured==="*") headers.set("access-control-allow-origin","*");
  else if(origin && configured.split(",").map(x=>x.trim()).includes(origin)){headers.set("access-control-allow-origin",origin);headers.append("vary","Origin");}
  headers.set("access-control-allow-methods","GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS");
  headers.set("access-control-allow-headers","Content-Type, Authorization, X-API-Key, X-Proxy-Client-Key, X-Request-Id");
  headers.set("access-control-expose-headers","X-Proxy-Backend, X-Request-Id");
  headers.set("access-control-max-age","86400");
}

async function register(request,env) {
  if (!env.ROUTES) return respond({ok:false,error:"kv_binding_missing"},503,request,env);
  if (!env.PROXY_API_KEY) return respond({ok:false,error:"registration_key_not_configured"},503,request,env);
  let body;
  try { body=await readJson(request,MAX_BODY); }
  catch(e) { return respond({ok:false,error:e.code||"invalid_json"},e.status||400,request,env); }
  if (!authorized(request,env,body.nama)) return respond({ok:false,error:"unauthorized"},401,request,env);
  const raw=body.url!==undefined?body.url:(body.Url!==undefined?body.Url:body.endpoint);
  if(typeof raw!=="string") return respond({ok:false,error:"missing_upstream_url"},400,request,env);
  let upstream;
  try { upstream=validateUpstream(raw); } catch(e) { return respond({ok:false,error:e.message},400,request,env); }
  let name=body.backend!==undefined?body.backend:(body.route!==undefined?body.route:body.name);
  if(name===undefined||name===null||name==="") name=upstream.hostname.slice(0,-".trycloudflare.com".length);
  if(typeof name!=="string") return respond({ok:false,error:"invalid_backend_name"},400,request,env);
  name=name.toLowerCase();
  if(!/^[a-z0-9][a-z0-9_-]{0,39}$/.test(name)) return respond({ok:false,error:"invalid_backend_name"},400,request,env);
  let payload=null;
  if(Object.prototype.hasOwnProperty.call(body,"payload")) {
    let json;
    try { json=JSON.stringify(body.payload); } catch { return respond({ok:false,error:"invalid_default_payload"},400,request,env); }
    if(new TextEncoder().encode(json).byteLength>8192) return respond({ok:false,error:"default_payload_too_large"},413,request,env);
    payload=body.payload;
  }
  let clientKeyHash=null;
  if(body.clientKey!==undefined&&body.clientKey!==null&&body.clientKey!=="") {
    if(typeof body.clientKey!=="string"||body.clientKey.length<16||body.clientKey.length>512) return respond({ok:false,error:"client_key_must_be_16_to_512_characters"},400,request,env);
    clientKeyHash=await hash(body.clientKey);
  }
  const key="route:"+name, old=await env.ROUTES.get(key,"json"), now=new Date().toISOString();
  const record={version:1,name,baseUrl:upstream.toString().replace(/\/+$/,""),createdAt:old&&old.createdAt?old.createdAt:now,updatedAt:now,defaultPayload:payload,clientKeyHash};
  await env.ROUTES.put(key,JSON.stringify(record),{expirationTtl:ROUTE_TTL_SECONDS,metadata:{updatedAt:now,hasClientKey:!!clientKeyHash}});
  return respond({ok:true,message:"route_registered",backend:name,endpoint:new URL(request.url).origin+PREFIX+name+"/",expiresInSeconds:ROUTE_TTL_SECONDS,clientKeyRequired:!!clientKeyHash},201,request,env);
}

async function unregister(request,env) {
  if(!env.ROUTES) return respond({ok:false,error:"kv_binding_missing"},503,request,env);
  let body;
  try { body=await readJson(request,MAX_BODY); } catch(e) { return respond({ok:false,error:e.code||"invalid_json"},e.status||400,request,env); }
  if(!authorized(request,env,body.nama)) return respond({ok:false,error:"unauthorized"},401,request,env);
  const name=body.backend!==undefined?body.backend:(body.route!==undefined?body.route:body.name);
  if(typeof name!=="string"||!/^[a-zA-Z0-9][a-zA-Z0-9_-]{0,39}$/.test(name)) return respond({ok:false,error:"invalid_backend_name"},400,request,env);
  await env.ROUTES.delete("route:"+name.toLowerCase());
  return respond({ok:true,message:"route_unregistered",backend:name.toLowerCase()},200,request,env);
}

function authorized(request,env,bodyKey) {
  if(!env.PROXY_API_KEY) return false;
  const auth=request.headers.get("Authorization")||"";
  const bearer=auth.startsWith("Bearer ")?auth.slice(7):"";
  return same(request.headers.get("X-API-Key")||"",env.PROXY_API_KEY)||
    same(bearer,env.PROXY_API_KEY)||same(typeof bodyKey==="string"?bodyKey:"",env.PROXY_API_KEY);
}
function same(a,b) {
  if(typeof a!=="string"||typeof b!=="string") return false;
  let diff=a.length^b.length;
  for(let i=0,n=Math.max(a.length,b.length);i<n;i++) diff|=(a.charCodeAt(i)||0)^(b.charCodeAt(i)||0);
  return diff===0;
}
async function hash(value) {
  const data=await crypto.subtle.digest("SHA-256",new TextEncoder().encode(value));
  return Array.from(new Uint8Array(data),b=>b.toString(16).padStart(2,"0")).join("");
}
async function readJson(request,maxBytes) {
  if(Number(request.headers.get("content-length")||0)>maxBytes) throw httpError("request_body_too_large",413);
  if(!request.body) throw httpError("missing_json_body",400);
  const reader=request.body.getReader(), chunks=[];
  let total=0;
  try {
    while(true) {
      const item=await reader.read(); if(item.done) break;
      total+=item.value.byteLength;
      if(total>maxBytes) { await reader.cancel(); throw httpError("request_body_too_large",413); }
      chunks.push(item.value);
    }
  } finally { reader.releaseLock(); }
  const bytes=new Uint8Array(total); let offset=0;
  for(const chunk of chunks) { bytes.set(chunk,offset); offset+=chunk.byteLength; }
  let value;
  try { value=JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(bytes)); }
  catch { throw httpError("invalid_json",400); }
  if(!value||typeof value!=="object"||Array.isArray(value)) throw httpError("json_object_required",400);
  return value;
}
function httpError(code,status) { const e=new Error(code); e.code=code; e.status=status; return e; }
function validateUpstream(value) {
  let u;
  try { u=new URL(value); } catch { throw new Error("invalid_upstream_url"); }
  if(u.protocol!=="https:"||!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.trycloudflare\.com$/i.test(u.hostname)) throw new Error("upstream_must_be_https_trycloudflare_com");
  if(u.port&&u.port!=="443") throw new Error("upstream_port_not_allowed");
  if(u.username||u.password||u.search||u.hash) throw new Error("upstream_must_not_include_credentials_query_or_fragment");
  u.hostname=u.hostname.toLowerCase(); u.port="";
  return u;
}

async function proxy(request,env,url) {
  if(!env.ROUTES) return respond({ok:false,error:"kv_binding_missing"},503,request,env);
  if(request.method==="CONNECT"||request.method==="TRACE") return respond({ok:false,error:"method_not_allowed"},405,request,env);
  const parts=url.pathname.split("/");
  if(!parts[2]) return respond({ok:false,error:"missing_backend_name"},400,request,env);
  let name;
  try { name=decodeURIComponent(parts[2]).toLowerCase(); } catch { return respond({ok:false,error:"invalid_backend_name"},400,request,env); }
  if(!/^[a-z0-9][a-z0-9_-]{0,39}$/.test(name)) return respond({ok:false,error:"invalid_backend_name"},400,request,env);
  const route=await env.ROUTES.get("route:"+name,"json");
  if(!route||typeof route.baseUrl!=="string") return respond({ok:false,error:"backend_not_registered",backend:name},404,request,env);
  if(route.clientKeyHash) {
    const key=request.headers.get("X-Proxy-Client-Key")||"";
    if(!key||!same(await hash(key),route.clientKeyHash)) return respond({ok:false,error:"proxy_client_unauthorized"},401,request,env);
  }
  let base;
  try { base=validateUpstream(route.baseUrl); } catch { return respond({ok:false,error:"stored_upstream_invalid"},502,request,env); }

  const prefix=PREFIX+name;
  let suffix=url.pathname.slice(prefix.length);
  if(!suffix) suffix="/";
  if(!suffix.startsWith("/")) suffix="/"+suffix;
  const target=new URL(base.toString());
  const basePath=target.pathname.replace(/\/+$/,"");
  target.pathname=(basePath+suffix)||"/";
  target.search=url.search;

  const headers=new Headers(request.headers);
  for(const h of HOP) headers.delete(h);
  headers.delete("host"); headers.delete("content-length");
  headers.delete("x-api-key"); headers.delete("x-proxy-client-key");
  headers.set("x-forwarded-host",url.host);
  headers.set("x-forwarded-proto",url.protocol.slice(0,-1));
  headers.set("x-proxy-backend",name);

  let body=request.body;
  const usesDefault=["POST","PUT","PATCH"].includes(request.method)&&body===null&&route.defaultPayload!==null&&route.defaultPayload!==undefined;
  if(usesDefault) {
    body=JSON.stringify(route.defaultPayload);
    if(!headers.has("content-type")) headers.set("content-type","application/json; charset=utf-8");
  }
  const init={method:request.method,headers,redirect:"manual"};
  if(request.method!=="GET"&&request.method!=="HEAD"&&body!==null) init.body=body;

  let upstream;
  try { upstream=await fetch(new Request(target.toString(),init)); }
  catch {
    return respond({ok:false,error:"upstream_unreachable",backend:name,hint:"Check the tunnel and register its latest URL again."},502,request,env);
  }

  const outHeaders=new Headers(upstream.headers);
  for(const h of HOP) outHeaders.delete(h);
  outHeaders.delete("content-length");
  outHeaders.set("cache-control","no-store");
  outHeaders.set("x-proxy-backend",name);
  const location=outHeaders.get("location");
  if(location&&upstream.status>=300&&upstream.status<400) {
    try {
      const dest=new URL(location,target);
      if(dest.origin===base.origin) {
        let path=dest.pathname;
        if(basePath&&(path===basePath||path.startsWith(basePath+"/"))) path=path.slice(basePath.length)||"/";
        outHeaders.set("location",url.origin+PREFIX+name+path+dest.search+dest.hash);
      }
    } catch { /* Keep invalid Location as returned by upstream. */ }
  }
  addCors(outHeaders,request,env);
  return new Response(upstream.body,{status:upstream.status,statusText:upstream.statusText,headers:outHeaders});
}
