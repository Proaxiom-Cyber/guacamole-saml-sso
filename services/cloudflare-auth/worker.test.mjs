import { test } from 'node:test';
import assert from 'node:assert/strict';
import worker, { Session } from './worker.mjs';

function fixture(){
 const stores=new Map(), objects=new Map(); let next=1;
 const env={CLIENT_ID:'fixture-client',ORIGIN:'https://auth.example.test',SESSION_LIMIT:{limit:async()=>({success:true})}};
 env.SESSIONS={newUniqueId:()=>String(next++).padStart(64,'0'),idFromString:id=>id,get(id){
  if(!objects.has(id)) {
   const data=new Map();stores.set(id,data);
   const ctx={id,blockConcurrencyWhile:fn=>fn(),storage:{get:async k=>data.get(k),put:async(k,v)=>data.set(k,v),setAlarm:async()=>{},deleteAlarm:async()=>{},deleteAll:async()=>data.clear()}};
   objects.set(id,new Session(ctx,env));
  }return objects.get(id);
 }};
 return {env,stores,request:(path,options={})=>worker.fetch(new Request(env.ORIGIN+path,options),env)};
}
const hash=async x=>Buffer.from(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(x))).toString('hex');
async function create(f){
 const key=await crypto.subtle.generateKey({name:'RSA-OAEP',modulusLength:2048,publicExponent:new Uint8Array([1,0,1]),hash:'SHA-256'},true,['encrypt','decrypt']);
 const public_key=await crypto.subtle.exportKey('jwk',key.publicKey);
 const body={public_key,challenge:'a'.repeat(43),poll_hash:await hash('fixture-poll')};
 const r=await f.request('/sessions',{method:'POST',body:JSON.stringify(body)});assert.equal(r.status,201);
 return {key,...await r.json(),headers:{Authorization:'Bearer fixture-poll'}};
}
test('encrypted result survives a lost poll and is deleted on acknowledgement',async()=>{
 const f=fixture(),s=await create(f);
 assert.equal((await f.request('/poll/'+s.id)).status,403);
 assert.equal((await f.request('/poll/'+s.id,{headers:s.headers})).status,202);
 const start=await f.request('/start/'+s.id);const u=new URL(start.headers.get('Location'));
 assert.equal(u.searchParams.get('code_challenge'),'a'.repeat(43));assert.equal(u.searchParams.get('response_mode'),'form_post');
 const options={method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({state:s.id,code:'fixture-code'})};
 assert.equal((await f.request('/callback',options)).status,200);
 assert.equal((await f.request('/callback',options)).status,409);
 const poll=()=>f.request('/poll/'+s.id,{headers:s.headers});
 const encrypted=await (await poll()).json();assert.deepEqual(await(await poll()).json(),encrypted);
 assert.equal(JSON.stringify([...f.stores.get(s.id)]).includes('fixture-code'),false);
 const aes=await crypto.subtle.decrypt({name:'RSA-OAEP'},s.key.privateKey,Buffer.from(encrypted.key,'base64'));
 const aesKey=await crypto.subtle.importKey('raw',aes,'AES-GCM',false,['decrypt']);
 const decoded=await crypto.subtle.decrypt({name:'AES-GCM',iv:Buffer.from(encrypted.iv,'base64')},aesKey,Buffer.from(encrypted.data,'base64'));
 assert.equal(JSON.parse(new TextDecoder().decode(decoded)).code,'fixture-code');
 assert.equal((await f.request('/poll/'+s.id,{method:'DELETE',headers:s.headers})).status,200);
 assert.equal((await poll()).status,410);
});
test('cancel pending, expiry, size limit, rate limit, invalid state',async()=>{
 const f=fixture(),s=await create(f);
 assert.equal((await f.request('/poll/'+s.id,{method:'DELETE',headers:s.headers})).status,200);
 const expired=await create(f);f.stores.get(expired.id).get('session').expires=0;
 assert.equal((await f.request('/poll/'+expired.id,{headers:expired.headers})).status,410);
 assert.equal((await f.request('/sessions',{method:'POST',body:'x'.repeat(16385)})).status,413);
 f.env.SESSION_LIMIT.limit=async()=>({success:false});
 assert.equal((await f.request('/sessions',{method:'POST',body:'{}'})).status,429);
 assert.equal((await f.request('/callback',{method:'POST',body:new URLSearchParams({state:'bad'})})).status,400);
});
