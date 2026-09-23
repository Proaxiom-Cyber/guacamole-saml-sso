// Live transport check using synthetic data only. No Cloudflare grant is requested.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
const {origin}=JSON.parse(await readFile(new URL('./deployment.json',import.meta.url),'utf8'));
const key=await crypto.subtle.generateKey({name:'RSA-OAEP',modulusLength:2048,publicExponent:new Uint8Array([1,0,1]),hash:'SHA-256'},true,['encrypt','decrypt']);
const poll=crypto.randomUUID();
const public_key=await crypto.subtle.exportKey('jwk',key.publicKey);
const poll_hash=Buffer.from(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(poll))).toString('hex');
const request=(path,options={})=>fetch(origin+path,{...options,redirect:'manual',signal:AbortSignal.timeout(15000)});
const created=await request('/sessions',{method:'POST',body:JSON.stringify({challenge:'a'.repeat(43),poll_hash,public_key})});
assert.equal(created.status,201);
const {id}=await created.json(),headers={Authorization:'Bearer '+poll};
try {
 assert.equal((await request('/poll/'+id)).status,403);
 assert.equal((await request('/poll/'+id,{headers})).status,202);
 assert.equal((await request('/callback',{method:'POST',body:new URLSearchParams({state:id,code:'synthetic-transport-fixture'})})).status,200);
 const a=await(await request('/poll/'+id,{headers})).json();
 const b=await(await request('/poll/'+id,{headers})).json();assert.deepEqual(a,b);
 const raw=await crypto.subtle.decrypt('RSA-OAEP',key.privateKey,Buffer.from(a.key,'base64'));
 const aes=await crypto.subtle.importKey('raw',raw,'AES-GCM',false,['decrypt']);
 const value=await crypto.subtle.decrypt({name:'AES-GCM',iv:Buffer.from(a.iv,'base64')},aes,Buffer.from(a.data,'base64'));
 assert.equal(JSON.parse(new TextDecoder().decode(value)).code,'synthetic-transport-fixture');
 console.log('PASS: live free-tier isolation, encryption, and repeat delivery');
} finally {
 assert.equal((await request('/poll/'+id,{method:'DELETE',headers})).status,200);
 assert.equal((await request('/poll/'+id,{headers})).status,410);
 console.log('PASS: session deleted');
}
