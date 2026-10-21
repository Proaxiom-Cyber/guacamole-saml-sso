// Temporary experiment. No credentials, request logs, or plaintext codes in storage.
const enc = new TextEncoder();
const headers = {"Cache-Control":"no-store", "Referrer-Policy":"no-referrer", "X-Content-Type-Options":"nosniff", "Content-Security-Policy":"default-src 'none'; frame-ancestors 'none'"};
const reply = (body, status=200) => new Response(JSON.stringify(body), {status, headers:{...headers,"Content-Type":"application/json"}});
const b64 = bytes => btoa(String.fromCharCode(...new Uint8Array(bytes)));
async function digest(value) { return [...new Uint8Array(await crypto.subtle.digest("SHA-256",enc.encode(value)))].map(x=>x.toString(16).padStart(2,"0")).join(""); }
async function seal(publicKey, value) {
  const rsa = await crypto.subtle.importKey("jwk",publicKey,{name:"RSA-OAEP",hash:"SHA-256"},false,["encrypt"]);
  const aes = await crypto.subtle.generateKey({name:"AES-GCM",length:256},true,["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = await crypto.subtle.encrypt({name:"AES-GCM",iv},aes,enc.encode(JSON.stringify(value)));
  const key = await crypto.subtle.encrypt("RSA-OAEP",rsa,await crypto.subtle.exportKey("raw",aes));
  return {key:b64(key),iv:b64(iv),data:b64(data)};
}
export class Session {
  constructor(ctx,env) { this.ctx=ctx; this.env=env; }
  async alarm() { await this.ctx.storage.deleteAll(); }
  async fetch(req) {
    return this.ctx.blockConcurrencyWhile(async()=>{
      const action=new URL(req.url).pathname;
      if (action==="/init") {
        const input=await req.json();
        if (!/^[A-Za-z0-9_-]{43}$/.test(input.challenge||"") || !/^[a-f0-9]{64}$/.test(input.poll_hash||"") || input.public_key?.kty!=="RSA" || input.public_key?.e!=="AQAB" || input.public_key?.d || !/^[A-Za-z0-9_-]{342}$/.test(input.public_key?.n||"")) return reply({error:"invalid_session"},400);
        await crypto.subtle.importKey("jwk",input.public_key,{name:"RSA-OAEP",hash:"SHA-256"},false,["encrypt"]);
        const expires=Date.now()+600000;
        await this.ctx.storage.put("session",{challenge:input.challenge,poll_hash:input.poll_hash,public_key:{kty:"RSA",n:input.public_key.n,e:"AQAB"},expires});
        await this.ctx.storage.setAlarm(expires);
        return reply({ready:true});
      }
      const s=await this.ctx.storage.get("session");
      if (!s || s.expires<Date.now()) return reply({error:"expired"},410);
      if (action==="/start") {
        const u=new URL("https://dash.cloudflare.com/oauth2/auth");
        u.search=new URLSearchParams({client_id:this.env.CLIENT_ID,redirect_uri:this.env.ORIGIN+"/callback",response_type:"code",response_mode:"form_post",scope:"argotunnel.write access.write access-acct.write dns.write zone.read offline_access",state:this.ctx.id.toString(),code_challenge:s.challenge,code_challenge_method:"S256"});
        return new Response(null,{status:302,headers:{...headers,Location:u.toString()}});
      }
      if (action==="/callback") {
        if (await this.ctx.storage.get("sealed")) return reply({error:"already_received"},409);
        const form=await req.formData();
        const code=form.get("code");
        if (typeof code!=="string" && !form.get("error")) return reply({error:"missing_code"},400);
        await this.ctx.storage.put("sealed",await seal(s.public_key,code?{code}:{error:"authorization_denied"}));
        return new Response("Authorization received. Return to the installer; you can close this page.",{headers:{...headers,"Content-Type":"text/plain; charset=utf-8"}});
      }
      if (action==="/poll") {
        const auth=req.headers.get("Authorization")||"";
        if (!auth.startsWith("Bearer ") || await digest(auth.slice(7))!==s.poll_hash) return reply({error:"forbidden"},403);
        const sealed=await this.ctx.storage.get("sealed");
        if (!sealed) return reply({pending:true},202);
        await this.ctx.storage.deleteAll();
        await this.ctx.storage.deleteAlarm();
        return reply(sealed);
      }
      return reply({error:"not_found"},404);
    });
  }
}
export default {
  async fetch(req,env) {
    try {
      if (Date.now()>Number(env.DEADLINE)) return reply({error:"test_ended"},410);
      const u=new URL(req.url);
      if (u.pathname==="/health") return reply({ok:true});
      if (Number(req.headers.get("Content-Length")||0)>16384) return reply({error:"too_large"},413);
      if (u.pathname==="/sessions" && req.method==="POST") {
        const id=env.SESSIONS.newUniqueId();
        const result=await env.SESSIONS.get(id).fetch(new Request("https://session/init",{method:"POST",body:await req.text(),headers:{"Content-Type":"application/json"}}));
        if (!result.ok) return result;
        return reply({id:id.toString(),authorization_url:env.ORIGIN+"/start/"+id,expires_in:600},201);
      }
      let id,action;
      if (u.pathname==="/callback" && req.method==="POST") {
        id=(await req.clone().formData()).get("state"); action="callback";
      } else {
        const match=u.pathname.match(/^\/(start|poll)\/([a-f0-9]{64})$/);
        if (!match || req.method!=="GET") return reply({error:"not_found"},404);
        [,action,id]=match;
      }
      if (typeof id!=="string" || !/^[a-f0-9]{64}$/.test(id)) return reply({error:"invalid_state"},400);
      return await env.SESSIONS.get(env.SESSIONS.idFromString(id)).fetch(new Request("https://session/"+action,req));
    } catch { return reply({error:"request_failed"},400); }
  }
};
