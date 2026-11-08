/* Passcode encryption: PBKDF2 (SHA-256) -> AES-GCM. Used by index.html and admin.html. */
const Vault=(()=>{
  const te=new TextEncoder(),td=new TextDecoder(),ITER=310000;
  const b64=u=>{let s='';new Uint8Array(u).forEach(x=>s+=String.fromCharCode(x));return btoa(s)};
  const unb64=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
  async function key(p,salt){
    const k=await crypto.subtle.importKey('raw',te.encode(p),'PBKDF2',false,['deriveKey']);
    return crypto.subtle.deriveKey({name:'PBKDF2',salt,iterations:ITER,hash:'SHA-256'},k,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);
  }
  return{
    async seal(list,p){
      const salt=crypto.getRandomValues(new Uint8Array(16)),iv=crypto.getRandomValues(new Uint8Array(12));
      const ct=await crypto.subtle.encrypt({name:'AES-GCM',iv},await key(p,salt),te.encode(JSON.stringify(list)));
      return{v:1,salt:b64(salt),iv:b64(iv),data:b64(ct)};
    },
    async open(env,p){
      try{
        const pt=await crypto.subtle.decrypt({name:'AES-GCM',iv:unb64(env.iv)},await key(p,unb64(env.salt)),unb64(env.data));
        return JSON.parse(td.decode(pt));
      }catch(e){throw new Error('Wrong passcode.')}
    }
  };
})();
