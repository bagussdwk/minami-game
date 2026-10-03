/* MINAMI shared account/statistics bridge. GitHub Pages runs this JS; the optional API lives on another HTTPS host. */
(function(){
  const GLOBAL_KEY='minamiGlobalProfileV1', MODE_KEY='minamiModeStatsV1', TOKEN_KEY='minamiApiTokenV1', USER_KEY='minamiApiUserV1';
  const defaults={games_finished:0,game_wins:0,rank1:0,match_finished:0,match_wins:0};
  const read=(k,f)=>{try{const x=JSON.parse(localStorage.getItem(k)||'null');return x&&typeof x==='object'?x:f}catch(e){return f}};
  const write=(k,v)=>{try{localStorage.setItem(k,JSON.stringify(v));return true}catch(e){return false}};
  function apiBase(){return String(window.MINAMI_API_BASE||localStorage.getItem('minamiApiBase')||'').replace(/\/$/,'')}
  function add(a,b){const x={...defaults,...a};for(const k of Object.keys(defaults))x[k]=(Number(x[k])||0)+(Number(b?.[k])||0);return x}
  function globalStats(){
    const existing=read(GLOBAL_KEY,defaults);
    if(!existing._migrated){
      const old=read('minamiFeatureStatsV2',null);
      if(old){const merged=add(existing,{games_finished:Number(old.games)||0,game_wins:Number(old.gameWins)||0,rank1:Number(old.rank1)||0,match_finished:Number(old.matches)||0,match_wins:Number(old.matchWins)||0});merged._migrated=true;write(GLOBAL_KEY,merged);return merged}
    }
    return {...defaults,...existing};
  }
  async function request(path,body,method='POST'){
    const base=apiBase();if(!base)throw new Error('API belum dikonfigurasi.');
    const h={'Content-Type':'application/json'},t=localStorage.getItem(TOKEN_KEY);if(t)h.Authorization='Bearer '+t;
    const r=await fetch(base+'/'+path,{method,headers:h,body:method==='GET'?undefined:JSON.stringify(body||{})});
    const j=await r.json().catch(()=>({ok:false,error:'Respons API tidak valid.'}));if(!r.ok||!j.ok)throw new Error(j.error||'API gagal.');return j;
  }
  async function record(mode,delta){
    const next=add(globalStats(),delta);write(GLOBAL_KEY,next);
    const modes=read(MODE_KEY,{});modes[mode]=add(modes[mode]||{},delta);write(MODE_KEY,modes);
    if(apiBase())try{await request('game-result',{mode,...delta})}catch(e){console.warn('MINAMI API:',e.message)}
    window.dispatchEvent(new CustomEvent('minami-profile-updated'));return next;
  }
  function title(s){const r=Number(s?.rank1)||0,g=Number(s?.games_finished)||0,w=Number(s?.game_wins)||0;if(r>=100&&g>=25&&w>=10)return 'GRANDMASTER '+(Math.floor((r-100)/50)+1);if(r>=60)return 'MASTER';if(r>=30)return 'EXPERT';if(r>=15)return 'PLAYER';if(r>=5)return 'NOVICE';return 'PEMULA'}
  window.MinamiAccount={getGlobalStats:globalStats,getModeStats:()=>read(MODE_KEY,{}),getTitle:()=>title(globalStats()),record,
    getUser:()=>read(USER_KEY,null),setApiBase:v=>localStorage.setItem('minamiApiBase',String(v||'').replace(/\/$/,'')),
    login:async(u,p)=>{const j=await request('login',{username:u,password:p});write(TOKEN_KEY,j.token);write(USER_KEY,j.user);window.dispatchEvent(new CustomEvent('minami-profile-updated'));return j.user},
    register:async(u,p,n)=>request('register',{username:u,password:p,display_name:n}),
    logout:async()=>{try{await request('logout',{})}catch(e){}localStorage.removeItem(TOKEN_KEY);localStorage.removeItem(USER_KEY);window.dispatchEvent(new CustomEvent('minami-profile-updated'))}
  };
})();