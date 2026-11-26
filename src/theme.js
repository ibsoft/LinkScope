(function(){
 'use strict';
 const key='linkscope.theme',root=document.documentElement;
 function read(){try{return localStorage.getItem(key);}catch(e){return null;}}
 function apply(value,save){root.dataset.theme=value;if(save){try{localStorage.setItem(key,value);}catch(e){}}const b=document.getElementById('ls-theme-switch');if(b){const dark=value==='dark';b.textContent=dark?'☀':'☾';b.title=dark?'Switch to light theme':'Switch to dark theme';b.setAttribute('aria-label',b.title);b.setAttribute('aria-pressed',String(dark));}if(save)window.dispatchEvent(new Event('resize'));}
 apply(read()==='dark'?'dark':'light',false);
 document.addEventListener('DOMContentLoaded',()=>{const b=document.createElement('button');b.id='ls-theme-switch';b.type='button';const bell=document.querySelector('.ls-tools a.ls-icon');const header=document.querySelector('header nav');if(bell)bell.after(b);else if(header)header.append(b);else{b.classList.add('theme-floating');document.body.append(b);}b.addEventListener('click',()=>apply(root.dataset.theme==='dark'?'light':'dark',true));apply(root.dataset.theme,false);});
 window.addEventListener('storage',e=>{if(e.key===key){apply(e.newValue==='dark'?'dark':'light',false);window.dispatchEvent(new Event('resize'));}});
})();
