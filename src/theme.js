(function(){
 'use strict';
 // Font Awesome Free 5.15.4 by Fonticons, Inc. (https://fontawesome.com) - icons CC BY 4.0; converted to SVG outlines.
 const themeIcons={"moon":"<svg class=\"ls-fa-icon\" data-fa=\"moon\" width=\"18\" height=\"18\" viewBox=\"0 0 894.2757 1000\" fill=\"currentColor\" aria-hidden=\"true\" focusable=\"false\"><path d=\"M500 1000C654 1000 796 930 889 815C903 798 887 773 866 777C623 823 401 637 401 392C401 251 476 122 599 52C618 41 613 12 592 8C562 3 531 0 500 0C224 0 0 224 0 500C0 776 224 1000 500 1000Z\"/></svg>","sun":"<svg class=\"ls-fa-icon\" data-fa=\"sun\" width=\"18\" height=\"18\" viewBox=\"0 0 999.5 999.5\" fill=\"currentColor\" aria-hidden=\"true\" focusable=\"false\"><path d=\"M499.75 312.75C396.75 312.75 311.75 396.75 311.75 499.75C311.75 602.75 396.75 686.75 499.75 686.75C602.75 686.75 687.75 602.75 687.75 499.75C687.75 396.75 602.75 312.75 499.75 312.75ZM980.75 469.75 795.75 376.75 861.75 180.75C870.75 153.75 844.75 128.75 818.75 137.75L622.75 203.75L529.75 18.75C516.75 -6.25 482.75 -6.25 469.75 18.75L376.75 203.75L180.75 137.75C153.75 128.75 128.75 154.75 137.75 180.75L203.75 376.75L18.75 469.75C-6.25 482.75 -6.25 516.75 18.75 529.75L203.75 622.75L137.75 818.75C128.75 845.75 154.75 870.75 180.75 861.75L376.75 795.75L469.75 980.75C481.75 1005.75 516.75 1005.75 529.75 980.75L621.75 795.75L818.75 861.75C845.75 870.75 869.75 844.75 860.75 818.75L795.75 622.75L980.75 529.75C1005.75 516.75 1005.75 482.75 980.75 469.75ZM676.75 676.75C579.75 773.75 419.75 773.75 322.75 676.75C225.75 579.75 225.75 419.75 322.75 322.75C419.75 225.75 579.75 225.75 676.75 322.75C773.75 419.75 773.75 579.75 676.75 676.75Z\"/></svg>","bars":"<svg class=\"ls-fa-icon\" data-fa=\"bars\" width=\"18\" height=\"18\" viewBox=\"0 0 875 766\" fill=\"currentColor\" aria-hidden=\"true\" focusable=\"false\"><path d=\"M31 141H844C861 141 875 127 875 110V31C875 14 861 0 844 0H31C14 0 0 14 0 31V110C0 127 14 141 31 141ZM31 453H844C861 453 875 439 875 422V344C875 327 861 313 844 313H31C14 313 0 327 0 344V422C0 439 14 453 31 453ZM31 766H844C861 766 875 752 875 735V656C875 639 861 625 844 625H31C14 625 0 639 0 656V735C0 752 14 766 31 766Z\"/></svg>","times":"<svg class=\"ls-fa-icon\" data-fa=\"times\" width=\"18\" height=\"18\" viewBox=\"0 0 688 688\" fill=\"currentColor\" aria-hidden=\"true\" focusable=\"false\"><path d=\"M474.0 344.0 670.0 149.0C694.0 125.0 694.0 86.0 670.0 62.0L626.0 18.0C602.0 -6.0 563.0 -6.0 539.0 18.0L344.0 214.0L148.0 18.0C124.0 -6.0 85.0 -6.0 61.0 18.0L18.0 62.0C-6.0 86.0 -6.0 125.0 18.0 149.0L213.0 344.0L18.0 539.0C-6.0 563.0 -6.0 602.0 18.0 626.0L61.0 670.0C85.0 694.0 124.0 694.0 148.0 670.0L344.0 474.0L539.0 670.0C563.0 694.0 602.0 694.0 626.0 670.0L670.0 626.0C694.0 602.0 694.0 563.0 670.0 539.0Z\"/></svg>"};
 const key='linkscope.theme',root=document.documentElement;
 function read(){try{return localStorage.getItem(key);}catch(e){return null;}}
 function apply(value,save){root.dataset.theme=value;if(save){try{localStorage.setItem(key,value);}catch(e){}}const b=document.getElementById('ls-theme-switch');if(b){const dark=value==='dark';if(!b.closest('.ls-tools'))b.innerHTML=themeIcons[dark?'sun':'moon'];b.title=dark?'Switch to light theme':'Switch to dark theme';b.setAttribute('aria-label',b.title);b.setAttribute('aria-pressed',String(dark));}if(save)window.dispatchEvent(new Event('resize'));}
 apply(read()==='dark'?'dark':'light',false);
 document.addEventListener('DOMContentLoaded',()=>{let b=document.getElementById('ls-theme-switch');if(!b){b=document.createElement('button');b.id='ls-theme-switch';b.type='button';b.classList.add('theme-floating');document.body.append(b);}b.addEventListener('click',()=>apply(root.dataset.theme==='dark'?'light':'dark',true));apply(root.dataset.theme,false);});
 // Shared responsive navigation. Collapse on tablets and whenever the desktop links cannot fit.
 document.addEventListener('DOMContentLoaded',()=>{
  const head=document.querySelector('.ls-header'),bar=head?.querySelector('.ls-header-inner'),nav=document.getElementById('ls-main-nav'),toggle=document.getElementById('ls-menu-toggle');
  if(!bar||!nav||!toggle)return;
  const compact=window.matchMedia('(max-width: 1299px)');
  const setOpen=open=>{if(toggle.getAttribute('aria-expanded')===String(open))return;bar.classList.toggle('ls-nav-open',open);toggle.setAttribute('aria-expanded',String(open));toggle.setAttribute('aria-label',open?'Close navigation':'Open navigation');toggle.innerHTML=themeIcons[open?'times':'bars'];};
  // CSS chooses the initial responsive layout before first paint; measure for unusually wide text.
  // Reserve the utility track independently; never wrap or hide overflowing links.
  const fit=()=>{
   const was=bar.classList.contains('ls-nav-compact');
   if(compact.matches){const focused=nav.contains(document.activeElement);bar.classList.add('ls-nav-compact');if(!was&&focused)toggle.focus();return;}
   bar.classList.remove('ls-nav-compact');
   const rect=nav.getBoundingClientRect(),last=nav.lastElementChild?.getBoundingClientRect();
   const narrow=nav.scrollWidth>nav.clientWidth||!!last&&last.right>rect.right+.25;
   const focused=nav.contains(document.activeElement);
   bar.classList.toggle('ls-nav-compact',narrow);
   if(narrow&&!was&&focused)toggle.focus();
   if(!narrow&&was){if(nav.contains(document.activeElement)||document.activeElement===toggle)nav.querySelector('a[aria-current=page],a')?.focus();setOpen(false);}
  };
  toggle.addEventListener('click',()=>{const open=toggle.getAttribute('aria-expanded')!=='true';setOpen(open);if(open)nav.querySelector('a')?.focus();});
  document.addEventListener('keydown',e=>{if(e.key==='Escape'&&toggle.getAttribute('aria-expanded')==='true'){setOpen(false);toggle.focus();}});
  document.addEventListener('pointerdown',e=>{if(!nav.contains(e.target)&&!toggle.contains(e.target))setOpen(false);});
  nav.addEventListener('click',e=>{if(e.target.closest('a')){if(bar.classList.contains('ls-nav-compact'))toggle.focus();setOpen(false);}});
  bar.addEventListener('focusout',e=>{if(e.relatedTarget&&!bar.contains(e.relatedTarget))setOpen(false);});
  window.addEventListener('resize',fit);if(typeof ResizeObserver!=='undefined')new ResizeObserver(fit).observe(bar);
  // Brand updates can change available width without changing the viewport.
  const brand=bar.querySelector('.brand');if(brand)new MutationObserver(fit).observe(brand,{childList:true,subtree:true,characterData:true});
  fit();if(document.fonts)document.fonts.ready.then(fit);
 });
 window.addEventListener('storage',e=>{if(e.key===key){apply(e.newValue==='dark'?'dark':'light',false);window.dispatchEvent(new Event('resize'));}});
})();
