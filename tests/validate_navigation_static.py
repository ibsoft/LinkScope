"""Portable source checks; not a browser layout or Windows installer test."""
from pathlib import Path
from html.parser import HTMLParser
import re, subprocess, json, xml.etree.ElementTree as ET
ROOT=Path(__file__).resolve().parents[1]
SRC=ROOT/'src'
PAGES={'dashboard':'/','system':'/system','integrity':'/integrity','endpoint':'/endpoint','alerts':'/alerts','logs':'/logs','audit':'/audit','ai':'/ai','settings':'/settings','account':'/account','users':'/users'}
ICONS={'/':'desktop','/system':'heartbeat','/integrity':'lock','/endpoint':'shield-alt','/alerts':'bell','/logs':'file-alt','/audit':'user-check','/ai':'robot',}
for name,route in PAGES.items():
    page=(SRC/(name+'.html')).read_text()
    nav=re.search(r'<nav id="ls-main-nav"[^>]*>(.*?)</nav>',page,re.S).group(1)
    links=re.findall(r'(<a\b[^>]*?href="([^"]+)"[^>]*>)(.*?)</a>',nav,re.S)
    assert [a[1] for a in links]==list(ICONS),name
    for start,href,body in links:
        svg=ET.fromstring(re.search(r'<svg\b.*?</svg>',body,re.S).group())
        assert svg.attrib['data-fa']==ICONS[href] and svg.attrib['fill']=='currentColor'
        assert svg.attrib['aria-hidden']=='true' and svg.find('path').attrib['d']
        assert ('aria-current="page"' in start)==(href==route)
    assert 'id="global-export"' not in nav and 'href="/settings"' not in nav
    assert re.search(r'id="global-export"[^>]*>.*?</svg>Report</a>',page,re.S)
    assert 'class="ls-tools"' in page and 'id="ls-theme-switch"' in page and '{{unread-count}}' in page
    assert 'class="ls-account-menu"' in page and 'href="/settings"' in page
    assert '{{admin-hidden}}' in page
    assert 'aria-controls="ls-main-nav"' in page and 'data-fa="bars"' in page
    assert 'Font Awesome Free 5.15.4' in page
assert 'id="ls-main-nav"' not in (SRC/'login.html').read_text()
for filename,keys in [('theme.js',['moon','sun','bars','times'])]:
    s=(SRC/filename).read_text()
    variable='themeIcons' if filename=='theme.js' else 'icons'
    values=json.loads(re.search(r'const '+variable+r'=(\{[^\n]+\});',s).group(1))
    assert list(values)==keys
    for name,value in values.items():
        svg=ET.fromstring(value);assert svg.attrib['data-fa']==name and svg.find('path').attrib['d']
    subprocess.run(['node','--check',str(SRC/filename)],check=True)
assert not list(ROOT.rglob('*.woff2')) and not list(ROOT.rglob('*.ttf')) and not list(ROOT.rglob('*.otf'))
assert (ROOT/'FONT-AWESOME-NOTICE.md').is_file()
print('PASS: eleven navigation headers, eight main Font Awesome icons and account links, active routes, Report link, hamburger, utility icon artwork, no font files')
css=(SRC/'navigation.css').read_text();js=(SRC/'theme.js').read_text()
for key in ['15px/20px','min-height:44px','ls-nav-compact','--ls-workspace-max,1440px']:assert key in css
for key in ['1299px','scrollWidth','aria-expanded','Escape','ResizeObserver']:assert key in js
assert 'e.preventDefault();exportAll();' in (SRC/'report.js').read_text()
assert 'setTimeout(()=>dismiss(key),7000)' in (SRC/'toast.js').read_text()
print('PASS: responsive navigation and existing Report/notification wiring (static source assertions)')
setup=(ROOT/'setup/Setup.cs').read_text();wizard=(ROOT/'setup/wizard.ps1').read_text();build=(ROOT/'setup/BuildSetup.cmd').read_text()
for key in ['CreateNoWindow=true','CreateNoWindow = true','RegistryView.Registry64','RegistryView.Registry32','clamav-latest.msi','MsiOpenDatabaseW','SHA256.Create()','/qn /norestart','RedirectStandardOutput=true','RequireAdmin()']:assert key in setup,key
for key in ['--check-clamav','--install-clamav','-Verb RunAs','YesNo','3010','1641']:assert key in wizard,key
for key in ['/target:winexe','clamav-latest.msi','targetDeploy']:assert key in build,key
assert 'BuildSetup.cmd' in (ROOT/'Build.cmd').read_text()
assert (ROOT/'deploy/README.md').is_file()
print('PASS: GUI setup build, hidden child-process flags, optional MSI workflow and deploy instructions (static source assertions)')

# The header is isolated from legacy wrapping containers. CSS chooses the initial layout before scripts run.
for name in PAGES:
    page=(SRC/(name+'.html')).read_text()
    assert '<div class="ls-header-inner">' in page,name
    assert '/assets/theme-workspace-v11.css' in page and '/assets/theme-stable-v9.js' in page,name
assert 'grid-template-areas:"brand navigation tools"' in css
assert 'grid-template-areas:"brand tools toggle"' in css
assert 'display:grid;grid-template-columns:' in css and 'justify-content:flex-start;flex-wrap:nowrap' in css and 'column-gap:4px' in css and 'font:700 29px/1' in css
assert 'nav.scrollWidth>nav.clientWidth' in js
web=(SRC/'Web.cs').read_text()
assert 'Asset("/assets/theme-workspace-v11.css","theme.css","text/css")' in web
assert 'Asset("/assets/theme-stable-v9.js","theme.js","application/javascript")' in web
assert 'Asset("/assets/navigation-v24.css","navigation.css","text/css")' in web
assert all('/assets/navigation-v24.css' in (SRC/(name+'.html')).read_text() for name in PAGES)
assert '@view-transition { navigation: auto; }' in (SRC/'navigation.css').read_text()
assert 'PageAsset(r.Path,session)' in web and 'alerts.HeaderUnread()' in web
assert 'tools.append(bell,account)' not in (SRC/'toast.js').read_text()
print('PASS: strict single-row grid, CSS initial layout, versioned theme resources and overflow fallback')
