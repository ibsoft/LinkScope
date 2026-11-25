'use strict';
(() => {
    const indicator = document.createElement('div');
    indicator.className = 'ls-global-loading';
    indicator.hidden = true;
    indicator.setAttribute('role', 'status');
    indicator.setAttribute('aria-atomic', 'true');

    const ring = document.createElement('span');
    ring.className = 'ls-spinner';
    ring.setAttribute('aria-hidden', 'true');
    const caption = document.createElement('span');
    indicator.append(ring, caption);
    document.body.append(indicator);

    const pending = new Map();
    let timer = null;
    function sync() {
        if (!pending.size) {
            clearTimeout(timer);
            timer = null;
            indicator.hidden = true;
            caption.textContent = '';
            return;
        }
        if (!indicator.hidden) {
            const {label} = Array.from(pending.values()).pop();
            if (caption.textContent !== label) caption.textContent = label;
        } else if (timer === null) {
            timer = setTimeout(() => {
                timer = null;
                indicator.hidden = false;
                sync();
            }, 200);
        }
    }
    function begin(label, key = Symbol()) {
        const action = {label};
        pending.delete(key);
        pending.set(key, action);
        sync();
        return () => {
            if (pending.get(key) !== action) return;
            pending.delete(key);
            sync();
        };
    }
    async function run(label, operation) {
        const done = begin(label);
        try { return await operation(); }
        finally { done(); }
    }
    window.LinkScopeBusy = {begin, run};
    if (document.readyState !== 'complete') {
        window.addEventListener('load', begin('Loading page…'), {once: true});
    }
})();
