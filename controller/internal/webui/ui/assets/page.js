// @ts-check
// What every page of the web UI does: it calls whoami with the token of the tab (and sends the
// browser to /sign-in without a token the API knows), hides each control whose UI action the
// role of the token may not make, renders, and wires its forms to the API. The <html> element
// tells how far the page is in data-state: loading, ready or error.

import { actions, allows, APIError, call, setToken, token } from './api.js';
import { find } from './dom.js';
import { RanzConfirm, RanzNav, RanzProblem } from './components.js';

/** @type {import('./api.js').Who} */
let who = { name: '', role: 'viewer' };

/** @type {Map<string, import('./api.js').Action>} */
let table = new Map();

/**
 * can reports whether the token of the tab may make the UI action name: whether its role allows
 * the role the action needs, as the API's Guard decides.
 * @param {string} name
 * @returns {boolean}
 */
export function can(name) {
  const a = table.get(name);
  if (!a) {
    throw new Error(`the web UI has no action ${name}`);
  }
  return allows(who.role, a.role);
}

/**
 * gate hides root and every element in it whose data-action names a UI action the token may not
 * make, and shows the others.
 * @param {Element} root
 */
function gate(root) {
  const all = root.matches('[data-action]') ? [root] : [];
  all.push(...root.querySelectorAll('[data-action]'));
  for (const e of all) {
    if (e instanceof HTMLElement) {
      e.hidden = !can(e.dataset.action ?? '');
    }
  }
}

/** toSignIn sends the browser to the sign-in page, which comes back to this page. */
function toSignIn() {
  const next = location.pathname + location.search;
  location.replace(`/sign-in?next=${encodeURIComponent(next)}`);
}

/**
 * start runs the page: render draws it once the token is known. Every element with data-action,
 * also the ones render and the forms add later, is shown only to a role that may make its action.
 * The ones in the HTML of a page start hidden, so no role sees a control it may not use while
 * the page loads.
 * @param {(who: import('./api.js').Who) => Promise<void>} render
 */
export async function start(render) {
  const html = document.documentElement;
  html.dataset.state = 'loading';
  if (!token()) {
    toSignIn();
    return;
  }
  try {
    [table, who] = await Promise.all([actions(), call('whoami')]);
    find('ranz-nav', RanzNav).who = who;
    gate(document.body);
    new MutationObserver((records) => {
      for (const r of records) {
        for (const n of r.addedNodes) {
          if (n instanceof Element) {
            gate(n);
          }
        }
      }
    }).observe(document.body, { childList: true, subtree: true });
    await render(who);
    // The observer gates what render added, too, but only at its next microtask.
    gate(document.body);
    html.dataset.state = 'ready';
  } catch (err) {
    if (err instanceof APIError && err.status === 401) {
      setToken('');
      toSignIn();
      return;
    }
    problem(err);
    html.dataset.state = 'error';
  }
}

/**
 * problem shows err in the page's problem area, or clears it when err is null.
 * @param {unknown} err
 */
export function problem(err) {
  const p = find('ranz-problem', RanzProblem);
  if (err === null) {
    p.clear();
  } else {
    p.show(err);
  }
}

/**
 * confirm asks the user before a change.
 * @param {string} message
 * @param {string} ok - the label of the button that goes ahead
 * @returns {Promise<boolean>}
 */
export function confirm(message, ok) {
  return find('ranz-confirm', RanzConfirm).ask(message, ok);
}

/**
 * onSubmit runs act when form is submitted, with its submit buttons off meanwhile. A failure is
 * shown in the problem area; a 401 sends the browser to /sign-in.
 * @param {HTMLFormElement} form
 * @param {(data: FormData) => Promise<void>} act
 */
export function onSubmit(form, act) {
  form.addEventListener('submit', (ev) => {
    ev.preventDefault();
    void run(form, () => act(new FormData(form)));
  });
}

/**
 * onClick runs act when button is clicked, with the button off meanwhile.
 * @param {HTMLButtonElement} button
 * @param {() => Promise<void>} act
 */
export function onClick(button, act) {
  button.addEventListener('click', () => void run(button, act));
}

/**
 * run runs act with the controls of owner off, and shows its failure.
 * @param {HTMLFormElement | HTMLButtonElement} owner
 * @param {() => Promise<void>} act
 */
async function run(owner, act) {
  const controls = owner instanceof HTMLFormElement ? [...owner.querySelectorAll('button')] : [owner];
  for (const c of controls) {
    c.disabled = true;
  }
  problem(null);
  try {
    await act();
  } catch (err) {
    if (err instanceof APIError && err.status === 401) {
      setToken('');
      toSignIn();
      return;
    }
    problem(err);
  } finally {
    for (const c of controls) {
      c.disabled = false;
    }
  }
}

/** @returns {URLSearchParams} the state of the page in its query string */
export function state() {
  return new URLSearchParams(location.search);
}

/**
 * setState puts the state of the page into its query string, without a new history entry, so a
 * link to the page shows the same (ADR-0038 decision 4). Empty values are left out.
 * @param {Record<string, string | number | undefined>} values
 */
export function setState(values) {
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(values)) {
    if (v !== undefined && v !== '') {
      q.set(k, String(v));
    }
  }
  const s = q.toString();
  history.replaceState(null, '', s ? `${location.pathname}?${s}` : location.pathname);
}

export { call };
