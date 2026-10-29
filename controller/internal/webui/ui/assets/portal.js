// @ts-check
// What every page of the portal does (SDN-58, #251), as page.js does for the console: it calls the action self
// with the token of the self scope that the tab keeps, and sends the browser to the sign-in of the portal without
// a token that the controller knows; it draws the header, with who is signed in and the button that signs out,
// renders, and wires its forms and buttons to the API, showing a refusal in the words of the API. The <html>
// element tells how far the page is in data-state: loading, ready or error. A token of the portal never holds an
// API role, so no page of the console opens with it, and the console's token never opens a page of the portal.

import { APIError, call, selfToken, setSelfToken } from './api.js';
import { el, find } from './dom.js';
import { RanzConfirm, RanzProblem } from './components.js';

/** The pages of the portal, in the order of the header. */
const areas = [
  { href: '/portal', label: 'My devices' },
  { href: '/portal-join', label: 'Join tokens' },
];

/** toSignIn sends the browser to the sign-in of the portal, which comes back to this page. */
function toSignIn() {
  const next = location.pathname + location.search;
  location.replace(`/portal-sign-in?next=${encodeURIComponent(next)}`);
}

/**
 * start runs the page: render draws it once the User is known, which is the answer of the action self. A tab
 * with no token goes to the sign-in, and so does one whose token the controller refuses.
 * @param {(self: import('./portal-types.js').SelfInfo) => Promise<void>} render
 */
export async function start(render) {
  const html = document.documentElement;
  html.dataset.state = 'loading';
  if (!selfToken()) {
    toSignIn();
    return;
  }
  try {
    /** @type {import('./portal-types.js').SelfInfo} */
    const self = await call('self');
    header(self);
    await render(self);
    html.dataset.state = 'ready';
  } catch (err) {
    if (err instanceof APIError && err.status === 401) {
      setSelfToken('');
      toSignIn();
      return;
    }
    problem(err);
    html.dataset.state = 'error';
  }
}

/**
 * header draws the header of the page: the pages of the portal, the User and the button that signs out.
 * @param {import('./portal-types.js').SelfInfo} self
 */
function header(self) {
  const links = el('ul');
  for (const a of areas) {
    const link = el('a', { href: a.href }, a.label);
    if (a.href === location.pathname) {
      link.setAttribute('aria-current', 'page');
    }
    links.append(el('li', {}, link));
  }
  const out = el('button', { type: 'button', class: 'quiet', 'data-action': 'signOut' }, 'Sign out');
  onClick(out, signOut);
  find('#portal-header', HTMLElement).replaceChildren(
    el('nav', { 'aria-label': 'Portal' }, el('a', { href: '/portal', class: 'brand' }, 'Ranz portal'), links),
    el('div', { class: 'who' }, el('span', { class: 'user' }, self.displayName || self.name), ' ', out),
  );
}

/** signOut ends the token of the tab at the controller, forgets it, and goes to the sign-in. */
async function signOut() {
  try {
    await call('signOut');
  } catch {
    // A token that the controller does not know any more is as good as ended
  }
  setSelfToken('');
  location.assign('/portal-sign-in');
}

/**
 * problem shows err in the problem area of the page, or clears it when err is null.
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
 * onSubmit runs act when form is submitted, with its buttons off meanwhile. A failure is shown in the problem
 * area; a 401 sends the browser to the sign-in.
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
 * run runs act with the buttons of owner off, and shows its failure.
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
      setSelfToken('');
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

export { call };
