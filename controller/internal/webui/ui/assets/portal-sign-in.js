// @ts-check
// The sign-in page of the portal (/portal-sign-in): a User signs in with its name and its password for the scope
// self (SDN-58), the action signIn. The token that the controller gives goes into the tab, which keeps it apart
// from the token of the console, and the browser goes on to the page that sent it here (?next=).

import { APIError, call, setSelfToken } from './api.js';
import { find } from './dom.js';
import { RanzProblem } from './components.js';

const form = find('#sign-in', HTMLFormElement);
const user = find('#user', HTMLInputElement);
// The fields have no name, so a browser that sends the form itself, without this script, never puts the password
// into a URL.
const password = find('#password', HTMLInputElement);
const problem = find('ranz-problem', RanzProblem);

/** @returns {string} where to go after the sign-in: a page of this controller, /portal by default */
function next() {
  const n = new URLSearchParams(location.search).get('next') ?? '';
  return n.startsWith('/') && !n.startsWith('//') && !n.startsWith('/\\') ? n : '/portal';
}

form.addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const button = find('button', HTMLButtonElement, form);
  button.disabled = true;
  problem.clear();
  try {
    /** @type {import('./portal-types.js').SignedIn} */
    const signed = await call('signIn', { body: { user: user.value.trim(), password: password.value, scope: 'self' } });
    setSelfToken(signed.token);
    password.value = '';
    location.assign(next());
  } catch (err) {
    password.value = '';
    problem.show(err instanceof APIError ? err.message : err);
    button.disabled = false;
  }
});

document.documentElement.dataset.state = 'ready';
