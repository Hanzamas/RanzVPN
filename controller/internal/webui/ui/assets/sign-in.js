// @ts-check
// The sign-in page (/sign-in): the token goes into the tab once the API accepts it for the
// action whoami, and the browser goes on to the page that sent it here (?next=).

import { APIError, call, setToken } from './api.js';
import { find } from './dom.js';
import { RanzProblem } from './components.js';

const form = find('#sign-in', HTMLFormElement);
// The field has no name, so a browser that sends the form itself, without this script, never
// puts the token into a URL.
const field = find('#token', HTMLInputElement);
const problem = find('ranz-problem', RanzProblem);

/** @returns {string} where to go after the sign-in: a path of this controller, / by default */
function next() {
  const n = new URLSearchParams(location.search).get('next') ?? '';
  return n.startsWith('/') && !n.startsWith('//') && !n.startsWith('/\\') ? n : '/';
}

form.addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const secret = field.value.trim();
  const button = find('button', HTMLButtonElement, form);
  button.disabled = true;
  problem.clear();
  setToken(secret);
  try {
    await call('whoami');
    location.assign(next());
  } catch (err) {
    setToken('');
    problem.show(err instanceof APIError && err.status === 401 ? 'This controller does not know the token, or it was deleted.' : err);
    button.disabled = false;
  }
});

document.documentElement.dataset.state = 'ready';
