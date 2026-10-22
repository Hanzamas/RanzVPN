// @ts-check
// The API tokens page (/tokens): the tokens and their roles, and making and deleting one. Only
// an admin may, so the page calls nothing for another role and says so instead.

import { call, can, confirm, onClick, onSubmit, start } from './page.js';
import { el, find } from './dom.js';
import { RanzTable } from './components.js';

/** @typedef {import('./types.js').Token} Token */
/** @typedef {import('./types.js').NewToken} NewToken */

const result = find('#result', HTMLOutputElement);

async function render() {
  /** @type {{tokens: Token[]}} */
  const l = await call('tokens');
  find('#tokens', RanzTable).render([
    { label: 'Name', cell: (t) => t.name },
    { label: 'Role', cell: (t) => t.role },
    {
      label: '',
      cell: (t) => {
        const b = el('button', { type: 'button', class: 'danger small', 'data-action': 'deleteToken' }, 'Delete');
        onClick(b, async () => {
          if (!(await confirm(`Delete the API token ${t.name}? Whoever holds its secret can call the API no more.`, 'Delete'))) {
            return;
          }
          /** @type {Token} */
          const gone = await call('deleteToken', { params: { name: t.name } });
          result.replaceChildren(`The API token ${gone.name} is deleted.`);
          await render();
        });
        return b;
      },
    },
  ], l.tokens, 'No API token.');
}

onSubmit(find('#create-form', HTMLFormElement), async (data) => {
  /** @type {NewToken} */
  const t = await call('createToken', { body: { name: String(data.get('name') ?? ''), role: String(data.get('role') ?? '') } });
  result.replaceChildren(
    `The API token ${t.name} (${t.role}) is made. Its secret shows only now: `,
    el('code', { class: 'secret' }, t.token),
  );
  find('#name', HTMLInputElement).value = '';
  await render();
});

start(async (who) => {
  if (can('tokens')) {
    await render();
    return;
  }
  const notice = find('#admin-only', HTMLElement);
  notice.textContent = `Managing the API tokens needs the role admin, and the token ${who.name} has the role ${who.role}.`;
  notice.hidden = false;
});
