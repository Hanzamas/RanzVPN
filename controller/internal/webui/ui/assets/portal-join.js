// @ts-check
// The Join tokens page of the portal (/portal-join): the join tokens of the User that wait for a device, each
// with a button that revokes it, and the form that makes one (SDN-58). A join token enrols one device, such as a
// server without a browser, as a device of the User: the secret shows once, when the token is made, and the
// device presents it with its static key.

import { call, confirm, onClick, onSubmit, start } from './portal.js';
import { el, find, when } from './dom.js';
import { RanzTable } from './components.js';

/** @typedef {import('./portal-types.js').JoinTokenInfo} JoinTokenInfo */
/** @typedef {import('./portal-types.js').NewJoinToken} NewJoinToken */

const result = find('#result', HTMLOutputElement);

async function render() {
  /** @type {{tokens: JoinTokenInfo[] | null}} */
  const l = await call('joinTokens');
  find('#tokens', RanzTable).render([
    { label: 'Name of the device', cell: (t) => t.name ?? el('span', { class: 'none' }, 'the controller draws one') },
    { label: 'Made', cell: (t) => when(t.created) },
    { label: 'Ends', cell: (t) => when(t.expires) },
    {
      label: '',
      cell: (t) => {
        const b = el('button', { type: 'button', class: 'danger small', 'data-action': 'revokeJoinToken' }, 'Revoke');
        onClick(b, async () => {
          if (!(await confirm('Revoke this join token? The device that has its secret can no longer join with it.', 'Revoke'))) {
            return;
          }
          await call('revokeJoinToken', { params: { id: t.id } });
          result.replaceChildren('The join token is revoked.');
          await render();
        });
        return b;
      },
    },
  ], l.tokens ?? [], 'No join token waits for a device.');
}

onSubmit(find('#make-form', HTMLFormElement), async (data) => {
  const name = String(data.get('name') ?? '').trim();
  /** @type {NewJoinToken} */
  const t = await call('makeJoinToken', { body: { name: name || undefined } });
  result.replaceChildren(
    'The join token is made. Its secret shows only now, and it enrols one device, once, until ',
    when(t.expires),
    ': ',
    el('code', { class: 'secret' }, t.token),
    ' On the device, run: ',
    el('code', { class: 'command' }, `echo ${t.token} | ranz node join -server ${location.origin}`),
  );
  find('#join-name', HTMLInputElement).value = '';
  await render();
});

start(render);
