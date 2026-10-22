// @ts-check
// The Licence page (/licence): the licence in force (ADR-0036), and the install and removal of
// the licence key.

import { call, confirm, onClick, onSubmit, start } from './page.js';
import { el, facts, find, when } from './dom.js';

/** @typedef {import('./types.js').LicenceStatus} LicenceStatus */

/** @param {LicenceStatus} st - the licence in force, which shows */
function show(st) {
  const key = st.key;
  find('#licence', HTMLElement).replaceChildren(
    el('p', {}, st.message),
    facts([
      ['Tier', st.tier],
      ['State', st.state],
      ['Node cap', String(st.nodes)],
      ['Features', (st.features ?? []).join(', ')],
      ['Controller version', st.version],
      ['Licence', key && `${key.id}, sold to ${key.licensee}`],
      ['Key tier and nodes', key && `${key.tier}, ${key.nodes} nodes`],
      ['Expires', key && when(key.expires)],
      ['Fallback licence for', key?.fallbackVersion],
    ]),
  );
  const box = find('#remove-box', HTMLElement);
  box.replaceChildren();
  if (key) {
    const remove = el('button', { type: 'button', class: 'danger', 'data-action': 'removeLicence' }, 'Remove the licence key');
    onClick(remove, async () => {
      if (!(await confirm('Remove the licence key? The Personal tier is in force then.', 'Remove'))) {
        return;
      }
      show(await call('removeLicence'));
      find('#result', HTMLOutputElement).replaceChildren('The licence key is removed.');
    });
    box.append(remove);
  }
}

onSubmit(find('#install-form', HTMLFormElement), async (data) => {
  show(await call('installLicence', { body: { key: String(data.get('key') ?? '').trim() } }));
  find('#key', HTMLTextAreaElement).value = '';
  find('#result', HTMLOutputElement).replaceChildren('The licence key is installed.');
});

start(async () => show(await call('licence')));
