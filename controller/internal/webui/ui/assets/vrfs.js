// @ts-check
// The VRFs page (/vrfs): the VRF resources of the Intent, with their Networks, the Nodes that
// join them and the route targets that they import and export, and the "connect VRF" shortcut
// (SDN-7), which leaks the routes of two VRFs into each other in one revision.

import { call, onSubmit, start } from './page.js';
import { el, find } from './dom.js';
import { RanzTable } from './components.js';
import { deleteButton, loadResources, report } from './resources.js';

/** @typedef {import('./types.js').ApplyResult} ApplyResult */

/** The MTU of a VRF that declares none (intent.DefaultMTU). */
const defaultMTU = 1280;

/**
 * targets returns a list of route targets of a VRF as text, "none" for none.
 * @param {unknown} list
 * @returns {string}
 */
function targets(list) {
  return Array.isArray(list) && list.length ? list.join(', ') : 'none';
}

/**
 * choose fills the select id of the shortcut with the names of the VRFs and keeps its choice.
 * @param {string} id
 * @param {string[]} names
 */
function choose(id, names) {
  const s = find(id, HTMLSelectElement);
  const kept = s.value;
  s.replaceChildren(...names.map((n) => el('option', { value: n }, n)));
  if (names.includes(kept)) {
    s.value = kept;
  }
}

async function render() {
  const all = await loadResources();
  const of = (/** @type {string} */ kind) => all.filter((r) => r.kind === kind);
  const networks = of('Network');
  const nodes = of('Node');
  find('#vrfs', RanzTable).render([
    { label: 'Name', cell: (r) => r.name },
    { label: 'ID', cell: (r) => r.spec?.id },
    { label: 'ULA', cell: (r) => el('code', {}, r.spec?.ula ?? '') },
    { label: 'MTU', cell: (r) => r.spec?.mtu ?? `${defaultMTU} (default)` },
    {
      label: 'Networks',
      cell: (r) => {
        const own = networks.filter((n) => n.spec?.vrf === r.name);
        return own.length ? el('a', { href: `/networks?vrf=${encodeURIComponent(r.name)}` }, own.map((n) => n.name).join(', ')) : 'none';
      },
    },
    { label: 'Nodes', cell: (r) => nodes.filter((n) => (n.spec?.vrfs ?? []).includes(r.name)).length },
    { label: 'Imports', cell: (r) => targets(r.spec?.importTargets) },
    { label: 'Exports', cell: (r) => targets(r.spec?.exportTargets) },
    { label: '', cell: (r) => deleteButton('VRF', r.name, render) },
  ], of('VRF'), 'The Intent has no VRF yet.');
  const names = of('VRF').map((r) => r.name);
  choose('#vrf-a', names);
  choose('#vrf-b', names);
}

onSubmit(find('#connect-form', HTMLFormElement), async (data) => {
  const a = String(data.get('a') ?? '');
  const b = String(data.get('b') ?? '');
  /** @type {ApplyResult} */
  const res = await call('connect', { body: { vrfs: [a, b] } });
  report(`Connected ${a} and ${b}`, res);
  await render();
});

start(render);
