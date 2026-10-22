// @ts-check
// The VRFs page (/vrfs): the VRF resources of the Intent, with their Networks and the Nodes that
// join them.

import { start } from './page.js';
import { el, find } from './dom.js';
import { RanzTable } from './components.js';
import { deleteButton, loadResources } from './resources.js';

/** The MTU of a VRF that declares none (intent.DefaultMTU). */
const defaultMTU = 1280;

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
    { label: '', cell: (r) => deleteButton('VRF', r.name, render) },
  ], of('VRF'), 'The Intent has no VRF yet.');
}

start(render);
