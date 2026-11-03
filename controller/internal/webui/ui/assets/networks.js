// @ts-check
// The Networks page (/networks): the Network resources of the Intent, of every VRF or of the one
// in ?vrf=.

import { problem, setState, start, state } from './page.js';
import { el, find } from './dom.js';
import { RanzTable } from './components.js';
import { deleteButton, loadResources } from './resources.js';

const select = find('#vrf', HTMLSelectElement);

async function render() {
  const all = await loadResources();
  const vrfs = all.filter((r) => r.kind === 'VRF').map((r) => r.name);
  const vrf = state().get('vrf') ?? '';
  select.replaceChildren(el('option', { value: '' }, 'every VRF'), ...vrfs.map((v) => el('option', { value: v }, v)));
  select.value = vrfs.includes(vrf) ? vrf : '';
  const rows = all.filter((r) => r.kind === 'Network' && (select.value === '' || r.spec?.vrf === select.value));
  find('#networks', RanzTable).render([
    { label: 'Name', cell: (r) => r.name },
    { label: 'VRF', cell: (r) => r.spec?.vrf },
    { label: 'Mode', cell: (r) => r.spec?.mode ?? 'L3' },
    { label: 'IPv4 pool', cell: (r) => el('code', {}, r.spec?.ipv4Pool ?? '') },
    { label: 'IPv6 pool', cell: (r) => el('code', {}, r.spec?.ipv6Pool ?? '') },
    // TCP splitting (CORE-P2-3): an ACK means that the client node has the data, as the lead of the page says
    { label: 'TCP splitting', cell: (r) => (r.spec?.tcpSplit ? 'on' : 'off') },
    { label: '', cell: (r) => deleteButton('Network', r.name, render) },
  ], rows, select.value ? `The VRF ${select.value} has no Network.` : 'The Intent has no Network yet.');
}

select.addEventListener('change', () => {
  setState({ vrf: select.value });
  render().catch(problem);
});

start(render);
