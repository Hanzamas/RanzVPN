// @ts-check
// The Nodes page (/nodes): each Node resource of the Intent with its status and the Capabilities
// its host reported (ADR-0033), from the action nodes.

import { call, start } from './page.js';
import { el, find, yesNo } from './dom.js';
import { RanzTable } from './components.js';
import { deleteButton, loadResources } from './resources.js';

/** @typedef {import('./types.js').NodeStatus} NodeStatus */
/** @typedef {import('./types.js').Capabilities} Capabilities */

/** The Egress tiers by number (capability.Capabilities.EgressTier). */
const tiers = ['none reported', '1, RRAS NAT', '2, WinNAT', '3, proxy'];

/**
 * capability returns the cell of one Capability of a node, or a dash while it reported none.
 * @param {NodeStatus} n
 * @param {(c: Capabilities) => import('./dom.js').Child} f
 * @returns {import('./dom.js').Child}
 */
function capability(n, f) {
  return n.capabilities ? f(n.capabilities) : el('span', { class: 'none' }, 'not reported');
}

async function render() {
  const [specs, status] = await Promise.all([loadResources('Node'), call('nodes')]);
  const spec = new Map(specs.map((r) => /** @type {[string, Record<string, any>]} */ ([r.name, r.spec ?? {}])));
  /** @type {NodeStatus[]} */
  const nodes = status.nodes;
  find('#nodes', RanzTable).render([
    { label: 'Name', cell: (n) => n.name },
    { label: 'VRFs', cell: (n) => (spec.get(n.name)?.vrfs ?? []).join(', ') },
    { label: 'Tags', cell: (n) => (spec.get(n.name)?.tags ?? []).join(', ') },
    {
      label: 'Connected',
      cell: (n) => n.unlicensed ? el('span', { class: 'no' }, 'beyond the licence') : yesNo(n.connected),
    },
    {
      label: 'Generation',
      cell: (n) => n.ackedGeneration === n.generation ? String(n.generation) : `${n.ackedGeneration} of ${n.generation}`,
    },
    { label: 'SKU', cell: (n) => capability(n, (c) => c.sku || 'none reported') },
    { label: 'Architecture', cell: (n) => capability(n, (c) => c.architecture || 'none reported') },
    { label: 'Hyper-V', cell: (n) => capability(n, (c) => yesNo(c.hyperV)) },
    { label: 'LBFO', cell: (n) => capability(n, (c) => yesNo(c.lbfo)) },
    { label: 'SeLow', cell: (n) => capability(n, (c) => yesNo(c.selow)) },
    { label: 'XDP', cell: (n) => capability(n, (c) => yesNo(c.xdp)) },
    { label: 'Egress tier', cell: (n) => capability(n, (c) => tiers[c.egressTier] ?? String(c.egressTier)) },
    { label: 'Port', cell: (n) => capability(n, (c) => c.tlsPortFallback ? '5555 (443 was taken)' : '443') },
    { label: '', cell: (n) => deleteButton('Node', n.name, render) },
  ], nodes, 'The Intent has no Node yet.');
}

start(render);
