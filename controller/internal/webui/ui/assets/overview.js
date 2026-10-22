// @ts-check
// The overview page (/): the controller, the Intent at its latest revision, the nodes and the
// licence in force, each from its own API call.

import { call, start } from './page.js';
import { el, facts, find, when } from './dom.js';

/** @typedef {import('./types.js').Status} Status */
/** @typedef {import('./types.js').Resource} Resource */
/** @typedef {import('./types.js').NodeStatus} NodeStatus */
/** @typedef {import('./types.js').Revision} Revision */
/** @typedef {import('./types.js').LicenceStatus} LicenceStatus */

start(async () => {
  const [status, resources, nodes, revisions, licence] =
    /** @type {[Status, {resources: Resource[]}, {nodes: NodeStatus[]}, {revisions: Revision[] | null}, LicenceStatus]} */ (
      await Promise.all([call('status'), call('resources'), call('nodes'), call('revisions'), call('licence')])
    );

  const caps = status.capabilities;
  const cluster = status.cluster;
  find('#controller', HTMLElement).replaceChildren(facts([
    ['Control address', status.controlAddress],
    ['TLS port', caps.tlsPortFallback ? `${caps.tlsPort} (443 could not be bound)` : String(caps.tlsPort)],
    ['Plain HTTP', caps.plainHttp],
    ['TLS fingerprint', el('code', {}, status.tlsFingerprint)],
    ['Public key', el('code', {}, status.publicKey)],
    ['Cluster member', cluster && `${cluster.member} (${cluster.role})`],
    ['Leader', cluster && cluster.leader && `${cluster.leader}, epoch ${cluster.epoch}`],
  ]));

  /** @type {Map<string, number>} */
  const kinds = new Map();
  for (const r of resources.resources) {
    kinds.set(r.kind, (kinds.get(r.kind) ?? 0) + 1);
  }
  const intent = [...kinds].map(([kind, n]) => /** @type {[string, import('./dom.js').Child]} */ ([kind, String(n)]));
  const latest = (revisions.revisions ?? []).at(-1);
  intent.push(['Revision', latest
    ? el('a', { href: `/revisions?revision=${latest.id}` }, `${latest.id}, ${latest.operation} at ${when(latest.time)}`)
    : 'none yet: the Intent is empty']);
  const waits = latest?.confirm;
  if (waits?.state === 'pending') {
    intent.push(['Waits for confirmation', `until ${when(waits.deadline)}, or the controller rolls it back`]);
  }
  find('#intent', HTMLElement).replaceChildren(facts(intent));

  const all = nodes.nodes;
  const unlicensed = all.filter((n) => n.unlicensed).length;
  find('#nodes', HTMLElement).replaceChildren(facts([
    ['In the Intent', String(all.length)],
    ['Connected', String(all.filter((n) => n.connected).length)],
    ['Beyond the licence', unlicensed > 0 && String(unlicensed)],
  ]), el('p', {}, el('a', { href: '/nodes' }, 'Nodes and their capabilities')));

  find('#licence', HTMLElement).replaceChildren(
    facts([
      ['Tier', licence.tier],
      ['State', licence.state],
      ['Node cap', String(licence.nodes)],
    ]),
    el('p', {}, licence.message),
  );
});
