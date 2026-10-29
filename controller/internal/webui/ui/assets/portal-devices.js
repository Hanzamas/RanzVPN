// @ts-check
// The My devices page of the portal (/portal): the User and the devices that are its own, each with how it
// stands and a button that removes it, and the form that adds one by the static key that the device shows
// (SDN-58). A device of another User is never in the list: the controller answers the calls of this page about
// the User of the token and nobody else.

import { call, confirm, onClick, onSubmit, start } from './portal.js';
import { el, facts, find, when } from './dom.js';
import { RanzTable } from './components.js';

/** @typedef {import('./portal-types.js').SelfInfo} SelfInfo */
/** @typedef {import('./portal-types.js').SelfDevice} SelfDevice */
/** @typedef {import('./portal-types.js').Enrolment} Enrolment */

const result = find('#result', HTMLOutputElement);

/** What each state of a device says to its User. */
const states = new Map([
  ['connected', 'Connected'],
  ['offline', 'Offline'],
  ['expired', 'The key of the device ended: sign in on the device again (ranz node login) to refresh it'],
  ['pending', 'Waits for an administrator to approve it'],
  ['banned', 'Held back by an operator'],
  ['unlicensed', 'Beyond the licence of this controller'],
]);

/**
 * account shows the User, and how many devices it has of how many it may.
 * @param {SelfInfo} self
 */
function account(self) {
  const devices = self.maxDevices ? `${self.devices} of ${self.maxDevices}` : String(self.devices);
  find('#account', HTMLElement).replaceChildren(facts([
    ['User', self.name],
    ['Name', self.displayName],
    ['Groups', self.groups?.join(', ')],
    ['Devices', devices],
    ['Expires', when(self.expires)],
  ]));
}

/**
 * networks returns the cell of the addresses of a device, each with its Network.
 * @param {SelfDevice} d
 * @returns {import('./dom.js').Child}
 */
function networks(d) {
  const addresses = (d.addresses ?? []).map((a) => `${a.address} (${a.network})`);
  return addresses.length > 0 ? addresses.join(', ') : el('span', { class: 'none' }, 'none yet');
}

/**
 * status returns the cell of how a device stands: what its state says, and for a WireGuard Device the last
 * handshake of its gateway.
 * @param {SelfDevice} d
 * @returns {import('./dom.js').Child}
 */
function status(d) {
  if (d.kind === 'Device') {
    return d.lastHandshake ? `Last handshake ${when(d.lastHandshake)}` : el('span', { class: 'none' }, 'No handshake yet');
  }
  const text = states.get(d.state ?? '') ?? d.state ?? '';
  const connected = d.connected && d.connectedSince ? ` since ${when(d.connectedSince)}` : '';
  return el('span', { class: d.state === 'connected' ? 'yes' : '' }, text + connected);
}

async function render() {
  /** @type {SelfInfo} */
  const self = await call('self');
  account(self);
  /** @type {{devices: SelfDevice[] | null}} */
  const l = await call('selfDevices');
  find('#devices', RanzTable).render([
    { label: 'Name', cell: (d) => d.name },
    { label: 'Type', cell: (d) => (d.kind === 'Device' ? 'WireGuard' : 'ranz node') },
    { label: 'Status', cell: status },
    { label: 'Addresses', cell: networks },
    { label: 'Tags', cell: (d) => (d.tags ?? []).join(', ') },
    { label: 'Key ends', cell: (d) => (d.keyExpires ? when(d.keyExpires) : '') },
    {
      label: '',
      cell: (d) => {
        const b = el('button', { type: 'button', class: 'danger small', 'data-action': 'removeSelfDevice' }, 'Remove');
        onClick(b, async () => {
          if (!(await confirm(`Remove the device ${d.name}? It leaves the network at once, and you can add it again.`, 'Remove'))) {
            return;
          }
          await call('removeSelfDevice', { params: { kind: d.kind, name: d.name } });
          result.replaceChildren(`The device ${d.name} is removed.`);
          await render();
        });
        return b;
      },
    },
  ], l.devices ?? [], 'You have no device yet.');
}

onSubmit(find('#add-form', HTMLFormElement), async (data) => {
  const name = String(data.get('name') ?? '').trim();
  /** @type {Enrolment} */
  const e = await call('addSelfDevice', { body: { publicKey: String(data.get('publicKey') ?? '').trim(), name: name || undefined } });
  result.replaceChildren(`The device ${e.node} is added. On the device, run ranz node login -server ${location.origin} so that it joins this network.`);
  find('#device-name', HTMLInputElement).value = '';
  find('#device-key', HTMLInputElement).value = '';
  await render();
});

start(render);
