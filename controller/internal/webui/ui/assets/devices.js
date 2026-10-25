// @ts-check
// The Devices page (/devices): each WireGuard Device of the Intent (SDN-80) with its addresses and
// the last handshake and the traffic that its gateway reported, from the action devices.

import { call, start } from './page.js';
import { el, find, when } from './dom.js';
import { RanzTable } from './components.js';
import { deleteButton } from './resources.js';

/** @typedef {import('./types.js').DeviceStatus} DeviceStatus */

/**
 * reported returns the cell of a value that the gateway of d reports, or a dash while it reported none.
 * @param {DeviceStatus} d
 * @param {string} v
 * @returns {import('./dom.js').Child}
 */
function reported(d, v) {
  return d.reported ? v : el('span', { class: 'none' }, 'not reported');
}

async function render() {
  /** @type {{devices: DeviceStatus[] | null}} */
  const l = await call('devices');
  const devices = l.devices ?? [];
  find('#devices', RanzTable).render([
    { label: 'Name', cell: (d) => d.name },
    { label: 'Network', cell: (d) => d.network },
    { label: 'Gateway', cell: (d) => d.unlicensed ? el('span', { class: 'no' }, `${d.gateway}, beyond the licence`) : d.gateway },
    { label: 'Addresses', cell: (d) => [d.address, d.ipv6Address].filter(Boolean).join(', ') },
    { label: 'Last handshake', cell: (d) => reported(d, d.lastHandshake ? when(d.lastHandshake) : 'none yet') },
    { label: 'Sent (bytes)', cell: (d) => reported(d, String(d.txBytes)) },
    { label: 'Received (bytes)', cell: (d) => reported(d, String(d.rxBytes)) },
    { label: 'Reported', cell: (d) => when(d.reported) },
    { label: '', cell: (d) => deleteButton('Device', d.name, render) },
  ], devices, 'The Intent has no Device yet.');
}

start(render);
