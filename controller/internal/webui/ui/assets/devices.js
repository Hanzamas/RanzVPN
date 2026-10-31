// @ts-check
// The Devices page (/devices): each WireGuard Device of the Intent (SDN-80) with its addresses and the last
// handshake and the traffic that its gateway reported, from the action devices; and the making and the
// revoking of a Device (SDN-82). The controller makes the key pair and the PresharedKey of a new Device and
// answers the action createDevice with the finished configuration and the QR code of it, which the page
// shows once: nothing keeps them, leaving the page or the button that clears them forgets them, and the
// controller never shows them again. A viewer sees the list and no form.

import { call, can, confirm, onClick, onSubmit, start } from './page.js';
import { el, find, when, yesNo } from './dom.js';
import { RanzTable } from './components.js';
import { loadResources, report } from './resources.js';

/** @typedef {import('./types.js').DeviceStatus} DeviceStatus */
/** @typedef {import('./types.js').DeviceRequest} DeviceRequest */
/** @typedef {import('./types.js').DeviceCreated} DeviceCreated */
/** @typedef {import('./types.js').NodeStatus} NodeStatus */

/** The quiet zone around a QR code, in modules, and the pixels of one module as the page draws it. */
const quiet = 4;
const moduleSize = 6;

/** How long the address of the saved file stays valid after the click that saves it. */
const saveSpan = 60_000;

const issued = find('#issued', HTMLElement);
const config = find('#config', HTMLPreElement);
const qr = find('#qr', HTMLCanvasElement);
const keysNote = find('#keys-note', HTMLElement);
const makeForm = find('#make-form', HTMLFormElement);

/** The name of the Device whose configuration the page shows, for the file that saves it. */
let issuedName = '';

/**
 * reported returns the cell of a value that the gateway of d reports, or a dash while it reported none.
 * @param {DeviceStatus} d
 * @param {string} v
 * @returns {import('./dom.js').Child}
 */
function reported(d, v) {
  return d.reported ? v : el('span', { class: 'none' }, 'not reported');
}

/**
 * presharedKey returns the cell of the PresharedKey of d: yes or no, or that the controller cannot open it, so
 * that the gateway terminates the Device without it until it opens, or until the Device is made again (SDN-82-R1).
 * @param {DeviceStatus} d
 * @returns {HTMLSpanElement}
 */
function presharedKey(d) {
  return d.presharedKeyDoesNotOpen ? el('span', { class: 'no' }, 'does not open') : yesNo(d.presharedKey);
}

/**
 * drawQR paints the QR code that rows hold on canvas: black modules on white, with the quiet zone that a
 * scanner needs, whatever the theme of the page.
 * @param {HTMLCanvasElement} canvas
 * @param {string[]} rows - one string of 1 (dark) and 0 (light) for each row of the modules
 */
function drawQR(canvas, rows) {
  const side = (rows.length + 2 * quiet) * moduleSize;
  canvas.width = side;
  canvas.height = side;
  const ctx = canvas.getContext('2d');
  if (!ctx) {
    throw new Error('this browser cannot draw the QR code');
  }
  ctx.fillStyle = '#ffffff';
  ctx.fillRect(0, 0, side, side);
  ctx.fillStyle = '#000000';
  rows.forEach((row, y) => {
    for (let x = 0; x < row.length; x++) {
      if (row[x] === '1') {
        ctx.fillRect((x + quiet) * moduleSize, (y + quiet) * moduleSize, moduleSize, moduleSize);
      }
    }
  });
}

/**
 * shownOnce says which keys of the configuration of made show only now.
 * @param {DeviceCreated} made
 * @returns {string}
 */
function shownOnce(made) {
  if (made.keyMade && made.presharedKey) {
    return 'The private key and the PresharedKey in this configuration show only now: the controller keeps no private key, and shows the PresharedKey once. Scan the QR code or save the file before you leave this page.';
  }
  if (made.keyMade) {
    return 'The private key in this configuration shows only now: the controller keeps no private key. Scan the QR code or save the file before you leave this page.';
  }
  if (made.presharedKey) {
    return 'The PresharedKey in this configuration shows only now. The private key stays with the Device: it goes into the line PrivateKey of the configuration. Scan the QR code or save the file before you leave this page.';
  }
  return 'This configuration holds no secret: the private key stays with the Device, and the Device has no PresharedKey.';
}

/** forget clears the configuration that the page showed, which no other place keeps. */
function forget() {
  issued.hidden = true;
  config.replaceChildren();
  keysNote.replaceChildren();
  qr.width = 0;
  qr.height = 0;
  issuedName = '';
}

/**
 * show puts the finished configuration of a new Device and the QR code of it on the page.
 * @param {DeviceCreated} made
 */
function show(made) {
  issuedName = made.name;
  config.textContent = made.config;
  keysNote.textContent = shownOnce(made);
  drawQR(qr, made.qr);
  qr.setAttribute('aria-label', `QR code of the configuration of Device ${made.name}, for the WireGuard app of a phone to scan`);
  issued.hidden = false;
}

/**
 * revokeButton returns the button that revokes the Device name after asking: the delete of its resource,
 * which the next generation of its gateway carries out, and which takes its PresharedKey with it.
 * @param {string} name
 * @returns {HTMLButtonElement}
 */
function revokeButton(name) {
  const b = el('button', { type: 'button', class: 'danger small', 'data-action': 'deleteResource' }, 'Revoke');
  onClick(b, async () => {
    if (!(await confirm(`Revoke the Device ${name}? Its gateway stops terminating it with the next generation, and its PresharedKey goes. The revoke makes a new revision; a rollback brings the Device back without its PresharedKey.`, 'Revoke'))) {
      return;
    }
    report(`Revoked Device ${name}`, await call('deleteResource', { params: { kind: 'Device', name } }));
    await render();
  });
  return b;
}

/** fillForm offers the Networks, the gateways and the Users of the Intent in the form that makes a Device. */
async function fillForm() {
  const [resources, status] = await Promise.all([loadResources(), call('nodes')]);
  /** @type {NodeStatus[]} */
  const nodes = status.nodes;
  const ready = new Set(nodes.filter((n) => n.capabilities?.wireguard).map((n) => n.name));

  /**
   * @param {string} kind
   * @param {(spec: Record<string, any>) => boolean} [keep]
   * @returns {string[]}
   */
  function names(kind, keep = () => true) {
    return resources.filter((r) => r.kind === kind && keep(r.spec ?? {})).map((r) => r.name);
  }

  find('#network', HTMLSelectElement).replaceChildren(
    ...names('Network', (spec) => (spec.mode ?? 'L3') === 'L3').map((n) => el('option', { value: n }, n)),
  );
  // A gateway whose WireGuard interface is not reported yet cannot be chosen: the controller refuses it
  find('#gateway', HTMLSelectElement).replaceChildren(
    ...names('Node', (spec) => Boolean(spec.wireguard)).map((n) => ready.has(n)
      ? el('option', { value: n }, n)
      : el('option', { value: n, disabled: '' }, `${n} (its WireGuard interface is not reported yet)`)),
  );
  find('#owner', HTMLSelectElement).replaceChildren(
    el('option', { value: '' }, 'none: a standalone Device'),
    ...names('User').map((n) => el('option', { value: n }, n)),
  );
}

async function render() {
  /** @type {{devices: DeviceStatus[] | null}} */
  const l = await call('devices');
  const devices = l.devices ?? [];
  find('#devices', RanzTable).render([
    { label: 'Name', cell: (d) => d.name },
    { label: 'Network', cell: (d) => d.network },
    { label: 'Gateway', cell: (d) => d.unlicensed ? el('span', { class: 'no' }, `${d.gateway}, beyond the licence`) : d.gateway },
    { label: 'Owner', cell: (d) => d.owner ?? '' },
    { label: 'Addresses', cell: (d) => [d.address, d.ipv6Address].filter(Boolean).join(', ') },
    { label: 'PresharedKey', cell: (d) => presharedKey(d) },
    { label: 'Last handshake', cell: (d) => reported(d, d.lastHandshake ? when(d.lastHandshake) : 'none yet') },
    { label: 'Sent (bytes)', cell: (d) => reported(d, String(d.txBytes)) },
    { label: 'Received (bytes)', cell: (d) => reported(d, String(d.rxBytes)) },
    { label: 'Reported', cell: (d) => when(d.reported) },
    { label: '', cell: (d) => revokeButton(d.name) },
  ], devices, 'The Intent has no Device yet.');
  if (can('createDevice')) {
    await fillForm();
  }
}

onSubmit(makeForm, async (data) => {
  /** @type {DeviceRequest} */
  const body = {
    name: String(data.get('name') ?? ''),
    network: String(data.get('network') ?? ''),
    gateway: String(data.get('gateway') ?? ''),
  };
  const owner = String(data.get('owner') ?? '');
  if (owner) {
    body.owner = owner;
  }
  const tags = String(data.get('tags') ?? '').split(',').map((t) => t.trim()).filter(Boolean);
  if (tags.length > 0) {
    body.tags = tags;
  }
  const publicKey = String(data.get('publicKey') ?? '').trim();
  if (publicKey) {
    body.publicKey = publicKey;
  }
  if (data.get('batterySaver')) {
    body.batterySaver = true;
  }
  if (data.get('noPresharedKey')) {
    body.noPresharedKey = true;
  }
  /** @type {DeviceCreated} */
  const made = await call('createDevice', { body });
  show(made);
  report(`Made Device ${made.name}`, made);
  makeForm.reset();
  await render();
});

onClick(find('#save', HTMLButtonElement), async () => {
  const address = URL.createObjectURL(new Blob([config.textContent ?? ''], { type: 'text/plain' }));
  const link = el('a', { href: address, download: `${issuedName || 'device'}.conf`, hidden: '' });
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(address), saveSpan);
});

onClick(find('#done', HTMLButtonElement), async () => {
  forget();
});

// A page that the browser keeps for the back button holds no configuration
addEventListener('pagehide', forget);

start(render);
