// @ts-check
// The kind of the links between the Nodes of a VRF (SDN-76): noise, the Noise session, or vxlan or
// geneve, plain on a network that the operator trusts. The UI marks a plain link as unencrypted, as
// information and not as a refusal: the operator chose it and may put IPsec or MACsec under it.

import { el } from './dom.js';

/**
 * linkCell returns the cell of the kind of the links of the VRF of spec: "noise (encrypted)", or the
 * kind, its VNI and that it is unencrypted. A VRF that names no kind is of kind noise, and one of kind
 * vxlan or geneve that names no VNI carries its id.
 * @param {Record<string, any> | undefined} spec
 * @returns {HTMLElement | string}
 */
export function linkCell(spec) {
  const kind = String(spec?.link ?? '').toLowerCase();
  if (kind !== 'vxlan' && kind !== 'geneve') {
    return 'noise (encrypted)';
  }
  const vni = spec?.vni ?? spec?.id;
  return el('span', { class: 'unencrypted', title: 'A plain link: no Noise and no encryption of Ranz, for a network that the operator trusts' },
    `${kind} on VNI ${vni}, unencrypted`);
}
