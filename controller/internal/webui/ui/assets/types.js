// @ts-check
// The JSON the API answers, as JSDoc types for the type check of CI (tsc --noEmit). Each type
// names the Go type of the controller it mirrors.

/**
 * intent.Resource
 * @typedef {object} Resource
 * @property {string} kind
 * @property {string} name
 * @property {Record<string, any>} [spec]
 */

/**
 * capability.Capabilities
 * @typedef {object} Capabilities
 * @property {string} sku
 * @property {string} architecture
 * @property {boolean} hyperV
 * @property {boolean} lbfo
 * @property {boolean} selow
 * @property {boolean} xdp
 * @property {number} egressTier
 * @property {boolean} tlsPortFallback
 * @property {boolean} [wireguard] - wireguard.dll loads, so the node can be the gateway of Devices (SDN-80)
 * @property {string} [wireguardKey] - the public key of its WireGuard interface, base64
 */

/**
 * controller.NodeStatus
 * @typedef {object} NodeStatus
 * @property {string} name
 * @property {number} generation
 * @property {number} ackedGeneration
 * @property {boolean} connected
 * @property {Capabilities | null} capabilities
 * @property {boolean} [unlicensed]
 */

/**
 * controller.NodeGeneration
 * @typedef {object} NodeGeneration
 * @property {string} name
 * @property {number} generation
 */

/**
 * controller.ApplyResult
 * @typedef {object} ApplyResult
 * @property {number} revision
 * @property {NodeGeneration[] | null} nodes
 * @property {string} [confirmBy]
 */

/**
 * intent.Confirmation
 * @typedef {object} Confirmation
 * @property {string} deadline
 * @property {string} state
 */

/**
 * intent.Revision
 * @typedef {object} Revision
 * @property {number} id
 * @property {string} time
 * @property {string} operation
 * @property {number} [restores]
 * @property {number} [reverts]
 * @property {Confirmation} [confirm]
 * @property {Resource[]} [resources]
 */

/**
 * intent.Change
 * @typedef {object} Change
 * @property {string} action
 * @property {string} kind
 * @property {string} name
 * @property {string[]} [fields]
 * @property {unknown} [from]
 * @property {unknown} [to]
 */

/**
 * api.DiffResult
 * @typedef {object} DiffResult
 * @property {number} from
 * @property {number} to
 * @property {Change[] | null} changes
 */

/**
 * event.Event (named so it does not hide the DOM's Event)
 * @typedef {object} ControllerEvent
 * @property {number} id
 * @property {string} time
 * @property {string} type
 * @property {string} message
 * @property {number} [revision]
 * @property {number} [reverts]
 * @property {string} [node] - the node the event is about, or the node that reported it
 * @property {string} [subject] - what else it is about: the gateway of a failover, the peer of a session flap
 */

/**
 * licence.Licence, what an installed licence key holds
 * @typedef {object} Licence
 * @property {string} id
 * @property {string} licensee
 * @property {string} tier
 * @property {number} nodes
 * @property {string} expires
 * @property {string} [fallbackVersion]
 */

/**
 * licence.Status
 * @typedef {object} LicenceStatus
 * @property {string} tier
 * @property {number} nodes
 * @property {string[] | null} features
 * @property {string} state
 * @property {string} version
 * @property {Licence} [key]
 * @property {string} message
 */

/**
 * rbac.Token: the times are RFC 3339 and left out while the token has none (AUD1-DT-13)
 * @typedef {object} Token
 * @property {string} name
 * @property {import('./api.js').Role} role
 * @property {string} [expires] - the instant from which the controller refuses the token
 * @property {boolean} [expired] - the expiry has passed: the token is refused, and an admin can still delete it
 * @property {string} [lastUsed] - when the token last authenticated a call, right to the minute
 */

/**
 * rbac.NewToken: a token with its secret, which the API shows once
 * @typedef {object} NewToken
 * @property {string} name
 * @property {import('./api.js').Role} role
 * @property {string} token
 */

/**
 * controller.DeviceStatus (SDN-80): the times are RFC 3339 and left out while the gateway reported none
 * @typedef {object} DeviceStatus
 * @property {string} name
 * @property {string} network
 * @property {string} gateway
 * @property {string} [address]
 * @property {string} [ipv6Address]
 * @property {string} [owner] - the User that the Device is a device of (SDN-82)
 * @property {boolean} [presharedKey] - the Device has a PresharedKey, which the controller showed once (SDN-82)
 * @property {boolean} [presharedKeyDoesNotOpen] - the controller cannot open that PresharedKey, so the gateway terminates the Device without it (SDN-82-R1)
 * @property {string} [lastHandshake]
 * @property {number} txBytes
 * @property {number} rxBytes
 * @property {string} [reported]
 * @property {boolean} [unlicensed]
 */

/**
 * controller.DeviceRequest (SDN-82): the Device that an administrator asks the controller to make. The
 * controller makes the key pair and the PresharedKey of the Device, unless publicKey and noPresharedKey say
 * otherwise.
 * @typedef {object} DeviceRequest
 * @property {string} name
 * @property {string} network
 * @property {string} gateway
 * @property {string} [owner]
 * @property {string[]} [tags]
 * @property {boolean} [batterySaver]
 * @property {string} [publicKey]
 * @property {boolean} [noPresharedKey]
 */

/**
 * controller.DeviceCreated (SDN-82): what the making of a Device answers, once: its finished WireGuard
 * configuration with the keys that only this answer holds, and the QR code of it as its modules, one string of
 * 1 (dark) and 0 (light) for each row, without the quiet zone
 * @typedef {object} DeviceCreated
 * @property {string} name
 * @property {number} revision
 * @property {NodeGeneration[] | null} nodes
 * @property {string} publicKey
 * @property {boolean} keyMade
 * @property {boolean} presharedKey
 * @property {string} config
 * @property {string[]} qr
 */

/**
 * api.Status
 * @typedef {object} Status
 * @property {string} publicKey
 * @property {string} controlAddress
 * @property {string} tlsFingerprint
 * @property {{tlsPort: number, tlsPortFallback: boolean, plainHttp?: string}} capabilities
 * @property {{member: string, role: string, leader: string, epoch: number, schemaVersion: number}} [cluster]
 */

export {};
