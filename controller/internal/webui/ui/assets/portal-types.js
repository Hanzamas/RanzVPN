// @ts-check
// The JSON that the calls of the portal answer, as JSDoc types for the type check of CI (tsc --noEmit): the
// self calls of a User and its sign-in (SDN-58). Each type names the Go type of the controller it mirrors.

/**
 * login.SignedIn: the answer of a sign-in for the scope self. The times are RFC 3339.
 * @typedef {object} SignedIn
 * @property {string} name - user:NAME, the name of the token
 * @property {string} role - self
 * @property {string} user
 * @property {string} token - the secret, which the portal keeps in the tab
 * @property {string} expires
 */

/**
 * controller.SelfInfo: the User as the portal shows it.
 * @typedef {object} SelfInfo
 * @property {string} name
 * @property {string} [displayName]
 * @property {string[]} [groups]
 * @property {string} [expires] - when the User cannot sign in any more, left out for none
 * @property {number} [maxDevices] - left out for no limit
 * @property {number} devices - how many devices the User has
 */

/**
 * controller.SelfAddress: the address of a device in one Network.
 * @typedef {object} SelfAddress
 * @property {string} network
 * @property {string} address
 */

/**
 * controller.SelfDevice: one device of the User, a Node or a WireGuard Device, with how it stands. The times are
 * RFC 3339 and left out while there is none.
 * @typedef {object} SelfDevice
 * @property {string} kind - Node or Device
 * @property {string} name
 * @property {string} [state] - connected, offline, expired, pending, banned or unlicensed
 * @property {boolean} connected
 * @property {string} [connectedSince]
 * @property {number} [generation]
 * @property {number} [ackedGeneration]
 * @property {string} [keyExpires]
 * @property {string[]} [vrfs]
 * @property {string[]} [tags]
 * @property {SelfAddress[]} [addresses]
 * @property {string} [lastHandshake]
 */

/**
 * controller.Enrolment: the Node that an added device is.
 * @typedef {object} Enrolment
 * @property {string} node
 * @property {string} user
 * @property {number} revision
 */

/**
 * controller.JoinTokenInfo: a join token that waits for a device, never with its secret.
 * @typedef {object} JoinTokenInfo
 * @property {string} id
 * @property {string} [name] - the name that the Node of the device takes, left out for a name that the controller draws
 * @property {string} created
 * @property {string} expires
 */

/**
 * controller.NewJoinToken: a join token just made, with its secret, which shows once.
 * @typedef {JoinTokenInfo & {token: string}} NewJoinToken
 */

export {};
