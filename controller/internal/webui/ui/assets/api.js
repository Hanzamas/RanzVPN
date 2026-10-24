// @ts-check
// The web UI's client of the controller's public API (ADR-0031 decision 10). Every call the UI
// makes goes through call, by the name of a UI action in actions.json: the one table of the API
// calls the UI makes, each with the least role it needs. No other module calls fetch, so the UI
// can reach nothing but the public API (webui_test.go checks it).

/** @typedef {'viewer' | 'operator' | 'admin'} Role */

/**
 * A UI action: the API call it makes and the least role that call needs, the role api.Needs
 * gives it.
 * @typedef {object} Action
 * @property {string} name
 * @property {string} method
 * @property {string} path - an http.ServeMux pattern: {placeholders} take the params of call
 * @property {Role} role
 */

/**
 * The API token the UI calls with, as the action whoami answers it.
 * @typedef {object} Who
 * @property {string} name
 * @property {Role} role
 */

/**
 * @typedef {object} CallOptions
 * @property {Record<string, string | number>} [params] - fill the {placeholders} of the path
 * @property {Record<string, string | number | undefined>} [query] - the query string; empty values are left out
 * @property {unknown} [body] - sent as JSON
 * @property {boolean} [blob] - the answer is a file: call returns {blob, filename} and not JSON
 */

/** The roles from the lowest, as internal/rbac orders them. */
const roles = ['viewer', 'operator', 'admin'];

/** Where the tab keeps the token: sessionStorage, so it ends with the tab. */
const tokenKey = 'ranz.apiToken';

/**
 * allows reports whether a token of the role have may make a call that needs the role need, as
 * rbac.Role.Allows does.
 * @param {string} have
 * @param {string} need
 * @returns {boolean}
 */
export function allows(have, need) {
  const n = roles.indexOf(need);
  return n >= 0 && roles.indexOf(have) >= n;
}

/** @type {Promise<Map<string, Action>> | undefined} */
let table;

/**
 * actions returns the action table, by name.
 * @returns {Promise<Map<string, Action>>}
 */
export function actions() {
  table ??= fetch('/assets/actions.json', { headers: { Accept: 'application/json' } }).then(async (r) => {
    if (!r.ok) {
      throw new Error(`the action table could not be loaded: ${r.status} ${r.statusText}`);
    }
    /** @type {{actions: Action[]}} */
    const t = await r.json();
    return new Map(t.actions.map((a) => /** @type {[string, Action]} */ ([a.name, a])));
  });
  return table;
}

/** An answer of the API that is not 200 OK, with the error of its Problem. */
export class APIError extends Error {
  /**
   * @param {number} status
   * @param {string} message
   */
  constructor(status, message) {
    super(message);
    this.name = 'APIError';
    this.status = status;
  }
}

/** @returns {string} the token of the tab, empty when it has none */
export function token() {
  try {
    return sessionStorage.getItem(tokenKey) ?? '';
  } catch {
    return '';
  }
}

/** @param {string} secret - the token the tab calls with from now on; empty forgets it */
export function setToken(secret) {
  try {
    if (secret) {
      sessionStorage.setItem(tokenKey, secret);
    } else {
      sessionStorage.removeItem(tokenKey);
    }
  } catch {
    // Without storage the token lasts until the next page, which then asks for it again.
  }
}

/**
 * fileName returns the name that the Content-Disposition header of an answer gives its file, or
 * the name of a diagnostics bundle when it gives none.
 * @param {string | null} disposition
 * @returns {string}
 */
function fileName(disposition) {
  const m = /filename="([^"\\/]+)"/.exec(disposition ?? '');
  return m ? m[1] : 'ranz-diagnostics.zip';
}

/**
 * call makes the API call of the action name with the token of the tab and returns the JSON of
 * the answer, or, for a call with the option blob, the file that the answer is. An answer other
 * than 200 OK throws an APIError with the API's own message, so the UI shows a refusal exactly as
 * the API words it.
 * @param {string} name
 * @param {CallOptions} [opts]
 * @returns {Promise<any>}
 */
export async function call(name, opts = {}) {
  const a = (await actions()).get(name);
  if (!a) {
    throw new Error(`the web UI has no action ${name}`);
  }
  let url = a.path.replace(/\{(\w+)\}/g, (_, key) => {
    const v = opts.params?.[key];
    if (v === undefined) {
      throw new Error(`the action ${name} needs the parameter ${key}`);
    }
    return encodeURIComponent(String(v));
  });
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(opts.query ?? {})) {
    if (v !== undefined && v !== '') {
      q.set(k, String(v));
    }
  }
  if (q.toString()) {
    url += `?${q}`;
  }
  /** @type {Record<string, string>} */
  const headers = { Accept: opts.blob ? 'application/zip, application/json' : 'application/json' };
  const secret = token();
  if (secret) {
    headers.Authorization = `Bearer ${secret}`;
  }
  /** @type {RequestInit} */
  const init = { method: a.method, headers, cache: 'no-store', credentials: 'omit' };
  if (opts.body !== undefined) {
    headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(opts.body);
  }
  const r = await fetch(url, init);
  if (opts.blob && r.ok) {
    return { blob: await r.blob(), filename: fileName(r.headers.get('Content-Disposition')) };
  }
  const text = await r.text();
  /** @type {any} */
  let data = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = null;
  }
  if (!r.ok) {
    const message = data && typeof data.error === 'string' ? data.error : `${r.status} ${r.statusText}`;
    throw new APIError(r.status, message);
  }
  return data;
}
