// @ts-check
// DOM helpers of the web UI. Text from the API only ever becomes text nodes (el, textContent),
// never markup, so nothing the controller stores can run as script in the UI.

/** @typedef {Node | string | number | null | undefined | false} Child */

/**
 * el creates the element tag with the attributes attrs and the children, skipping the children
 * that are null, undefined or false.
 * @template {keyof HTMLElementTagNameMap} K
 * @param {K} tag
 * @param {Record<string, string>} [attrs]
 * @param {...Child} children
 * @returns {HTMLElementTagNameMap[K]}
 */
export function el(tag, attrs = {}, ...children) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    e.setAttribute(k, v);
  }
  for (const c of children) {
    if (c !== null && c !== undefined && c !== false) {
      e.append(typeof c === 'number' ? String(c) : c);
    }
  }
  return e;
}

/**
 * find returns the element that selector selects in root, which must be of type.
 * @template {Element} T
 * @param {string} selector
 * @param {new () => T} type
 * @param {ParentNode} [root]
 * @returns {T}
 */
export function find(selector, type, root = document) {
  const e = root.querySelector(selector);
  if (!(e instanceof type)) {
    throw new Error(`the page has no ${type.name} ${selector}`);
  }
  return e;
}

/**
 * when returns the time t of the API (RFC 3339) as the browser's locale writes it.
 * @param {string | undefined} t
 * @returns {string}
 */
export function when(t) {
  if (!t) {
    return '';
  }
  const d = new Date(t);
  return Number.isNaN(d.getTime()) ? t : d.toLocaleString();
}

/**
 * json returns v as indented JSON in a <pre>.
 * @param {unknown} v
 * @returns {HTMLPreElement}
 */
export function json(v) {
  return el('pre', { class: 'json' }, JSON.stringify(v, null, 2));
}

/**
 * facts returns a definition list of the pairs whose value is not empty.
 * @param {[string, Child][]} pairs
 * @returns {HTMLDListElement}
 */
export function facts(pairs) {
  const dl = el('dl', { class: 'facts' });
  for (const [term, value] of pairs) {
    if (value !== null && value !== undefined && value !== false && value !== '') {
      dl.append(el('dt', {}, term), el('dd', {}, value));
    }
  }
  return dl;
}

/**
 * yesNo returns a cell that says yes or no.
 * @param {boolean | undefined} b
 * @returns {HTMLSpanElement}
 */
export function yesNo(b) {
  return el('span', { class: b ? 'yes' : 'no' }, b ? 'yes' : 'no');
}
