// @ts-check
// The shared parts of the web UI's pages, as Web Components (ADR-0038 decision 1): the
// navigation with the sign-in state, the problem area, tables and the confirmation dialog.

import { el } from './dom.js';
import { setToken } from './api.js';

/** The pages of the UI, in the order of the navigation. */
const areas = [
  { href: '/', label: 'Overview' },
  { href: '/vrfs', label: 'VRFs' },
  { href: '/networks', label: 'Networks' },
  { href: '/nodes', label: 'Nodes' },
  { href: '/intent', label: 'Intent' },
  { href: '/revisions', label: 'Revisions' },
  { href: '/events', label: 'Events' },
  { href: '/licence', label: 'Licence' },
  // Only an admin may list the API tokens, so only an admin sees the page.
  { href: '/tokens', label: 'API tokens', action: 'tokens' },
];

/**
 * <ranz-nav>: the navigation between the pages, and who the tab is signed in as with the button
 * that signs out. Signing out forgets the token in the tab; it calls nothing, as the API keeps no
 * sign-in to end.
 */
export class RanzNav extends HTMLElement {
  connectedCallback() {
    if (this.firstChild) {
      return;
    }
    const links = el('ul');
    for (const a of areas) {
      const link = el('a', { href: a.href }, a.label);
      if (a.href === location.pathname) {
        link.setAttribute('aria-current', 'page');
      }
      const item = el('li', {}, link);
      if (a.action) {
        item.dataset.action = a.action;
      }
      links.append(item);
    }
    this.append(
      el('nav', { 'aria-label': 'Areas' }, el('a', { href: '/', class: 'brand' }, 'Ranz controller'), links),
      el('div', { class: 'who' }),
    );
  }

  /** @param {import('./api.js').Who} who - the token the tab calls with */
  set who(who) {
    const box = this.querySelector('.who');
    if (!box) {
      return;
    }
    const out = el('button', { type: 'button', class: 'quiet' }, 'Sign out');
    out.addEventListener('click', () => {
      setToken('');
      location.assign('/sign-in');
    });
    box.replaceChildren(el('span', { class: 'token' }, who.name), ' ', el('span', { class: 'role' }, who.role), ' ', out);
  }
}

/** <ranz-problem>: where a page shows what went wrong, in the words of the API. */
export class RanzProblem extends HTMLElement {
  /** @param {unknown} err */
  show(err) {
    const message = err instanceof Error ? err.message : String(err);
    this.replaceChildren(el('p', { role: 'alert' }, message));
  }

  clear() {
    this.replaceChildren();
  }
}

/**
 * A column of a <ranz-table>.
 * @template R
 * @typedef {object} Column
 * @property {string} label
 * @property {(row: R) => import('./dom.js').Child} cell
 */

/** <ranz-table>: a table of rows, one column per Column. */
export class RanzTable extends HTMLElement {
  /**
   * render shows rows in the columns, or the text empty when there are none.
   * @template R
   * @param {Column<R>[]} columns
   * @param {R[]} rows
   * @param {string} empty
   */
  render(columns, rows, empty) {
    if (rows.length === 0) {
      this.replaceChildren(el('p', { class: 'empty' }, empty));
      return;
    }
    const head = el('tr', {}, ...columns.map((c) => el('th', { scope: 'col' }, c.label)));
    const body = rows.map((r) => el('tr', {}, ...columns.map((c) => el('td', {}, c.cell(r)))));
    this.replaceChildren(el('div', { class: 'scroll' }, el('table', {}, el('thead', {}, head), el('tbody', {}, ...body))));
  }
}

/** <ranz-confirm>: a modal dialog that asks before a change. */
export class RanzConfirm extends HTMLElement {
  /**
   * ask shows message and resolves to true when the user chooses ok, false otherwise.
   * @param {string} message
   * @param {string} ok - the label of the button that goes ahead
   * @returns {Promise<boolean>}
   */
  ask(message, ok) {
    const form = el('form', { method: 'dialog' },
      el('p', {}, message),
      el('div', { class: 'buttons' },
        el('button', { value: 'cancel', class: 'quiet' }, 'Cancel'),
        el('button', { value: 'ok', class: 'danger' }, ok)));
    const dialog = el('dialog', {}, form);
    this.replaceChildren(dialog);
    return new Promise((resolve) => {
      dialog.addEventListener('close', () => {
        resolve(dialog.returnValue === 'ok');
        dialog.remove();
      }, { once: true });
      dialog.showModal();
    });
  }
}

customElements.define('ranz-nav', RanzNav);
customElements.define('ranz-problem', RanzProblem);
customElements.define('ranz-table', RanzTable);
customElements.define('ranz-confirm', RanzConfirm);
