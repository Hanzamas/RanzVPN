// @ts-check
// The Events page (/events): every event the controller raised, the latest first.

import { call, onClick, start } from './page.js';
import { el, find, when } from './dom.js';
import { RanzTable } from './components.js';

/** @typedef {import('./types.js').ControllerEvent} ControllerEvent */

/**
 * revision links to revision id, or is empty for none.
 * @param {number | undefined} id
 * @returns {import('./dom.js').Child}
 */
function revision(id) {
  return id ? el('a', { href: `/revisions?revision=${id}` }, String(id)) : '';
}

async function render() {
  /** @type {{events: ControllerEvent[] | null}} */
  const l = await call('events');
  const events = l.events ?? [];
  find('#events', RanzTable).render([
    { label: 'Time', cell: (e) => when(e.time) },
    { label: 'Type', cell: (e) => e.type },
    { label: 'Node', cell: (e) => e.node ?? '' },
    { label: 'Subject', cell: (e) => e.subject ?? '' },
    { label: 'Message', cell: (e) => e.message },
    { label: 'Revision', cell: (e) => revision(e.revision) },
    { label: 'Reverts', cell: (e) => revision(e.reverts) },
  ], events.reverse(), 'No event yet.');
}

onClick(find('#refresh', HTMLButtonElement), render);

start(render);
