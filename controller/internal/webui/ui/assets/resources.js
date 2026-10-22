// @ts-check
// What the pages of the Intent's resources share: the delete of a resource and the report of a
// change of the Intent.

import { call, confirm, onClick } from './page.js';
import { el, find, when } from './dom.js';

/** @typedef {import('./types.js').Resource} Resource */
/** @typedef {import('./types.js').ApplyResult} ApplyResult */

/**
 * loadResources returns the Intent's resources of kind, or all of them without a kind.
 * @param {string} [kind]
 * @returns {Promise<Resource[]>}
 */
export async function loadResources(kind) {
  /** @type {{resources: Resource[]}} */
  const l = await call('resources');
  return kind ? l.resources.filter((r) => r.kind === kind) : l.resources;
}

/**
 * report shows what a change of the Intent did in the page's <output id="result">: the revision
 * it made and the nodes it sent a new generation.
 * @param {string} what - the change, for example "Applied"
 * @param {ApplyResult} res
 */
export function report(what, res) {
  const nodes = (res.nodes ?? []).map((n) => `${n.name} (generation ${n.generation})`);
  find('#result', HTMLOutputElement).replaceChildren(
    `${what} as `,
    el('a', { href: `/revisions?revision=${res.revision}` }, `revision ${res.revision}`),
    '. ',
    nodes.length ? `A new generation went to ${nodes.join(', ')}.` : 'No node got a new generation.',
    res.confirmBy ? ` Confirm it by ${when(res.confirmBy)}, or the controller rolls it back.` : '',
  );
}

/**
 * deleteButton returns the button that deletes the resource kind/name after asking, and then
 * runs done.
 * @param {string} kind
 * @param {string} name
 * @param {() => Promise<void>} done
 * @returns {HTMLButtonElement}
 */
export function deleteButton(kind, name, done) {
  const b = el('button', { type: 'button', class: 'danger small', 'data-action': 'deleteResource' }, 'Delete');
  onClick(b, async () => {
    if (!(await confirm(`Delete the ${kind} ${name}? The delete makes a new revision, which a rollback undoes.`, 'Delete'))) {
      return;
    }
    report('Deleted', await call('deleteResource', { params: { kind, name } }));
    await done();
  });
  return b;
}
