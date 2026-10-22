// @ts-check
// The Revisions page (/revisions): the history of the Intent with the confirmation and the
// rollback of a revision, one revision with its whole Intent (?revision=N), and the diff between
// two revisions (?from=A&to=B, or the change of the latest revision without them).

import { call, confirm, onClick, onSubmit, setState, start, state } from './page.js';
import { el, facts, find, json, when } from './dom.js';
import { RanzTable } from './components.js';
import { report } from './resources.js';

/** @typedef {import('./types.js').Revision} Revision */
/** @typedef {import('./types.js').DiffResult} DiffResult */

const fromInput = find('#from', HTMLInputElement);
const toInput = find('#to', HTMLInputElement);

/** The number of revisions, as renderList last saw it. */
let count = 0;

/**
 * operation describes how revision r came to be.
 * @param {Revision} r
 * @returns {string}
 */
function operation(r) {
  if (r.operation === 'rollback' && r.restores !== undefined) {
    return `rollback to ${r.restores}`;
  }
  if (r.operation === 'automatic-rollback' && r.reverts) {
    return `automatic rollback of ${r.reverts}`;
  }
  return r.operation;
}

/**
 * actions returns the buttons of the row of revision r: its confirmation while it waits for one,
 * and the rollback to it.
 * @param {Revision} r
 * @returns {HTMLSpanElement}
 */
function actions(r) {
  const box = el('span', { class: 'buttons' });
  if (r.confirm?.state === 'pending') {
    const ok = el('button', { type: 'button', class: 'small', 'data-action': 'confirmRevision' }, 'Confirm');
    onClick(ok, async () => {
      /** @type {Revision} */
      const done = await call('confirmRevision', { params: { id: r.id } });
      find('#result', HTMLOutputElement).replaceChildren(`Revision ${done.id} is confirmed and stays.`);
      await render();
    });
    box.append(ok);
  }
  const back = el('button', { type: 'button', class: 'danger small', 'data-action': 'rollback' }, `Roll back to ${r.id}`);
  onClick(back, async () => {
    if (!(await confirm(`Roll back to revision ${r.id}? Its Intent becomes the Intent again, as a new revision, and the nodes get the matching generation.`, 'Roll back'))) {
      return;
    }
    report(`Rolled back to revision ${r.id}`, await call('rollback', { body: { revision: r.id } }));
    await render();
  });
  box.append(back);
  return box;
}

/** renderList shows the history, the latest revision first. */
async function renderList() {
  /** @type {{revisions: Revision[] | null}} */
  const l = await call('revisions');
  const revisions = l.revisions ?? [];
  find('#revisions', RanzTable).render([
    { label: 'Revision', cell: (r) => el('a', { href: `/revisions?revision=${r.id}` }, String(r.id)) },
    { label: 'Time', cell: (r) => when(r.time) },
    { label: 'Operation', cell: (r) => operation(r) },
    { label: 'Confirmation', cell: (r) => r.confirm ? `${r.confirm.state}, deadline ${when(r.confirm.deadline)}` : '' },
    { label: 'Diff', cell: (r) => el('a', { href: `/revisions?from=${r.id - 1}&to=${r.id}` }, `${r.id - 1} to ${r.id}`) },
    { label: '', cell: (r) => actions(r) },
  ], [...revisions].reverse(), 'No revision yet: the Intent is empty until the first apply.');
  count = revisions.length;
}

/** renderRevision shows the revision in ?revision=, if any. */
async function renderRevision() {
  const id = state().get('revision');
  const section = find('#revision', HTMLElement);
  section.hidden = !id;
  if (!id) {
    return;
  }
  /** @type {Revision} */
  const r = await call('revision', { params: { id } });
  find('#h-revision', HTMLHeadingElement).textContent = `Revision ${r.id}`;
  find('#revision-facts', HTMLElement).replaceChildren(facts([
    ['Time', when(r.time)],
    ['Operation', operation(r)],
    ['Confirmation', r.confirm && `${r.confirm.state}, deadline ${when(r.confirm.deadline)}`],
  ]));
  find('#revision-resources', RanzTable).render([
    { label: 'Kind', cell: (x) => x.kind },
    { label: 'Name', cell: (x) => x.name },
    { label: 'Spec', cell: (x) => json(x.spec ?? {}) },
  ], r.resources ?? [], 'The Intent of this revision is empty.');
}

/** renderDiff shows the diff of ?from= and ?to=, or the change of the latest revision. */
async function renderDiff() {
  const q = state();
  const from = q.get('from') ?? '';
  const to = q.get('to') ?? '';
  if (count === 0 && !from && !to) {
    find('#diff-title', HTMLElement).textContent = 'Nothing to compare yet.';
    find('#changes', HTMLElement).replaceChildren();
    return;
  }
  /** @type {DiffResult} */
  const d = await call('diff', { query: { from, to } });
  fromInput.value = String(d.from);
  toInput.value = String(d.to);
  find('#diff-title', HTMLElement).textContent = `From revision ${d.from} to revision ${d.to}:`;
  find('#changes', RanzTable).render([
    { label: 'Change', cell: (c) => el('span', { class: `change ${c.action}` }, c.action) },
    { label: 'Kind', cell: (c) => c.kind },
    { label: 'Name', cell: (c) => c.name },
    { label: 'Fields', cell: (c) => (c.fields ?? []).join(', ') },
    { label: 'Before', cell: (c) => c.from === undefined ? '' : json(c.from) },
    { label: 'After', cell: (c) => c.to === undefined ? '' : json(c.to) },
  ], d.changes ?? [], 'The two revisions have the same Intent.');
}

async function render() {
  await renderList();
  await Promise.all([renderRevision(), renderDiff()]);
}

onSubmit(find('#diff-form', HTMLFormElement), async () => {
  setState({ revision: state().get('revision') ?? undefined, from: fromInput.value, to: toInput.value });
  await renderDiff();
});

start(render);
