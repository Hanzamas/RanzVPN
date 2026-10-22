// @ts-check
// The Intent page (/intent): every resource of the Intent, of the kind in ?kind= or of every
// kind, the delete of each, and the apply of an intent document as `ranz apply -f` makes it.

import { call, onSubmit, problem, setState, start, state } from './page.js';
import { el, find, json } from './dom.js';
import { RanzTable } from './components.js';
import { deleteButton, loadResources, report } from './resources.js';

/** @typedef {import('./types.js').Resource} Resource */

const select = find('#kind', HTMLSelectElement);
const doc = find('#document', HTMLTextAreaElement);

/** @type {Resource[]} */
let current = [];

async function render() {
  current = await loadResources();
  const kinds = [...new Set(current.map((r) => r.kind))].sort();
  const kind = state().get('kind') ?? '';
  select.replaceChildren(el('option', { value: '' }, 'every kind'), ...kinds.map((k) => el('option', { value: k }, k)));
  select.value = kinds.includes(kind) ? kind : '';
  find('#resources', RanzTable).render([
    { label: 'Kind', cell: (r) => r.kind },
    { label: 'Name', cell: (r) => r.name },
    { label: 'Spec', cell: (r) => json(r.spec ?? {}) },
    { label: '', cell: (r) => deleteButton(r.kind, r.name, render) },
  ], current.filter((r) => select.value === '' || r.kind === select.value), 'The Intent is empty.');
}

select.addEventListener('change', () => {
  setState({ kind: select.value });
  render().catch(problem);
});

find('#load', HTMLButtonElement).addEventListener('click', () => {
  doc.value = JSON.stringify({ resources: current }, null, 2);
});

onSubmit(find('#apply-form', HTMLFormElement), async (data) => {
  let body;
  try {
    body = JSON.parse(String(data.get('document') ?? ''));
  } catch (err) {
    throw new Error(`The intent document is not JSON: ${err instanceof Error ? err.message : err}`);
  }
  const confirm = String(data.get('confirm') ?? '').trim();
  report('Applied', await call('apply', { body, query: { confirm } }));
  await render();
});

start(render);
