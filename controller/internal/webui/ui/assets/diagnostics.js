// @ts-check
// The Diagnostics page (/diagnostics): an operator pulls the diagnostics bundle of the controller,
// one ZIP archive with its logs, its configuration and its status and no secret (SDN-54). The
// browser saves the archive as a file; the page only says that it is made.

import { call, can, onClick, start } from './page.js';
import { el, find } from './dom.js';

/** How long the address of the archive stays valid after the click that saves it. */
const saveSpan = 60_000;

onClick(find('#bundle-button', HTMLButtonElement), async () => {
  const { blob, filename } = await call('diagnosticsBundle', { blob: true });
  const address = URL.createObjectURL(blob);
  const link = el('a', { href: address, download: filename, hidden: '' });
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(address), saveSpan);
  find('#result', HTMLOutputElement).replaceChildren(`The diagnostics bundle ${filename} is made: ${Math.ceil(blob.size / 1024)} KiB, saved by the browser.`);
});

start(async (who) => {
  if (can('diagnosticsBundle')) {
    return;
  }
  const notice = find('#operator-only', HTMLElement);
  notice.textContent = `Pulling the diagnostics bundle needs the role operator, and the token ${who.name} has the role ${who.role}.`;
  notice.hidden = false;
});
