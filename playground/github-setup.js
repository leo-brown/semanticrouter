/** Installation-only OAuth setup; secrets go to the private server database. */
import { $, esc } from './dom.js';
import { teamRequest } from './team-client.js';
export function githubSetup(session) {
  if (!session.can_bootstrap) return '';
  const create = new URL('https://github.com/settings/applications/new');
  create.searchParams.set('oauth_application[name]', 'SemanticRouter');
  create.searchParams.set('oauth_application[url]', new URL('./', location.href).href);
  create.searchParams.set('oauth_application[callback_url]', session.callback_url);
  return `<details${session.github_configured ? '' : ' open'}><summary>GitHub sign-in setup</summary><p class="helper">Register an OAuth app, then enter its credentials here.</p><a class="text-button" href="${esc(create.href)}" target="_blank" rel="noopener noreferrer">Register OAuth app on GitHub ↗</a><form id="github-setup-form"><label class="field">Callback URL<input id="github-callback" readonly value="${esc(session.callback_url)}"></label><label class="field">Client ID<input id="github-client-id" required autocomplete="off"></label><label class="field">Client Secret<input id="github-client-secret" type="password" required autocomplete="new-password"></label><button class="button">Save GitHub configuration</button></form></details>`;
}
export function bindGithubSetup(refresh, report) {
  const form = $('#github-setup-form');
  if (!form) return;
  form.onsubmit = async (event) => {
    event.preventDefault();
    try {
      await teamRequest('configure_github', {
        client_id: $('#github-client-id').value.trim(),
        client_secret: $('#github-client-secret').value,
        callback_url: $('#github-callback').value,
      });
      $('#github-client-secret').value = '';
      await refresh();
    } catch (error) {
      report(error.message);
    }
  };
}
export async function beginGithub(invite) {
  const { url } = await teamRequest('oauth_start', invite ? { invite } : {});
  const target = new URL(url);
  if (
    target.origin !== 'https://github.com' ||
    target.pathname !== '/login/oauth/authorize'
  )
    throw new Error('Invalid GitHub sign-in URL.');
  location.assign(url);
}
