/** GitHub invitation tokens stay in the URL fragment until an explicit sign-in. */
import { teamRequest } from './team-client.js';
import { githubSetup, bindGithubSetup, beginGithub } from './github-setup.js';
import { $ } from './dom.js';
const invite = new URLSearchParams(location.hash.slice(1)).get('invite');
if (invite) $('h1').textContent = 'Join your team with GitHub';
async function refresh() {
  const session = await teamRequest('session');
  $('#login-submit').disabled = !session.github_configured;
  $('#github-setup').innerHTML = githubSetup(session);
  if (session.can_bootstrap)
    bindGithubSetup(refresh, (message) => ($('#login-error').textContent = message));
  if (!session.github_configured && !session.can_bootstrap)
    $('#login-error').textContent =
      'The installation administrator needs to configure GitHub sign-in.';
}
try {
  await refresh();
} catch (error) {
  $('#login-error').textContent = error.message;
}
$('#login-submit').onclick = async () => {
  try {
    await beginGithub(invite);
  } catch (error) {
    $('#login-error').textContent = error.message;
  }
};
