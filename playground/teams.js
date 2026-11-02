/** Team UI keeps remote workspaces separate from browser-local records. Publishing
 * is explicit; signing in alone never shares the bundled BF snapshot with a team.
 */
import { $, esc, notify } from './dom.js';
import { state, clone } from './state.js';
import { teamRequest } from './team-client.js';
import { githubSetup, bindGithubSetup, beginGithub } from './github-setup.js';
let controller,
  session = null,
  selectedTeam = null;
export function activeTeam() {
  return selectedTeam;
}
export async function openTeams() {
  $('#team-dialog').showModal();
  if (!document.body.dataset.teamApi) {
    $('#team-content').innerHTML =
      '<p>Shared teams need the PHP deployment. Local workspaces and file import/export remain available.</p>';
    return;
  }
  await refreshTeamPanel();
}
async function refreshTeamPanel() {
  try {
    session = await teamRequest('session');
    if (!session.storage_available)
      throw new Error(
        'Team storage is not configured on this server. Configure a private SQLite or MySQL database.',
      );
    const teams = session.teams || [];
    if (!teams.some((team) => team.id === selectedTeam))
      selectedTeam = teams[0]?.id || null;
    const signedIn = Boolean(session.user);
    $('#team-access').textContent = signedIn
      ? '♧ ' +
        (teams.find((team) => team.id === selectedTeam)?.name ||
          session.user.github_login)
      : '♧ Team & login';
    $('#team-content').innerHTML = signedIn
      ? `<p>Signed in as <strong>${esc(session.user.github_login)}</strong></p><label class="field">Team<select id="team-select">${teams.map((team) => `<option value="${esc(team.id)}"${team.id === selectedTeam ? ' selected' : ''}>${esc(team.name)} · ${esc(team.role)}</option>`).join('')}</select></label><div id="team-workspace-list"></div><form id="team-save-form"><label class="field">Workspace name<input id="team-workspace-name" value="${esc(state.workspace.name)}" required maxlength="100"></label><button class="button primary">Save current workspace to team</button></form><details><summary>Invite a teammate / create a team</summary><form id="team-invite-form"><label class="field">GitHub username<input id="invite-login" required></label><button class="button">Create invitation link</button></form><p id="invite-output" class="helper"></p><form id="team-create-form"><label class="field">New team name<input id="team-name" required maxlength="100"></label><button class="button">Create team</button></form></details><button id="team-logout" class="text-button">Sign out</button>`
      : `<p>Sign in with GitHub to create a team, share workspaces and sync config repositories.</p><button id="team-github-login" class="button primary" ${session.github_configured ? '' : 'disabled'}>Sign in with GitHub</button>${!session.github_configured ? '<p class="helper">GitHub sign-in needs the installation’s OAuth app configuration.</p>' : ''}${githubSetup(session)}`;
    $('#team-error').textContent = '';
    if (!signedIn) {
      $('#team-github-login').onclick = async () => {
        try {
          await beginGithub();
        } catch (error) {
          $('#team-error').textContent = error.message;
        }
      };
      if (session.can_bootstrap)
        bindGithubSetup(
          refreshTeamPanel,
          (message) => ($('#team-error').textContent = message),
        );
      return;
    }
    $('#team-select').onchange = async () => {
      selectedTeam = $('#team-select').value;
      await refreshWorkspaceList();
    };
    $('#team-save-form').onsubmit = (event) =>
      formAction(event, async () => {
        if (!selectedTeam) throw new Error('Choose or create a team first.');
        const same =
          state.workspace.scope === 'team' && state.workspace.teamId === selectedTeam;
        if (same) {
          state.workspace.name = $('#team-workspace-name').value;
          await controller.save();
          await refreshWorkspaceList();
          notify('Workspace saved to the team.');
          return;
        }
        await controller.save();
        const payload = {
          team_id: selectedTeam,
          name: $('#team-workspace-name').value,
          snapshot: controller.capture(),
          revision: same ? state.workspace.remoteRevision : 0,
          ...(same ? { id: state.workspace.remoteId } : {}),
        };
        const { workspace } = await teamRequest('save_workspace', payload);
        await controller.openRecord(remoteRecord(workspace, selectedTeam), {
          stash: false,
        });
        await refreshWorkspaceList();
        notify('Workspace saved to the team.');
      });
    $('#team-invite-form').onsubmit = (event) =>
      formAction(event, async () => {
        const { token } = await teamRequest('invite', {
          team_id: selectedTeam,
          github_login: $('#invite-login').value,
        });
        const url = new URL('login.php', location.href);
        url.hash = 'invite=' + token;
        $('#invite-output').innerHTML =
          `<label class="field">Invitation link<input readonly value="${esc(url.href)}" aria-label="Invitation link"></label><span>Share this link with the invited GitHub user. It expires in seven days.</span>`;
      });
    $('#team-create-form').onsubmit = (event) =>
      formAction(event, async () => {
        const { team } = await teamRequest('create_team', {
          name: $('#team-name').value,
        });
        selectedTeam = team.id;
        await refreshTeamPanel();
      });
    $('#team-logout').onclick = async () => {
      try {
        await teamRequest('logout');
        location.reload();
      } catch (error) {
        $('#team-error').textContent = error.message;
      }
    };
    await refreshWorkspaceList();
  } catch (error) {
    $('#team-error').textContent = error.message;
  }
}
async function formAction(event, action) {
  event.preventDefault();
  const buttons = event.target.querySelectorAll('button');
  buttons.forEach((button) => (button.disabled = true));
  try {
    await action();
  } catch (error) {
    $('#team-error').textContent = error.message;
  } finally {
    buttons.forEach((button) => (button.disabled = false));
  }
}
function remoteRecord(workspace, teamId) {
  return {
    id: 'team:' + teamId + ':' + workspace.id,
    name: workspace.name,
    scope: 'team',
    teamId,
    remoteId: workspace.id,
    remoteRevision: workspace.revision,
    snapshot: workspace.snapshot,
    baseline: clone(workspace.snapshot),
  };
}
async function refreshWorkspaceList() {
  const container = $('#team-workspace-list');
  if (!selectedTeam) {
    container.innerHTML = '<p>Create a team to save shared workspaces.</p>';
    return;
  }
  const { workspaces } = await teamRequest('workspaces', { team_id: selectedTeam });
  container.innerHTML =
    '<h3>Shared workspaces</h3>' +
    (workspaces
      .map(
        (workspace) =>
          `<button type="button" class="team-workspace" data-team-workspace="${esc(workspace.id)}">${esc(workspace.name)}<small>Revision ${workspace.revision}</small></button>`,
      )
      .join('') || '<p class="helper">No shared workspaces yet.</p>');
  container.querySelectorAll('[data-team-workspace]').forEach(
    (button) =>
      (button.onclick = async () => {
        try {
          const { workspace } = await teamRequest('workspace', {
            team_id: selectedTeam,
            id: button.dataset.teamWorkspace,
          });
          await controller.openRecord(remoteRecord(workspace, selectedTeam));
          $('#team-dialog').close();
          notify('Opened team workspace: ' + workspace.name);
        } catch (error) {
          $('#team-error').textContent = error.message;
        }
      }),
  );
}
export function initializeTeams(workspaces) {
  controller = workspaces;
  $('#team-access').onclick = openTeams;
  $('#close-team').onclick = () => $('#team-dialog').close();
  controller.setRemoteSaver(async (record) => {
    const { workspace } = await teamRequest('save_workspace', {
      team_id: record.teamId,
      id: record.remoteId,
      name: record.name,
      revision: record.remoteRevision,
      snapshot: controller.capture(),
    });
    return { remoteRevision: workspace.revision };
  });
  // Obtain CSRF/session metadata without activating or downloading a team workspace.
  if (document.body.dataset.teamApi)
    teamRequest('session')
      .then((value) => {
        session = value;
        selectedTeam = value.teams?.[0]?.id || null;
        if (value.user)
          $('#team-access').textContent =
            '♧ ' + (value.teams?.[0]?.name || value.user.github_login);
      })
      .catch(() => {});
}
