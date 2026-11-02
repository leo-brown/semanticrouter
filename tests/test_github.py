"""Deterministic OAuth/identity contracts and Git object import without internet."""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]


@unittest.skipUnless(shutil.which("php"), "PHP is required")
class GithubTests(unittest.TestCase):
    def php(self, script, *arguments, env=None):
        result = subprocess.run(
            ["php", "-r", script, str(ROOT / "playground"), *arguments],
            text=True,
            capture_output=True,
            check=True,
            env=env,
        )
        return json.loads(result.stdout)

    def test_pkce_state_is_single_use_and_tokens_do_not_become_profiles(self):
        data = self.php(r"""
require $argv[1].'/server/github.php';
$s = new SemanticRouter\Store(new PDO('sqlite::memory:'));
$s->saveSetting('github',['client_id'=>'example-client-id','client_secret'=>'synthetic-secret-123456','callback_url'=>'https://example.invalid/oauth_callback.php']);
$url=SemanticRouter\oauthStart($s); parse_str(parse_url($url, PHP_URL_QUERY),$params);
$flow=SemanticRouter\consumeOauthState($params['state']);
$replay=false;try{SemanticRouter\consumeOauthState($params['state']);}catch(SemanticRouter\ApiError $e){$replay=true;}
$requests=[];
$transport=function($method,$url,$headers,$body)use(&$requests){$requests[]=[$method,$url,$headers,$body];return $method==='POST'?['access_token'=>'gho_synthetic']:['id'=>42,'login'=>'renamed-user'];};
$github=new SemanticRouter\Github(SemanticRouter\githubConfiguration($s),$transport);
$profile=$github->profile('example-code',$flow['verifier']);
echo json_encode(['replay_rejected'=>$replay,'challenge_matches'=>rtrim(strtr(base64_encode(hash('sha256',$flow['verifier'],true)),'+/','-_'),'=')===$params['code_challenge'],'profile'=>$profile,'verifier_sent'=>$requests[0][3]['code_verifier']===$flow['verifier'],'scope'=>$params['scope']]);
""")
        self.assertTrue(data["replay_rejected"])
        self.assertTrue(data["challenge_matches"])
        self.assertTrue(data["verifier_sent"])
        self.assertEqual(data["scope"], "read:user")
        self.assertEqual(data["profile"], {"id": 42, "login": "renamed-user"})

    def test_invites_bind_stable_ids_and_survive_a_username_change(self):
        data = self.php(r"""
require $argv[1].'/server/storage.php';
$s=new SemanticRouter\Store(new PDO('sqlite::memory:'));
$owner=$s->githubAccount(['id'=>1,'login'=>'owner']);$team=$s->createTeam($owner['id'],'Team');
$token=$s->invite($owner['id'],$team['id'],['id'=>2,'login'=>'old-name']);
$wrong=$s->githubAccount(['id'=>3,'login'=>'old-name']);$rejected=false;
try{$s->acceptGithub($wrong['id'],$token);}catch(SemanticRouter\ApiError $e){$rejected=true;}
$correct=$s->githubAccount(['id'=>2,'login'=>'new-name']);$s->acceptGithub($correct['id'],$token);
echo json_encode(['wrong_id_rejected'=>$rejected,'teams'=>$s->teams($correct['id'])]);
""")
        self.assertTrue(data["wrong_id_rejected"])
        self.assertEqual(data["teams"][0]["role"], "member")

    def test_git_transports_and_paths_are_restricted(self):
        data = self.php(r"""
require $argv[1].'/server/git.php';$denied=0;
foreach(['file:///tmp/repo','ext::sh -c anything','https://user:secret@github.com/x/y','https://localhost/x/y','ssh://git@github.com:2222/x/y'] as $url){try{SemanticRouter\repositoryUrl($url);}catch(SemanticRouter\ApiError $e){$denied++;}}
foreach(['../configs','/configs','a/../../b'] as $path){try{SemanticRouter\repositoryDirectory($path);}catch(SemanticRouter\ApiError $e){$denied++;}}
echo json_encode(['denied'=>$denied,'valid'=>SemanticRouter\repositoryUrl('git@github.com:example/configs.git')]);
""")
        self.assertEqual(data["denied"], 8)
        self.assertEqual(data["valid"], "ssh://git@github.com/example/configs.git")

    @unittest.skipUnless(shutil.which("git"), "Git is required")
    def test_git_pull_reads_blobs_skips_symlinks_and_never_checks_out(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = root / "fixture"
            repo.mkdir()

            def git(*args):
                subprocess.run(
                    ["git", "-C", str(repo), *args], check=True, capture_output=True
                )

            git("init", "--quiet")
            git("config", "user.name", "Synthetic fixture")
            git("config", "user.email", "test@example.invalid")
            (repo / "net-configs").mkdir()
            text = "/system identity\nset name=router\n"
            (repo / "net-configs/router.cfg").write_text(text)
            (repo / "net-configs/link.cfg").symlink_to("router.cfg")
            (repo / "README.md").write_text("Not a config")
            git("add", ".")
            git("commit", "--quiet", "-m", "Synthetic fixture")
            binary = root / "bin"
            binary.mkdir()
            real_git = shutil.which("git")
            wrapper = binary / "git"
            # Only the transport is replaced. All real bare-repository/object commands
            # run through the production runner; no remote network is contacted.
            wrapper.write_text(f"""#!{sys.executable}
import os,sys,subprocess
args=sys.argv[1:]
env=dict(os.environ)
if 'fetch' in args:
    args[args.index('--')+1]={str(repo)!r}
    args=['-c','protocol.file.allow=always',*args]
    env['GIT_ALLOW_PROTOCOL']='file'
sys.exit(subprocess.call([{real_git!r},*args],env=env))
""")
            wrapper.chmod(0o700)
            result = self.php(
                r"""
require $argv[1].'/server/git.php';
echo json_encode(SemanticRouter\pullRepository(['url'=>'git@github.com:example/configs.git','branch'=>'HEAD','directory'=>'net-configs']));
""",
                env={
                    **os.environ,
                    "PATH": str(binary) + os.pathsep + os.environ["PATH"],
                },
            )
            self.assertEqual([item["name"] for item in result["files"]], ["router"])
            self.assertEqual(result["files"][0]["text"], text)
            self.assertEqual(len(result["repository"]["commit"]), 40)
