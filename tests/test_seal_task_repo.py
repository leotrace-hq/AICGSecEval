"""seal_task_repo: after masking, the task repo's git must not reach the original or the fix.

    python -m unittest tests/test_seal_task_repo.py
"""

import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from bench.utils import seal_task_repo  # noqa: E402

ORIGINAL = "def check(user):\n    return True  # ORIGINAL-VULNERABLE-LINE\n"
FIX = "def check(user):\n    return user.is_admin  # UPSTREAM-FIX-LINE\n"
MASKED = "def check(user):\n    <MASKED>\n"
ENV = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
       "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t",
       "GIT_COMMITTER_EMAIL": "t@t"}


def git(repo, *args, check=True):
    return subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True, env=ENV,
                          check=check).stdout


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


class SealTaskRepoTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = os.path.join(self.tmp.name, "repo")
        r = self.repo
        os.makedirs(r)
        git(r, "init", "-q", "-b", "master")
        write(os.path.join(r, "app/auth.py"), ORIGINAL)
        write(os.path.join(r, "README"), "readme\n")
        write(os.path.join(r, ".gitignore"), "build/\n")
        git(r, "add", "-A")
        git(r, "commit", "-q", "-m", "base")
        base = git(r, "rev-parse", "HEAD").strip()
        # the upstream fix lands later on the default branch, as in every A.S.E clone
        write(os.path.join(r, "app/auth.py"), FIX)
        git(r, "commit", "-q", "-am", "fix CVE")
        git(r, "remote", "add", "origin", "https://TOKEN@github.com/x/y.git")
        git(r, "checkout", "-q", base)  # what ContextManager's reset --hard base_commit leaves
        # a vendored repo with its own history, and an ignored build dir
        nested = os.path.join(r, "vendor/lib")
        os.makedirs(nested)
        git(nested, "init", "-q")
        write(os.path.join(nested, "lib.py"), "x = 1\n")
        git(nested, "add", "-A")
        git(nested, "commit", "-q", "-m", "lib")
        write(os.path.join(r, "build/out.txt"), "ignored\n")
        write(os.path.join(r, "app/auth.py"), MASKED)  # the uncommitted mask

    def tearDown(self):
        self.tmp.cleanup()

    def test_only_the_masked_tree_is_reachable(self):
        r = self.repo
        seal_task_repo(r, "app/auth.py", MASKED)
        self.assertEqual(git(r, "rev-list", "--all", "--count").strip(), "1")
        self.assertEqual(git(r, "show", "HEAD:app/auth.py"), MASKED)
        self.assertEqual(git(r, "diff", "HEAD"), "")  # a full diff shows nothing original
        self.assertEqual(git(r, "remote").strip(), "")
        self.assertEqual(git(r, "stash", "list").strip(), "")
        self.assertEqual(git(r, "for-each-ref", "--format=%(refname)").split(), ["refs/heads/main"])
        # no object anywhere in the repo holds the original or the fix
        objs = git(r, "cat-file", "--batch-all-objects", "--batch-check=%(objectname)").split()
        blobs = subprocess.run(["git", "-C", r, "cat-file", "--batch"], input="\n".join(objs),
                               capture_output=True, text=True, errors="replace", env=ENV).stdout
        self.assertNotIn("ORIGINAL-VULNERABLE-LINE", blobs)
        self.assertNotIn("UPSTREAM-FIX-LINE", blobs)
        with open(os.path.join(r, ".git/config"), encoding="utf-8") as f:
            self.assertNotIn("TOKEN", f.read())

    def test_restoring_from_git_gives_back_the_masked_file(self):
        r = self.repo
        seal_task_repo(r, "app/auth.py", MASKED)
        write(os.path.join(r, "app/auth.py"), ORIGINAL.replace("ORIGINAL", "AGENT"))
        git(r, "checkout", "--", "app/auth.py")
        with open(os.path.join(r, "app/auth.py"), encoding="utf-8") as f:
            self.assertEqual(f.read(), MASKED)

    def test_nested_repo_becomes_plain_files_and_ignored_files_stay(self):
        r = self.repo
        seal_task_repo(r, "app/auth.py", MASKED)
        self.assertFalse(os.path.exists(os.path.join(r, "vendor/lib/.git")))
        self.assertEqual(git(r, "show", "HEAD:vendor/lib/lib.py"), "x = 1\n")
        self.assertTrue(os.path.exists(os.path.join(r, "build/out.txt")))
        self.assertEqual(git(r, "ls-files", "build").strip(), "")

    def test_refuses_when_the_mask_is_not_on_disk(self):
        with self.assertRaises(RuntimeError):
            seal_task_repo(self.repo, "app/auth.py", "something else\n")

    def test_same_tree_same_commit(self):
        seal_task_repo(self.repo, "app/auth.py", MASKED)
        first = git(self.repo, "rev-parse", "HEAD").strip()
        seal_task_repo(self.repo, "app/auth.py", MASKED)
        self.assertEqual(git(self.repo, "rev-parse", "HEAD").strip(), first)


if __name__ == "__main__":
    unittest.main()
