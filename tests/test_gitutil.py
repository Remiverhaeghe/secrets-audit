import unittest
from unittest import mock

from secrets_audit import gitutil
from tests.support import RepoTestCase, commit_all, git, make_repo, write


class FindReposTest(RepoTestCase):
    def test_finds_repos_up_to_depth_two_and_skips_vendor_dirs(self):
        make_repo(self.aRoot, "a")
        make_repo(self.aRoot / "groupe", "b")
        make_repo(self.aRoot / "node_modules", "c")
        make_repo(self.aRoot / "x" / "y", "trop-profond")
        vNames = [vRepo.name for vRepo in gitutil.find_repos(self.aRoot)]
        self.assertEqual(["a", "b"], vNames)

    def test_root_that_is_a_repo_is_returned_alone(self):
        vRepo = make_repo(self.aRoot, "solo")
        make_repo(vRepo, "imbrique")
        self.assertEqual([vRepo], gitutil.find_repos(vRepo))

    def test_unreadable_directory_is_skipped(self):
        with mock.patch("pathlib.Path.iterdir", side_effect=PermissionError("non")):
            with self.assertLogs("secrets_audit.gitutil", "WARNING"):
                self.assertEqual([], gitutil.find_repos(self.aRoot))


class FilesTest(RepoTestCase):
    def test_tracked_untracked_and_ignored(self):
        vRepo = make_repo(self.aRoot)
        write(vRepo, "suivi.txt", "a")
        write(vRepo, ".gitignore", "cache.txt\n")
        commit_all(vRepo)
        write(vRepo, "cache.txt", "b")
        write(vRepo, "nouveau.txt", "c")
        self.assertEqual([".gitignore", "suivi.txt"], gitutil.tracked_files(vRepo))
        self.assertEqual(["nouveau.txt"], gitutil.untracked_files(vRepo))

    def test_history_keeps_deleted_files_and_sorts(self):
        vRepo = make_repo(self.aRoot)
        write(vRepo, "b.txt", "1")
        write(vRepo, "dossier/a.txt", "1")
        commit_all(vRepo)
        git(vRepo, "rm", "-q", "b.txt")
        git(vRepo, "commit", "-q", "-m", "retrait")
        self.assertEqual(["b.txt", "dossier/a.txt"], gitutil.history_added_files(vRepo))

    def test_history_of_repo_without_commit_is_empty(self):
        self.assertEqual([], gitutil.history_added_files(make_repo(self.aRoot)))

    def test_history_failure_gives_empty_list(self):
        with mock.patch(
            "secrets_audit.gitutil._git", side_effect=gitutil.GitError("non")
        ):
            self.assertEqual([], gitutil.history_added_files(self.aRoot))

    def test_git_failure_raises(self):
        with self.assertRaises(gitutil.GitError):
            gitutil.tracked_files(self.aRoot)

    def test_missing_git_raises(self):
        with mock.patch("shutil.which", return_value=None):
            with self.assertRaisesRegex(gitutil.GitError, "introuvable"):
                gitutil.tracked_files(self.aRoot)


if __name__ == "__main__":
    unittest.main()
