from hooks.pre_commit.baseprecommithook import BasePreCommitHook


class ExamplePreCommitHook(BasePreCommitHook):

    def do_work(self, *args, **kwargs):
        super().do_work(*args, **kwargs)
        print(self.data)
        """
        This is the base hook for pre-commit hooks. A pre-commit hook is called right before the clipboard request is persisted
        and may modify the request or deny further processing (this may allow for implementing auth-mechanisms)
        """
