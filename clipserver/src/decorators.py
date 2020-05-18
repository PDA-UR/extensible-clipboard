from flask import request


def access_hooks(func):
    def wrapper(*args, **kwargs):
        return _pre_access_hooks(
            _post_access_hooks(
                func
            )
        )(*args, **kwargs)
    return wrapper


def _pre_access_hooks(func):
    def wrapper(*args, **kwargs):
        # Pass request to hooks and get their 'consent'
        if not args[0].hook_manager.trigger_preaccess(request):
            return '', 403
        return func(*args, **kwargs)
    return wrapper


def _post_access_hooks(func):
    def wrapper(*args, **kwargs):
        response = func(*args, **kwargs)
        args[0].hook_manager.trigger_postaccess(response)
        return response
    return wrapper


def commit_hooks(func):
    def wrapper(*args, **kwargs):
        return pre_commit_hooks(
            post_commit_hooks(
                func
            )
        )(*args, **kwargs)
    return wrapper


def pre_commit_hooks(func):
    def wrapper(*args, **kwargs):
        # Pass request to hooks and get their 'consent'
        if not args[0].hook_manager.trigger_precommit(request):
            return '', 403
        return func(*args, **kwargs)
    return wrapper


def post_commit_hooks(func):
    def wrapper(*args, **kwargs):
        result = func(**kwargs)
        result = args[0].hook_manager.trigger_postcommit(result)
        return result
    return wrapper


def pre_notify_hooks(func, hook_manager):
    def wrapper(*args, **kwargs):
        args = hook_manager.trigger_prenotify(args[0], args[1], args[2], args[3])
        return func(args[0], args[3])
    return wrapper


def post_notify_hooks(func, hook_manager):
    def wrapper(*args, **kwargs):
        result = func(*args, **kwargs)
        hook_manager.trigger_postnotify(args[0], args[1], args[2], args[3])
        return result
    return wrapper
