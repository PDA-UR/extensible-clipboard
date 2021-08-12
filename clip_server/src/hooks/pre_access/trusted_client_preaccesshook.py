from hooks.pre_access.basepreaccesshook import BasePreAccessHook
import server
from importlib import machinery
import json

import os

class TrustedClientHook(BasePreAccessHook):
    """
    Hook for restricting or allowing access to the clipboard server.

    trusted-clients-config.json contains an array with the addresses of allowed devices, all requests from other
    sources will effect an "access forbidden" warning.
    """

    def do_work(self, request):
        config_file = open("../config/trusted-clients-config.json")
        trusted_addresses = json.load(config_file)
        config_file.close()
        remote = request.remote_addr
        if (remote in trusted_addresses):
            return request
        else:
            raise ValueError('User Not Authorized for Access on Resource!')
