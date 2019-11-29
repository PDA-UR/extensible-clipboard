from fbs_runtime.application_context.PyQt5 import ApplicationContext

import sys
import time

# from server.main import MainApp as MainServerApp
# from clipboard_server.main import  ClipboardServerApp as ClipboardApp

from server.main import  ClipServer
from util.context import Context

main_server_port = 5000
clipboard_port = 5010

from importlib import machinery

if __name__ == '__main__':

    Context.ctx = ApplicationContext()       # 1. Instantiate ApplicationContext

    server = ClipServer(sys.argv, main_server_port)
    server.main()


    """
    # TODO: quite messy way of waiting for the server to finish starting, but it should do the trick for now
    time.sleep(1)

    print("Start Server")

    clipboard = ClipboardServerApp(
        clipboard_port,
        "http://localhost:{}/".format(str(main_server_port)),
        "http://localhost",
        True,
        sys.argv,
        Context.ctx.app
    )
    clipboard.main()
    """
    exit_code = Context.ctx.app.exec_()      # 2. Invoke appctxt.app.exec_()
    # sys.exit(exit_code)
