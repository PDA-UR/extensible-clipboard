from .clipboard import Clipboard
from .network_manager import NetworkManager


class EventHandler:
    """
    This class is responsible to take data from other programs, plugins etc and save them to the clipboard
    and also forwards the data to the server
    It also retrieves data from the server and can return it
    """
    # A Clipboard from this package, used for changing the local clipboard
    clipboard = None
    # A NetworkManager from this package, used for interacting with the remote clipboard
    network_manager = None

    def _save_to_local_clipboard(self, data):
        """
        Saves data to the local clipboard. Uses a QClipboard
        :param data: Data to be saved
        """
        self.clipboard.save(data)

    def _propagate_to_server(self, data):
        """
        Passes the saved data to the server to store it there
        :param data: The data to be sent
        """
        self.network_manager.send_data(data)

    def put_into_storage(self, data):
        """
        Responsible for storing data on a higher level. This function should be called when you want to save
        data in your clipboard and on the server simultaneously
        :param data: The data to be saved
        """
        self._save_to_local_clipboard(data)
        self._propagate_to_server(data)

    def retrieve_from_storage(self, callback):
        """
        Queries the server for the current content of the clipboard and returns the data
        :return: The data sent from the server
        """
        clipboard_data = self.network_manager.get_data(callback)
        return clipboard_data

    def __init__(self, q_app):
        """
        :param q_app: The current QApplication this package is part of running in
        """
        self.clipboard = Clipboard(q_app.clipboard())
        self.network_manager = NetworkManager()