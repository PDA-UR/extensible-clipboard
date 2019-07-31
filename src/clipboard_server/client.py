#!/usr/bin/python3
import sys

from PyQt5 import uic, QtWidgets, QtCore
import time

import os
import signal

import subprocess

#
#
# CONSTANTS
from main import MainApp

WINDOW_WIDTH = 500
WINDOW_HEIGHT = 300
STR_APP_NAME = 'Extensible Clipboard Client'
STR_UI_PATH = './client.ui'


#
class ClipboardClientController(QtWidgets.QMainWindow):

    def __init__(self):
        QtWidgets.QMainWindow.__init__(self)
        self.ui = uic.loadUi(STR_UI_PATH, self)
        self.ui.show()
        self.ui.btn_connect.pressed.connect(self.on_start_pressed)
        self.ui.edit_server_address.textChanged.connect(self.on_text_entered)

        self.server_address = self.ui.edit_server_address.text()

        self.clipboard_process = None
    # UI Event Handlers

    def on_start_pressed(self):
        self.start_server(
            self.server_address
        )

    def on_text_entered(self, content):
        # TODO: evaluate, whether the input is correct
        # TODO: add http:// and / to address
        self.server_address = content

    def closeEvent(self, QCloseEvent):
        if self.app is not None:
            self.app.quit()

    # Actions

    def start_server(self, address):
        try:
            self.app = MainApp(5555, address, "public", True, sys.argv)
            self.app.main()
            self.set_connected(True)
        except:
            print("Error connecting!")
            # TODO: error handling and feedback!

    def set_connected(self, is_connected):
        if is_connected == True:
            self.ui.btn_connect.setDisabled(True)
            self.ui.btn_connect.setText("Clipserver Connected!")
            self.repaint()


    # Set the display content to the value of str_display and repaint
    def update_display(self):
        self.update()


    #
    #
    # INPUT BIND FUNCTIONS
    """
    # Connect to GUI Events
    def bind_buttons(self):
        # get all buttons
        # https://stackoverflow.com/questions/13725704/grabbing-all-qpushbutton-in-a-pyqt-python-ui-file 8.5.19
        buttons = self.ui.findChildren(QtWidgets.QPushButton)
        for btn in buttons:
            # ignore first parameter of lambda function (specific for button callbacks)
            # https://stackoverflow.com/questions/18836291/lambda-function-returning-false 8.5.19
            btn.pressed.connect(lambda bound_btn=btn: self.slot_resolve_button_press(bound_btn.objectName()))
            # btn.released.connect(lambda bound_btn=btn: self.slot_resolve_mouserelease(bound_btn.objectName()))

    # bind keypress signals to the resolve function
    def bind_keypress(self):
        self.key_pressed_signal.connect(self.slot_resolve_keypress)

    # Bind keypress to signal
    # https://stackoverflow.com/questions/27475940/pyqt-connect-to-keypressevent, 8.5.19
    def keyPressEvent(self, event):
        super(ClipboardClientController, self).keyPressEvent(event)
        self.key_pressed_signal.emit(event.key())
    """


def main():
    window = ClipboardClientController()
    window.setWindowTitle(STR_APP_NAME)


if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    main()
    #sys.exit(app.exec_())
    app.exec()