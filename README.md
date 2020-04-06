![alt text](logo.png)
# Extensible Clipboard
This is the improved repository of Extensible Clipboard, 
which has been initially developed by Matthias Rösl. 

Extensible Clipboard is a web-transparent extension of the
traditional clipboard, enabling users enhanced functionality 
and the capability to create own applications, tapping into 
the functionality of the system clipboard.

🚨 Running extensible clipboard is currently **not supported on OS X platforms** due to 
restrictions of the PyQT framework. 

🚨 Also, **building will currently not work on Windows platforms**, so please use `fbs run` instead.

## Features
- 🌏  Remotely set the clipboard on multiple systems via HTTP-Requests

- ⏳ Access the clipboard history via HTTP-Requests

- 📋 Full portation of clipboard functionality to REST-interface ([Read the doc here...](./../../wiki/API-Documentation)
)

- 🔒 Control access to your clipboard by whitelisting clients

## Installation & Building
We recommend installing extensible clipboard from the built version, since it is the most convenient way and does not require installing any packages:

- [Download Debian build (04.03.2020)](https://files.mi.ur.de/f/81159d53bc/?dl=1)



If you run extensible clipboard for the first time, please initialize it with the 
following command:
    
    # Execute from project root
    ./build.sh
    
## Running 
After building the executable, you can run it through the console:

    # Start extensible clipboard
    cd ./servers
    'target/ExtensibleClipboard/ExtensibleClipboard'
  
It's easy as that!

## Configuring 


### Server Whitelist
The clip/backend server will only accept requests from trusted clipboards. Trusted clipboards
can be defined in ExtensibleClipboard/config/trusted-clients-config.json: Simply add the
IPv4 address of your clipboard device to the list to allow access to the clipboard.

### System
You can adapt extensible clipboard to your needs and workflows by changing the config files 
or passing command line arguments. The following commands will demonstrate some possible 
use cases, that we have encountered

#### Full package
For deploying the complete system with server and clipboard, simply run:

    # Start extensible clipboard full environment
    cd ./servers
    'target/ExtensibleClipboard/ExtensibleClipboard'

#### Server only
For only running a server, enter:

    # Start extensible clipboard server
    cd ./servers
    'target/ExtensibleClipboard/ExtensibleClipboard' -nocbs

This may come in handy, if you want to offer a centralized, remote server.

#### Clipboard only
For only running the clipboard, enter:

    # Start extensible clipboard, clipboard-only
    cd ./servers
    'target/ExtensibleClipboard/ExtensibleClipboard' -nocs -cbsdomain=http://mydomain -cbsport=12345 -cshost=http://myserverdomain:12345/

This configuration is suitable for setups, where you might connect your local 
clipboard to a remote server.


