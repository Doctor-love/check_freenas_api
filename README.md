# check_freenas_api
Monitoring/Nagios plugin for FreeNAS systems

### Overview
The check_freenas_api monitoring plugin utilizes the FreeNAS REST API for status monitoring.
It's designed to be easily extendable with new "check modes" for monitoring different parts of the system.

**Use the plugin at your own risk and keep in mind that all contributions are appriciated!**

### Available check modes

###### "volume-usage":
Checks the usage percentage of all or specified volumes.  
API version support: 1.0 (full)

### Installation and configuration
The plugin is written in Python and requires the following modules besides version 2.6 standard library:
- argparse
- requests
- nagiosplugin

You will also have to enable HTTPS access to your FreeNAS system if it's not already configured.
