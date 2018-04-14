# icinga2-autod

## Purpose:
The purpose of icinga2-autod is to bring basic auto-discovery Icinga2 (or Icinga/Nagios Core with minor modifications) in an effort to take some of the pain away from discovering and adding a bunch of devices on new or existing networks. The focus of this tool is to quickly generate a fairly suitable host config with custom vars to tie them to HostGroups. 

## Requirements
This utility requires Linux packages 'nmap' and 'snmp' (or 'net-snmp + net-snmp-utils' on RHEL). It will not run until any missing requirements are satisfied.  

## Installation
```bash
git clone https://github.com/hobbsh/icinga2-autod.git
cd icinga2-autod

./icinga-autod.py -n 192.168.1.0/24
```
Will output discovered_hosts.conf to current directory. 

## Usage:
This utility is meant to serve as a way to quickly generate a base hosts config for a given network. The host objects it creates (depending on the information it can gather) provide enough data to use HostGroups to do most of your check manangement. It's by no means a catch-all or the only way to do it, but I figured people might have a use for it.

```
usage: icinga-autod.py [-h] -n NETWORK [-L LOCATION] [-c COMMUNITIES]
                       [-d DEBUG]

required arguments
  -n NETWORK, --network NETWORK
                        Network segment to iterate through for live
                        IP addresses in CIDR IPv4 Notation (accepts single IPv4 address too)
optional arguments:
  -h, --help            show this help message and exit
  -L LOCATION, --location LOCATION
                        Location alias of the network - will be appended to
                        the hosts config (i.e. hosts_location.conf)
  -c COMMUNITIES, --communities COMMUNITIES
                        Specify comma-separated list of SNMP communities to
                        iterate through (to override default public,private)
  -d DEBUG, --debug DEBUG
			Use '-d True' to turn debug on
```
Add your own sys_descriptor matches in the compile_hvars method to add custom variables. Hoping to add a better way of handling this soon
```

## Icinga2 sample files:
The folder "samples" contains some ready to use .conf files for icinga2 configuration regarding templates and groups. 

## TODO:
- More options
 - Allow user to input hostname FQDN format (should it come to that)
 - Specify SNMP timeout/retries
- Integrate with icingaweb2
- Add SNMPv3 Support
- Handle bad user input better
