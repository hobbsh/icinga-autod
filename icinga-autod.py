#!/usr/bin/env python
import util.checkpkg as checkpkg

checkpkg.check(['nmap', 'snmp', 'net-snmp-utils'])

import sys
import subprocess
import json
import nmap

try:
    import argparse
except ImportError:
    checkpkg.check(['python-argparse'])

import time
import socket
import util.ianaparse as ianaparse

"""
This discovery script will scan a subnet for alive hosts,
determine some basic information about them,
then create a hosts.conf in the current directory for use in Nagios or Icinga

required Linux packages: python-nmap and nmap

Copyright Wylie Hobbs - 08/28/2015

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
"""

USAGE = './icinga-autod.py -n 192.168.1.0/24'


def build_parser():

    parser = argparse.ArgumentParser(description='Device AutoDiscovery Tool')

    parser.add_argument('-n', '--network', required=True,
	help='Network segment (only /24) to iterate through for live IP addresses in CIDR IPv4 Notation')

    parser.add_argument('-L', '--location', default=None,
        help='Location alias of the network - will be appended to the hosts config (i.e. hosts_location.conf)')

    parser.add_argument('-c', '--communities', default="public,private",
        help='Specify comma-separated list of SNMP communities to iterate through (to override default public,private)')

    parser.add_argument('-d', '--debug', default=False,
        help='Specify comma-separated list of SNMP communities to iterate through (to override default public,private)')

    #The following two arguments have no effect currently
    parser.add_argument('-r', '--reparse-iana', default=False,
        help='Whether icinga-autod should grab a fresh version of the sysObjectIDs from the IANA URL')

    parser.add_argument('-t', '--thorough', default=0,
        help='Thorough scan mode (will take longer) - will try additional SNMP versions/communities to try to gather as much information as possible')

    return parser


def main():

    global debug
    global credential
    global int_oid

    parser = build_parser()
    args = parser.parse_args()

    '''Check arguments'''
    if check_args(args) is False:
        sys.stderr.write("There was a problem validating the arguments supplied. Please check your input and try again. Exiting...\n")
        sys.exit(1)

    if args.debug:
        debug = True
    else:
        debug = False

    start_time = time.time()

    cidr = args.network

    location = args.location

    credential = dict()
    credential['version'] = '2c'
    credential['community'] = args.communities.split(',')

    #Hostname, vendor OID and sysDescr OIDs
    oids = '1.3.6.1.2.1.1.5.0 1.3.6.1.2.1.1.2.0 1.3.6.1.2.1.47.1.1.1.1.2.1 1.3.6.1.2.1.1.1.0'

    #This OID returns all network interfaces from a switch
    int_oid = '1.3.6.1.2.1.2.2.1.2'

    #Scan the network for live hosts
    hosts = handle_netscan(cidr)

    all_hosts = {}

    print("Found {0} hosts - gathering more info (estimate 120 seconds per host for OS and SNMP scan)".format(get_count(hosts)))
    print("Have in mind that a host timeout has been set to 120 seconds for performance reasons")

    try:
        with open('iana_numbers.json', 'r') as f:
            numbers = json.load(f)
    except Exception, e:
        try:
            numbers = ianaparse.IanaParser().parse()
        except:
            sys.exit("Unable to open iana_numbers.json or read from the URL. Exiting...")

        sys.stderr.write('Unable to open iana_numbers.json, trying URL method. Please wait\n')


    for host in hosts:
        host = str(host)

        '''If your communities/versions vary, modify credentials here. I've used last_octet to do this determination
	        octets = host.split('.')
                last_octet = str(octets[3]).strip()
	   Otherwise, grab the data
	    '''

        hostname = ''

        if ',' in host:
            hostname, host = host.split(',')

        # SNMPGET tries to return info about hostname, vendor and some OS related description
        data = snmpget_by_cl(host, credential, oids)
        try:
            output = data['output'].split('\n')
            hostname = output[0].strip('"')
        except:
            output = ''
        try:
            community = data['community']
        except:
            community = 'unknown'
        try:
            sysobject = output[1].strip('"')
        except:
            sysobject = ''
        try:
            systype = output[2].strip('"')
        except:
            systype = ''
        try:
            sysdesc = output[3].strip('"')
        except:
            sysdesc = ''

        ''' This uses nmap to discover OS, type of device and OS details'''
        # You need root privileges to perform active OS fingerprinting
        os_data = handle_osscan(host)
        try:
            ports = os_data['ports']
        except:
            ports = 'Unknown'
        try:
            os = os_data['os'][0]
        except:
            os = 'Unknown'
        try:
            type = os_data['type'][0]
        except:
            type = 'Unknown'
        try:
            details = os_data['details'][0]
        except:
            details = 'Unknown'

        ''' This uses snmp to discover network interaces'''
        data = snmpwalk_by_cl(host, credential, int_oid)
        try:
            interfaces = data['output'].split('\n')
            # print interfaces
        except:
            interfaces = ''

        v_match = vendor_match(numbers, sysobject)

        if v_match:
            vendor = v_match['o'].strip('"')
        else:
            vendor = None

        all_hosts[host] = {
	        'community': community,
            'snmp_version': credential['version'],
            'hostname': hostname,
            'sysdesc': sysdesc,
            'vendor' : vendor,
            'os' : os,
            'type' : type,
            'details' : details,
            'model' : systype,
            'ports' : ports,
            'ints' : interfaces
            }

        if debug:
            print host, sysobject, all_hosts[host]

    print "\n"
    print("Discovery took %s seconds" % (time.time() - start_time))
    print "Writing data to config file. Please wait"

    outfile = compile_hosts(all_hosts, location)
    print "Wrote data to "+outfile


def vendor_match(numbers, sysobject):
    if sysobject:
        #Possible prefixes in sysObjectID OID largely dependent on MIB used
        prefixes = ['SNMPv2-SMI::enterprises.', 'iso.3.6.1.4.1.', '1.3.6.1.4.1.', '1.3.6.1.4.1.9.', 'NET-SNMP-MIB::netSnmpAgentOIDs.']

        for prefix in prefixes:
            if sysobject.startswith(prefix):
                sysobject = sysobject[len(prefix):]

            values = sysobject.split('.')
            #first value will be the enterprise number
            vendor_num = values[0]

        try:
            vendor_string = numbers[vendor_num]
            return vendor_string
        except Exception, e:
            sys.stderr.write('Unknown sysObjectID prefix encountered - you can add it to the prefix list in vendor_match(), but please report this on GitHub\n'+str(e))
            return False
    else:
	    return False



def check_args(args):
    '''Exit if required arguments not specified'''
    '''
    if args.network == None:
	sys.stderr.write("Network and/or location are required arguments! Use -h for help\n")
	sys.exit(1)
    '''
    check_flags = {}
    '''Iterate through specified args and make sure input is valid. TODO: add more flags'''
    for k,v in vars(args).iteritems():
        if k == 'network':
	    network = v.split('/')[0]
	    if len(network) > 7:
	    	if is_valid_ipv4_address(network) is False:
		    check_flags['is_valid_ipv4_address'] = False
	    else:
		check_flags['is_valid_ipv4_format'] = False

    last_idx = len(check_flags) - 1
    last_key = ''

    '''Find last index key so all the violated flags can be output in the next loop'''
    for idx, key in enumerate(check_flags):
	if idx == last_idx:
	    last_key = key

    for flag, val in check_flags.iteritems():
        if val is False:
	    sys.stderr.write("Check "+flag+" failed to validate your input.\n")
	    if flag == last_key:
		return False


def is_valid_ipv4_address(address):
    '''from http://stackoverflow.com/questions/319279/how-to-validate-ip-address-in-python'''
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:  # no inet_pton here, sorry
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
        return address.count('.') == 3
    except socket.error:  # not a valid address
        return False

    return True


def get_count(hosts):
    count = len(hosts)
    if count == 0:
        print "No hosts found! Is the network reachable? \nExiting..."
        sys.exit(0)
    else:
        return count


def compile_hosts(data, location):
    if location:
        loc = location.lower()
        filename = 'hosts_'+loc+'.conf'
    else:
        filename = 'discovered_hosts.conf'

    f = open(filename, 'w')

    for ip, hdata in data.iteritems():
        hostvars = compile_hvars(hdata['sysdesc'])

        if not hdata['hostname']:
            hostname = ip
        else:
            hostname = hdata['hostname']

        host_entry = build_host_entry( hostname,
                        str(ip),
                        location,
                        hdata['vendor'],
                        hdata['sysdesc'],
                        hdata['os'],
                        hdata['type'],
                        hdata['details'],
                        hdata['model'],
                        hdata['ports'],
                        hdata['ints'],
                        str(hostvars) )

        f.write(host_entry)

    f.close()

    return filename


def build_host_entry(hostname, ip, location, vendor, notes, os, type, details, model, ports, ints, hostvars):
    host_entry = ( 'object Host "%s" {\n'
            '  address = "%s"\n'
            '  import "generic-host"\n'
        ) % (hostname, ip)

    if os:
        if "Linux" in os:
            host_entry += '  import "linux-host"\n'
        if "Solaris" in os:
            host_entry += '  import "solaris-host"\n'
        if "Windows" in os:
            host_entry += '  import "windows-host"\n'
        if "Apple" in os:
            host_entry += '  import "mac-host"\n'
        if "VMware ESXi" in os:
            host_entry += '  import "vm-host"\n'
        if "UPS" in os:
            host_entry += '  import "power-device"\n'
        host_entry += '  vars.os = "{0}"\n'.format(os)
    if type:
        if ("firewall" in type) | ("router" in type) | ("switch" in type):
            host_entry += '  import "network-host"\n'
        if "power" in type:
            host_entry += '  import "power-device"\n'
        if ("printer" in type) & ("storage" not in type):
            host_entry += '  import "generic-printer"\n'
        host_entry += '  vars.type = "{0}"\n'.format(type)
    if details:
        host_entry += '  vars.os_details = "{0}"\n'.format(details)
    if model:
        host_entry += '  vars.description = "{0}"\n'.format(model)
    if ports:
        host_entry += '  vars.ports = "{0}"\n'.format(ports)
    if location:
        host_entry += '  vars.location = "{0}"\n'.format(location)
    if vendor:
        host_entry += '  vars.vendor = "{0}"\n'.format(vendor)
    if notes:
        host_entry += '  notes = "{0}"\n'.format(notes)
    if hostvars:
        host_entry += '  {0}\n'.format(hostvars)
    if ints:
        for interface in ints:
#            if ("Ethernet" in interface) or ("Radio" in interface) or ("FC" in interface):
            if interface and ("unrouted" not in interface):
                host_entry += '  vars.int["{0}"] = '.format(interface.strip('"')) + '{\n'
                host_entry += '    int = "{0}"\n'.format(interface.strip('"'))
                host_entry += '  }\n'

    host_entry += '}\n'

    return host_entry


def compile_hvars(sysdesc):
    sys_descriptors = {
#	'APC': 'vars.group = "UPS"',
        'Fibre Channel Switch': 'vars.group = "FC Switches"',
#        'Cisco IOS Software': 'vars.os = "Switches"',
#	'Linux':'vars.os = "Linux"',
#	'Windows':'vars.os = "Windows"',
    }

    hostvars = ''

    '''Append hostvars based on sysDescr matches'''
    for match, var in sys_descriptors.iteritems():
        if match in sysdesc:
            hostvars += var +'\n  '

    return hostvars


def handle_netscan(cidr):
    '''
    Scan network with nmap using ping only
    '''
    start = time.time()

    print "Starting scan for "+cidr

    ret, output, err = exec_command('nmap -sn -sP {0}'.format(cidr))
    if ret and err:
        sys.stderr.write('There was a problem performing the scan - is the network reachable?')
        sys.exit(1)
    else:
        print ("Scan took %s seconds" % (time.time() - start))
    data = parse_nmap_scan(output)
    if data:
        return data
    else:
        sys.stderr.write('Unable to parse nmap scan results! Please report this issue')
        sys.exit(1)


def parse_nmap_scan(data):
    data_list = data.split('\n')
    match = 'Nmap scan report for '
    hosts = []
    for line in data_list:
        if match in line and line is not None:
            line = line[len(match):].strip(' ')

            if '(' in line:
                remove = '()'
                for c in remove:
                    line = line.replace(c, '')

                line = ','.join(line.split(' '))

            hosts.append(line)

    return hosts


def parse_nmap_osscan(data):
    ans = {}
    data_list = data.split('\n')
    match_os1 = 'Running:'
    match_os2 = 'Aggressive OS guesses:'
    #    match_os3 = 'OS detection performed.'
    match_osd = 'OS details:'
    match_dt  = 'Device type:'
    os = []
    type = []
    details = []
    for line in data_list:
        if match_dt in line and line is not None:
            line = line[len(match_dt):].strip(' ')
            type.append(line)
        if match_osd in line and line is not None:
            line = line[len(match_osd):].strip(' ')
            details.append(line)
        if match_os1 in line and line is not None:
            line = line[len(match_os1):].strip(' ')
            os.append(line)
        if match_os2 in line and line is not None:
            line = line[len(match_os2):].strip(' ')
            os.append(line)
    try:
        ans['type'] = type
        ans['details'] = details
        ans['os'] = os
    except Exception, e:
        print "There was a problem appending data to the dict " + str(e)

    return ans


def snmpget_by_cl(host, credential, oid, timeout=1, retries=0):
    '''
    Slightly modified snmpget method from net-snmp source to loop through multiple communities if necessary
    '''

    data = {}
    version = credential['version']
    communities = credential['community']
    com_count = len(communities)

    for i in range(0, com_count):
        cmd = ''
        community = communities[i].strip()
        cmd = "snmpget -Oqv -v %s -c %s -r %s -t %s %s %s" % (
            version, community, retries, timeout, host, oid)

        returncode, output, err = exec_command(cmd)

        #print returncode, output, err

        if returncode and err:
            if i < com_count:
                continue
            else:
                data['error'] = str(err)
        else:
            try:
                data['output'] = output
                data['community'] = community
        #Got the data, now get out
		break
            except Exception, e:
                print "There was a problem appending data to the dict " + str(e)

    return data


def snmpwalk_by_cl(host, credential, oid, timeout=1, retries=0):
    '''
    Slightly modified snmpwalk method from net-snmp source to loop through multiple communities if necessary
    '''

    data = {}
    version = credential['version']
    communities = credential['community']
    com_count = len(communities)

    for i in range(0, com_count):
        cmd = ''
        community = communities[i].strip()
        cmd = "snmpwalk -Oqv -v %s -c %s -r %s -t %s %s %s" % (
            version, community, retries, timeout, host, oid )

        returncode, output, err = exec_command(cmd)

        # print returncode, output, err

        if returncode and err:
            if i < com_count:
                continue
            else:
                data['error'] = str(err)
        else:
            try:
                data['output'] = output
                data['community'] = community
                #Got the data, now get out
                break
            except Exception, e:
                print "There was a problem appending data to the dict " + str(e)

    return data


def handle_osscan(cidr):
    '''
    Scan network with nmap to detect OS
    '''
    start = time.time()

    print "\nStarting OS scan for "+cidr

    ret, output, err = exec_command('nmap -sT -O --host-timeout 2m {0}'.format(cidr))
#    nm = nmap.PortScanner()
#    nm.scan(hosts='{0}'.format(cidr), arguments='-sT -O --host-timeout 10s')
    try:
        tcp_ports = nm['{0}'.format(cidr)]['tcp'].keys()
    except:
        tcp_ports = []
    if ret and err:
        sys.stderr.write('There was a problem performing the scan - is the network reachable?')
        sys.exit(1)
    else:
        print ("OS Scan took %s seconds" % (time.time() - start))
        data = parse_nmap_osscan(output)

        if data:
            if tcp_ports:
                data['ports'] = tcp_ports
            return data
        else:
            sys.stderr.write('Unable to parse nmap scan results! Please report this issue')
            sys.exit(1)


def exec_command(command):
    """Execute command.
       Return a tuple: returncode, output and error message(None if no error).
    """
    sub_p = subprocess.Popen(command,
                             shell=True,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
    output, err_msg = sub_p.communicate()
    return (sub_p.returncode, output, err_msg)


if __name__ == "__main__":
    main()
    sys.exit(0)
