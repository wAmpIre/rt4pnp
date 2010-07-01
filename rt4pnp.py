#!/usr/bin/env python

# (c) 2010 by Sven Velt, Teamix GmbH
#             sv@teamix.de

import ConfigParser
import netsnmp
import optparse
import os
import re
import sys
import time

##############################################################################

PERFDATATEMPL = 'DATATYPE::SERVICEPERFDATA\tTIMET::%(timet)s\tHOSTNAME::%(host_name)s\tSERVICEDESC::%(service_desc)s\tSERVICEPERFDATA::%(service_perfdata)s\tSERVICECHECKCOMMAND::rt4pnp\tHOSTSTATE::UP\tHOSTSTATETYPE::HARD\tSERVICESTATE::OK\tSERVICESTATETYPE::HARD'

##############################################################################

def normalize_snmp_version(version):
	if version in [1,'1']:
		return 1
	elif version in [2,'2','2c']:
		return 2
#	elif version in [3,'3']:
#		return 3
	else:
		print 'Unknow SNMP version "%s"!' % version
		sys.exit(1)


def read_config_global(config):
	cfg = {}

	if config.has_option('global','pnpspoolpath'):
		cfg['pnpspoolpath'] = config.get('global','pnpspoolpath')
	else:
		cfg['pnpspoolpath'] = '/var/spool/pnp4nagios/npcd'
	if not os.access(cfg['pnpspoolpath'],os.W_OK):
		print 'PNP4Nagios spool path "%s" is not writeable!' % cfg['pnpspoolpath']
		sys.exit(1)

	if config.has_option('global','interval'):
		cfg['interval'] = config.getint('global','interval')
	else:
		cfg['interval'] = 60

	if config.has_option('global','snmp_community'):
		cfg['snmp_community'] = config.get('global','snmp_community')
	else:
		cfg['snmp_community'] = 'public'

	if config.has_option('global','snmp_version'):
		cfg['snmp_version'] = normalize_snmp_version(config.get('global','snmp_version'))
	else:
		cfg['snmp_version'] = normalize_snmp_version(2)

	return cfg


def read_config_sections(config, sections, globalcfg):
	hosts = {}

	for section in sections:
		host = {}
		host['host_name'] = config.get(section, 'host_name')
		host['address'] = config.get(section, 'address')

		if config.has_option(section, 'snmp_version'):
			host['snmp_version'] = normalize_snmp_version(config.get(section, 'snmp_version'))
		else:
			host['snmp_version'] = normalize_snmp_version(globalcfg['snmp_version'])

		if config.has_option(section, 'snmp_community'):
			host['snmp_community'] = config.get(section, 'snmp_community')
		else:
			host['snmp_community'] = globalcfg['snmp_community']

		hosts[section] = host

	return hosts


def snmp_get_idx(host):
	return netsnmp.snmpwalk('.1.3.6.1.2.1.2.2.1.1', Version=host['snmp_version'], DestHost=host['address'], Community=host['snmp_community'])


def snmp_get_data(host):
	if host['snmp_version'] == 1:

		nics_name = netsnmp.snmpwalk('.1.3.6.1.2.1.2.2.1.2', Version=host['snmp_version'], DestHost=host['address'], Community=host['snmp_community'])
		nics_byin = netsnmp.snmpwalk('.1.3.6.1.2.1.2.2.1.10', Version=host['snmp_version'], DestHost=host['address'], Community=host['snmp_community'])
		nics_byout = netsnmp.snmpwalk('.1.3.6.1.2.1.2.2.1.16', Version=host['snmp_version'], DestHost=host['address'], Community=host['snmp_community'])

	elif host['snmp_version'] == 2:

		nics_name = netsnmp.snmpwalk('.1.3.6.1.2.1.31.1.1.1.1', Version=host['snmp_version'], DestHost=host['address'], Community=host['snmp_community'])
		nics_byin = netsnmp.snmpwalk('.1.3.6.1.2.1.31.1.1.1.6', Version=host['snmp_version'], DestHost=host['address'], Community=host['snmp_community'])
		nics_byout = netsnmp.snmpwalk('.1.3.6.1.2.1.31.1.1.1.10', Version=host['snmp_version'], DestHost=host['address'], Community=host['snmp_community'])
	else:
		return ([],[],[])

	if len(nics_name) == len(nics_byin) == len(nics_byout):
		return (nics_name, nics_byin, nics_byout)
	else:
		return ([],[],[])


##############################################################################

def main():

	# Read options and arguments
	parser = optparse.OptionParser()

	parser.add_option("-c", "--configfile", dest="conffile", help="Config file", metavar="INIFILE")
	parser.add_option('-d', '--daemon', action='store_true', dest='daemon', help='Daemonize, go to background')
	parser.add_option('-T', '--test', action='store_true', dest='test', help='Test if all hosts are reachable')
	parser.add_option('-v', '--verbose', action='count', dest='verb', help='Verbose output')

	parser.set_defaults(conffile='/etc/rt4pnp/rt4pnp.ini')
	parser.set_defaults(verb=3)

	(options, args) = parser.parse_args()

	# Read config file
	config = ConfigParser.RawConfigParser()
	inis = config.read(options.conffile)

	if not inis:
		print 'Config file "%s" could not be read!' % options.conffile
		sys.exit(1)

	sections = config.sections()

	if options.verb >= 2:
		print 'Reading [global] sections...'

	globalcfg = read_config_global(config)
	if 'global' in sections:
		sections.remove('global')

	if options.verb >= 2:
		print 'Reading other sections...'

	hosts = read_config_sections(config, sections, globalcfg)

	if options.verb >= 3:
		import pprint
		pprint.pprint(hosts)
		pprint.pprint(globalcfg)

	# Test if all hosts could be reached
	if options.test:
		for host in hosts:
			print 'FIXME: Test for "%s"' % hosts[host]['host_name']


	# Daemonize
	if options.daemon:
		print 'FIXME: Not daemonizing ATM...'

	# Scheduler
	while True:
		time_start = time.time()
		counter_hosts = 0
		counter_ports = 0
		lines = []

		# Walk over hosts
		for host_name in hosts:
			host = hosts[host_name]

			if options.verb >= 2:
				print 'Now have a look at "%s"/"%s"/"%s"' % (host_name, host['host_name'], host['address'])

			nics_idx = snmp_get_idx(host)

			if not nics_idx:
				print 'WARNING: Got no information from "%s"/"%s"/"%s"' % (host_name, host['host_name'], host['address'])
			else:
				(nics_name, nics_byin, nics_byout) = snmp_get_data(host)
				if nics_name:
					counter_hosts += 1

				t = {}
				t['timet'] = int(time.time())
				t['host_name'] = re.sub('[^a-zA-Z0-9-_\.]', '_', host['host_name'])
				for i in xrange(0,len(nics_idx)):
					t['service_desc'] = 'Port_' + re.sub('[^a-zA-Z0-9-_\.]', '_', nics_name[i].lstrip().rstrip())
					t['service_perfdata'] = 'bytes_in=' + nics_byin[i] + 'c bytes_out=' + nics_byout[i] + 'c'
					lines.append(PERFDATATEMPL % t)
					counter_ports += 1
				del t

		file(os.path.join(globalcfg['pnpspoolpath'], 'rt4pnp-%s' % int(time.time())), 'w').writelines('\n'.join(lines))

		time_end = time.time()
		duration_run = time_end - time_start
		if options.verb >= 2:
			print 'This round took %.2f seconds, for %s ports on %s hosts' % (duration_run, counter_ports, counter_hosts)

		duration_sleep = globalcfg['interval'] - duration_run
		if duration_sleep < 0:
			print 'ERROR: Round took too long! Duration: %.2f, but interval is set to %.2f!' % (duration_run, globalcfg['interval'])
		else:
			if options.verb >= 2:
				print 'Sleeping for %.2f seconds...' % duration_sleep
			time.sleep(duration_sleep)



##############################################################################

if __name__ == '__main__':
	try:
		main()
	except KeyboardInterrupt:
		pass

