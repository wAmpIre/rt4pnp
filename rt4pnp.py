#!/usr/bin/env python

#####################################################################
# (c) 2010 by Sven Velt and team(ix) GmbH, Nuernberg, Germany       #
#             sv@teamix.net                                         #
#                                                                   #
# This file is part of RT4PNP.                                      #
#                                                                   #
# RT4PNP is free software: you can redistribute it and/or modify it #
# under the terms of the GNU General Public License as published by #
# the Free Software Foundation, either version 2 of the License, or #
# (at your option) any later version.                               #
#                                                                   #
# Foobar is distributed in the hope that it will be useful,         #
# but WITHOUT ANY WARRANTY; without even the implied warranty of    #
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the     #
# GNU General Public License for more details.                      #
#                                                                   #
# You should have received a copy of the GNU General Public License #
# along with RT4PNP.  If not, see <http://www.gnu.org/licenses/>.   #
#####################################################################

import ConfigParser
import optparse
import os
import re
import sys
import time

try:
	import netsnmp
except ImportError:
	pass

##############################################################################

PERFDATATEMPL = 'DATATYPE::SERVICEPERFDATA\tTIMET::%(timet)s\tHOSTNAME::%(host_name)s\tSERVICEDESC::%(service_desc)s\tSERVICEPERFDATA::%(service_perfdata)s\tSERVICECHECKCOMMAND::%(service_checkcommand)s\tHOSTSTATE::UP\tHOSTSTATETYPE::HARD\tSERVICESTATE::OK\tSERVICESTATETYPE::HARD'

CMDLINE_walk = '/usr/bin/snmpwalk -v%s -c%s -OqevtU %s %s 2>/dev/null'

##############################################################################

def daemonize(pidfile=None, stdin='/dev/null', stdout='/dev/null', stderr='/dev/null'):
	# 1st fork
	try:
		pid = os.fork()
		if pid > 0:
			sys.exit(0)
	except OSError, e:
		sys.stderr.write("1st fork failed: (%d) %s\n" % (e.errno, e.strerror))
		sys.exit(1)
	# Prepare 2nd fork
	os.chdir("/")
	os.umask(0)
	os.setsid( )
	# 2nd fork
	try:
		pid = os.fork()
		if pid > 0:
			sys.exit(0)
	except OSError, e:
		sys.stderr.write("2nd fork failed: (%d) %s\n" % (e.errno, e.strerror))
		sys.exit(1)

	# Try to write PID file
	if pidfile:
		pid = str(os.getpid())
		try:
			file(pidfile, 'w+').write('%s\n' % pid)
		except IOError:
			sys.stderr.write("Could not write PID file, exiting...\n")
			sys.exit(1)

	# Redirect stdin, stdout, stderr
	sys.stdout.flush()
	sys.stderr.flush()
	si = file(stdin, 'r')
	so = file(stdout, 'a+')
	se = file(stderr, 'a+', 0)
	os.dup2(si.fileno(), sys.stdin.fileno())
	os.dup2(so.fileno(), sys.stdout.fileno())
	os.dup2(se.fileno(), sys.stderr.fileno())

	return

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

	if config.has_option('global','write_internal_perfdata'):
		cfg['write_internal_perfdata'] = config.getboolean('global','write_internal_perfdata')
	else:
		cfg['write_internal_perfdata'] = True

	if config.has_option('global','pidfile'):
		cfg['pidfile'] = config.get('global','pidfile')
	else:
		cfg['pidfile'] = '/var/run/rt4pnp.pid'

	return cfg


def read_config_sections(config, sections, globalcfg):
	hosts = {}

	for section in sections:
		host = {}

		if config.has_option(section, 'host_name'):
			host['host_name'] = config.get(section, 'host_name')
		else:
			host['host_name'] = section

		if config.has_option(section, 'address'):
			host['address'] = config.get(section, 'address')
		else:
			host['address'] = host['host_name']

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


def SNMPWALK_netsnmp(oid, version, address, snmp_community):
	return netsnmp.snmpwalk(oid, Version=version, DestHost=address, Community=snmp_community)


def SNMPWALK_cmdline(oid, version, address, snmp_community):
	if version == 2:
		version = '2c'
	cmdline = CMDLINE_walk % (version, snmp_community, address, oid)

	cmd = os.popen(cmdline)

	out = cmd.readlines()
	retcode = cmd.close()

	if retcode != None:
		return ()

	for line in range(0,len(out)):
		out[line] = out[line].rstrip().replace('"','')
	return out


def snmp_get_idx(SNMPWALK, host):
	return SNMPWALK('.1.3.6.1.2.1.2.2.1.1', host['snmp_version'], host['address'], host['snmp_community'])


def snmp_get_data(SNMPWALK, host, required_ports):
	if host['snmp_version'] == 1:

		nics_name = SNMPWALK('.1.3.6.1.2.1.2.2.1.2', host['snmp_version'], host['address'], host['snmp_community'])
		nics_byin = SNMPWALK('.1.3.6.1.2.1.2.2.1.10', host['snmp_version'], host['address'], host['snmp_community'])
		nics_byout = SNMPWALK('.1.3.6.1.2.1.2.2.1.16', host['snmp_version'], host['address'], host['snmp_community'])

	elif host['snmp_version'] == 2:

		nics_name = SNMPWALK('.1.3.6.1.2.1.31.1.1.1.1', host['snmp_version'], host['address'], host['snmp_community'])
		nics_byin = SNMPWALK('.1.3.6.1.2.1.31.1.1.1.6', host['snmp_version'], host['address'], host['snmp_community'])
		nics_byout = SNMPWALK('.1.3.6.1.2.1.31.1.1.1.10', host['snmp_version'], host['address'], host['snmp_community'])
	else:
		return ([],[],[])

	if required_ports == len(nics_name) == len(nics_byin) == len(nics_byout):
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
#	parser.add_option("", "--path", dest="path", help="Path to snmpwalk")
	parser.add_option("", "--nonetsnmp", action="store_true", dest="nonetsnmp", help="Do not use NET-SNMP python bindings")
	parser.add_option('-v', '--verbose', action='count', dest='verb', help='Verbose output')

	parser.set_defaults(conffile='/etc/rt4pnp/rt4pnp.ini')
#	parser.set_defaults(path='')
	parser.set_defaults(verb=0)

	(options, args) = parser.parse_args()

	##### Detect NET-SNMP-Python bindings
	use_netsnmp = False

	if not options.nonetsnmp:
		try:
			import netsnmp
			use_netsnmp = True
		except ImportError:
			pass

	if use_netsnmp:
		if options.verb >=1:
			print "Using NET-SNMP Python bindings"
		SNMPWALK = SNMPWALK_netsnmp

	else:
		if options.verb >=1:
			print "Using NET-SNMP command line tools"
		SNMPWALK = SNMPWALK_cmdline

		if options.verb >=3:
			print "Using commandline: " + CMDLINE_walk

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

	if not options.test and not os.access(globalcfg['pnpspoolpath'],os.W_OK):
		print 'PNP4Nagios spool path "%s" is not writeable!' % globalcfg['pnpspoolpath']
		sys.exit(1)

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
		for host_name in hosts:
			host = hosts[host_name]
			sysDescr = SNMPWALK('.1.3.6.1.2.1.1.1', host['snmp_version'], host['address'], host['snmp_community'])
			if not sysDescr:
				print 'CRITICAL: No answer from "%s/%s/%s"'  % (host_name, host['host_name'], host['address'])
			else:
				print 'OK: "%s/%s/%s":   %s' % (host_name, host['host_name'], host['address'], sysDescr[0])
		sys.exit(0)


	# Daemonize
	if options.daemon:
		daemonize(pidfile=globalcfg['pidfile'])

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

			nics_idx = snmp_get_idx(SNMPWALK, host)

			if not nics_idx:
				print 'WARNING: Got no information from "%s"/"%s"/"%s"' % (host_name, host['host_name'], host['address'])
			else:
				(nics_name, nics_byin, nics_byout) = snmp_get_data(SNMPWALK, host, required_ports=len(nics_idx))
				if nics_name:
					counter_hosts += 1

				t = {}
				t['timet'] = int(time.time())
				t['host_name'] = re.sub('[^a-zA-Z0-9-_\.]', '_', host['host_name'])
				t['service_checkcommand'] = 'rt4pnp_v%d' % host['snmp_version']
				for i in xrange(0,len(nics_name)):
					t['service_desc'] = 'Port_' + re.sub('[^a-zA-Z0-9-_\.]', '_', nics_name[i].lstrip().rstrip())
					t['service_perfdata'] = 'bytes_in=' + nics_byin[i] + 'c bytes_out=' + nics_byout[i] + 'c'
					lines.append(PERFDATATEMPL % t)
					counter_ports += 1
				del t

		# Walked over all hosts, internal stats now
		duration_run = time.time() - time_start
		if options.verb >= 2:
			print 'This round took %.2f seconds, for %s ports on %s hosts' % (duration_run, counter_ports, counter_hosts)

		if globalcfg['write_internal_perfdata']:
			t = {}
			t['timet'] = int(time.time())
			t['host_name'] = 'rt4pnp-internal'
			t['service_desc'] = 'runtime informations'
			t['service_checkcommand'] = 'rt4pnp-internal'
			t['service_perfdata'] = 'ports=%s;;;0; hosts=%s;;;0;' % (counter_ports, counter_hosts)
			t['service_perfdata'] += 'runtime=%.3f;;%0.f;0; interval=%.0f;;;0;' % (duration_run, globalcfg['interval'], globalcfg['interval'])
			lines.append(PERFDATATEMPL % t)
			del t

		# Write perfdata file
		# FIXME: Exception handling is missing...
		file(os.path.join(globalcfg['pnpspoolpath'], 'rt4pnp-%s' % int(time.time())), 'w').writelines('\n'.join(lines))

		# Calculate for sleep
		duration_sleep = globalcfg['interval'] - (time.time() - time_start)
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

