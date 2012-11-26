#!/usr/bin/env python
# -*- encoding: utf-8 -*-

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
import signal
import sys
import time

class RT4PNP(object):

	PERFDATATEMPL = 'DATATYPE::SERVICEPERFDATA\tTIMET::%(timet)s\tHOSTNAME::%(host_name)s\tSERVICEDESC::%(service_desc)s\tSERVICEPERFDATA::%(service_perfdata)s\tSERVICECHECKCOMMAND::%(service_checkcommand)s\tHOSTSTATE::UP\tHOSTSTATETYPE::HARD\tSERVICESTATE::OK\tSERVICESTATETYPE::HARD'

	CMDLINE_walk_12 = '/usr/bin/snmpwalk -v%s -c%s -OqevtU %s %s 2>/dev/null'
	CMDLINE_get_12 = '/usr/bin/snmpget -v%s -c%s -OqevtU %s %s 2>/dev/null'

	OID = [ None,
		{
			'name': '.1.3.6.1.2.1.2.2.1.2',
			'byin': '.1.3.6.1.2.1.2.2.1.10',
			'byout': '.1.3.6.1.2.1.2.2.1.16',
		},
		{
			'name': '.1.3.6.1.2.1.31.1.1.1.1',
			'byin': '.1.3.6.1.2.1.31.1.1.1.6',
			'byout': '.1.3.6.1.2.1.31.1.1.1.10',
		},
		{
			'name': '.1.3.6.1.2.1.31.1.1.1.1',
			'byin': '.1.3.6.1.2.1.31.1.1.1.6',
			'byout': '.1.3.6.1.2.1.31.1.1.1.10',
		},
		]


	def __init__(self, *args, **kwargs):
		self.netsnmp = None # Placeholder for NET:SNMP Python Bindings
		self.use_netsnmp = False
		self.parser = None
		self.clean_string = re.compile('[^a-zA-Z0-9-_\.]')

		self.read_cmdline_options()
		self.read_inifile()

		if self.options.verb >= 3:
			import pprint
			pprint.pprint(self.cfg_global)
			pprint.pprint(self.hosts)

		if self.options.test:
			self.run_test()
			sys.exit(0)

		return


	def daemonize(pidfile=None, stdin='/dev/null', stdout='/dev/null', stderr='/dev/null'):
		try:
			# 1st fork
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
		try:
			# 2nd fork
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


	def SNMPWALK_netsnmp(self, host, oid):
		return self.netsnmp.snmpwalk(oid, Version=host['snmp_version'], DestHost=host['address'], Community=host['snmp_community'])


	def SNMPGET_netsnmp(self, host, oids):
		if type(oids) == str:
			oids = [oids, ]

		#oids = self.netsnmp.VarList(*oids)
		self.netsnmp.VarList(*oids)
		return self.netsnmp.snmpget(Version=host['snmp_version'], DestHost=host['address'], Community=host['snmp_community'], *oids)


	def SNMPWALK_cmdline(self, host, oid):
		version = host['snmp_version']
		if version == 2:
			version = '2c'
		cmdline = self.CMDLINE_walk_12 % (version, host['snmp_community'], host['address'], oid)

		cmd = os.popen(cmdline)

		out = cmd.readlines()
		retcode = cmd.close()

		if retcode != None:
			return ()

		for line in range(0,len(out)):
			out[line] = out[line].rstrip().replace('"','')
		return out


	def SNMPGET_cmdline(self, host, oids):
		if type(oids) == str:
			oids = [oids, ]

		version = host['snmp_version']
		if version == 2:
			version = '2c'
		cmdline = self.CMDLINE_get_12 % (version, host['snmp_community'], host['address'], " ".join(oids))

		cmd = os.popen(cmdline)

		out = cmd.readlines()
		retcode = cmd.close()

		if retcode != None:
			return ()

		for line in range(0,len(out)):
			out[line] = out[line].rstrip().replace('"','')
		return out


	def read_cmdline_options(self):
		self.parser = optparse.OptionParser()

		self.parser.add_option("-c", "--configfile", dest="conffile", help="Config file", metavar="INIFILE")
		self.parser.add_option('-d', '--daemon', action='store_true', dest='daemon', help='Daemonize, go to background')
		self.parser.add_option('-T', '--test', action='store_true', dest='test', help='Test if all hosts are reachable')
		# self.parser.add_option("", "--path", dest="path", help="Path to snmpwalk")
		self.parser.add_option("", "--nonetsnmp", action="store_true", dest="nonetsnmp", help="Do not use NET-SNMP python bindings")
		self.parser.add_option('-v', '--verbose', action='count', dest='verb', help='Verbose output')

		self.parser.set_defaults(conffile='/etc/rt4pnp/rt4pnp.ini')
		# self.parser.set_defaults(path='')
		self.parser.set_defaults(verb=0)

		(self.options, self.args) = self.parser.parse_args()

		##### Detect NET-SNMP-Python bindings
		use_netsnmp = False

		if not self.options.nonetsnmp:
			try:
				self.netsnmp = __import__('netsnmp')
				self.use_netsnmp = True
			except ImportError:
				pass

		if self.use_netsnmp:
			self.SNMPWALK = self.SNMPWALK_netsnmp
			self.SNMPGET = self.SNMPGET_netsnmp

			if self.options.verb >=1:
				print "Using NET-SNMP Python bindings"

		else:
			self.SNMPWALK = self.SNMPWALK_cmdline
			self.SNMPGET = self.SNMPGET_cmdline

			if self.options.verb >=1:
				print "Using NET-SNMP command line tools"


	def read_inifile(self):
		config = ConfigParser.RawConfigParser()
		config.optionxform = str # We need case-sensitive options
		inis = config.read(self.options.conffile)

		if not inis:
			print 'Config file "%s" could not be read!' % self.options.conffile
			sys.exit(1)

		sections = config.sections()

		if self.options.verb >= 2:
			print 'Reading [global] sections...'
		self.cfg_global = self.read_inifile_global(config)

		if not self.options.test and not os.access(self.cfg_global['pnpspoolpath'],os.W_OK):
			print 'PNP4Nagios spool path "%s" is not writeable!' % self.cfg_global['pnpspoolpath']
			sys.exit(1)

		if self.options.verb >= 2:
			print 'Reading other sections...'

		self.hosts = self.read_inifile_hosts(config)

		if self.options.verb >= 3:
			import pprint
			pprint.pprint(self.hosts)
			pprint.pprint(self.cfg_global)

		return


	def read_inifile_global(self, config):
		cfg = {}

		if config.has_option('global','pnpspoolpath'):
			cfg['pnpspoolpath'] = config.get('global','pnpspoolpath')
		else:
			cfg['pnpspoolpath'] = '/var/spool/pnp4nagios/npcd'

		if config.has_option('global','interval'):
			cfg['interval'] = config.getint('global','interval')
		else:
			cfg['interval'] = 120

		if config.has_option('global','snmp_community'):
			cfg['snmp_community'] = config.get('global','snmp_community')
		else:
			cfg['snmp_community'] = 'public'

		if config.has_option('global','snmp_version'):
			cfg['snmp_version'] = self.normalize_snmp_version(config.get('global','snmp_version'))
		else:
			cfg['snmp_version'] = self.normalize_snmp_version(2)

		if config.has_option('global','write_internal_perfdata'):
			cfg['write_internal_perfdata'] = config.getboolean('global','write_internal_perfdata')
		else:
			cfg['write_internal_perfdata'] = True

		if config.has_option('global','pidfile'):
			cfg['pidfile'] = config.get('global','pidfile')
		else:
			cfg['pidfile'] = '/var/run/rt4pnp.pid'

		return cfg


	def read_inifile_hosts(self, config):
		sections = config.sections()
		if 'global' in sections:
			sections.remove('global')

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
				host['snmp_version'] = self.normalize_snmp_version(config.get(section, 'snmp_version'))
			else:
				host['snmp_version'] = self.normalize_snmp_version(self.cfg_global['snmp_version'])

			if config.has_option(section, 'snmp_community'):
				host['snmp_community'] = config.get(section, 'snmp_community')
			else:
				host['snmp_community'] = self.cfg_global['snmp_community']

			hosts[section] = host

		return hosts


	def normalize_snmp_version(self, version):
		if version in [1,'1']:
			return 1
		elif version in [2,'2','2c']:
			return 2
		# elif version in [3,'3']:
		#	return 3
		else:
			print 'Unknow SNMP version "%s"!' % version
			sys.exit(1)


	def run_test(self):
		for host_name in self.hosts:
			host = self.hosts[host_name]
			sysDescr = self.SNMPWALK(host, '.1.3.6.1.2.1.1.1')
			if not sysDescr:
				print 'CRITICAL: No answer from "%s/%s/%s"'  % (host_name, host['host_name'], host['address'])
			else:
				print 'OK: "%s/%s/%s":   %s' % (host_name, host['host_name'], host['address'], sysDescr[0])


	def snmp_get_idx(self, host):
		return self.SNMPWALK(host, '.1.3.6.1.2.1.2.2.1.1')


	def snmp_get_data(self, host, idxs):
		nics_name = self.SNMPGET(host, ['.'.join([self.OID[host['snmp_version']]['name'],i]) for i in idxs])
		nics_byin = self.SNMPGET(host, ['.'.join([self.OID[host['snmp_version']]['byin'],i]) for i in idxs])
		nics_byout = self.SNMPGET(host, ['.'.join([self.OID[host['snmp_version']]['byout'],i]) for i in idxs])

		return (nics_name, nics_byin, nics_byout)


	def verbose_hostname(self, host):
		return '"%s"/"%s"' % (host['host_name'], host['address'])


	def collector(self):
		time_start = time.time()
		counter_hosts = 0
		counter_ports = 0
		lines = []

		# Walk over hosts
		for host_name in self.hosts:
			host = self.hosts[host_name]

			if self.options.verb >= 2:
				print 'Now have a look at %s' % self.verbose_hostname(host)

			nics_idx = self.snmp_get_idx(host)

			if not nics_idx:
				print 'WARNING: Got no information from %s' % self.verbose_hostname(host)
			else:
				(nics_name, nics_byin, nics_byout) = self.snmp_get_data(host, nics_idx)

				t = {}
				t['timet'] = int(time.time())
				t['host_name'] = self.clean_string.sub('_', host['host_name'])
				t['service_checkcommand'] = 'rt4pnp_v%d' % host['snmp_version']
				if self.options.verb >= 3:
					print 'Length of tables: %s %s %s %s' % (len(nics_idx), len(nics_name), len(nics_byin), len(nics_byout))
				if len(nics_idx) == len(nics_name) == len(nics_byin) == len(nics_byout):
					for i in xrange(0,len(nics_name)):
						if nics_name[i] != None and nics_byin[i] != None and nics_byout != None:
							t['service_desc'] = 'Port_' + self.clean_string.sub('_', nics_name[i].lstrip().rstrip())
							t['service_perfdata'] = 'bytes_in=' + nics_byin[i] + 'c bytes_out=' + nics_byout[i] + 'c'
							lines.append(self.PERFDATATEMPL % t)
							counter_ports += 1
					del t

					if counter_ports > 0:
						counter_hosts += 1
				else:
					if self.options.verb >= 3:
						print 'WHUPS! Lengths do NOT match!'

		# Walked over all hosts, internal stats now
		duration_run = time.time() - time_start
		if self.options.verb >= 2:
			print 'This round took %.2f seconds, for %s ports on %s hosts' % (duration_run, counter_ports, counter_hosts)

		if self.cfg_global['write_internal_perfdata']:
			t = {}
			t['timet'] = int(time.time())
			t['host_name'] = '.rt4pnp-internal'
			t['service_desc'] = 'runtime informations'
			t['service_checkcommand'] = 'rt4pnp-internal'
			t['service_perfdata'] = 'ports=%s;;;0; hosts=%s;;;0;' % (counter_ports, counter_hosts)
			t['service_perfdata'] += 'runtime=%.3f;;%0.f;0; ' % (duration_run, self.cfg_global['interval'])
			t['service_perfdata'] += 'interval=%.0f;;;0;' % self.cfg_global['interval']
			lines.append(self.PERFDATATEMPL % t)
			del t

		# Write perfdata file
		try:
			file(os.path.join(self.cfg_global['pnpspoolpath'], 'rt4pnp-%s' % int(time.time())), 'w').writelines('\n'.join(lines))
		except IOError, error:
			print 'CRITICAL: ' + error

		return (counter_hosts, counter_ports)


	def scheduler(self):
		counter_rounds = 0
		counter_hosts = 0
		counter_ports = 0

		while not self.quit_scheduler:
			if self.reread_config:
				self.read_inifile()
				self.reread_config = False

			time_start = time.time()
			(c_hosts, c_ports) = self.collector()
			counter_rounds += 1
			counter_hosts += c_hosts
			counter_ports += c_ports

			duration_run = time.time() - time_start
			duration_sleep = self.cfg_global['interval'] - duration_run
			if duration_sleep < 0:
				print 'CRITICAL: Round took too long! Duration: %.2f, but interval is set to %.2f!' % (duration_run, self.cfg_global['interval'])
			else:
				if self.quit_scheduler:
					sys.exit(0)

				self.scheduler_sleep = True
				if self.options.verb >= 2:
					print 'Sleeping for %.2f seconds...\n' % duration_sleep
				time.sleep(duration_sleep)
				self.scheduler_sleep = False

		return


	def signal_handler(self, sig, frame):
		print 'Received SIGNAL %s on PID %s' % (sig, self.pid)
		if sig == signal.SIGHUP:
			self.reread_config = True
			return
		elif sig in [signal.SIGTERM, signal.SIGINT]:
			if self.scheduler_sleep:
				sys.exit(0)
			self.quit_scheduler = True
			return


	def startup(self):
		self.quit_scheduler = False
		self.scheduler_sleep = False
		self.reread_config = False
		signal.signal(signal.SIGHUP, self.signal_handler)
		signal.signal(signal.SIGINT, self.signal_handler)
		signal.signal(signal.SIGTERM, self.signal_handler)
		self.scheduler()


	def main(self):
		if self.options.daemon:
			self.daemonize(self.cfg_global['pidfile'])

		self.pid = os.getpid()
		self.startup()

		sys.exit(0)



if __name__ == '__main__':
	try:
		rt4pnp = RT4PNP()
		rt4pnp.main()
	except KeyboardInterrupt:
		pass

