<?php
#
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
#
# For faked "rt4pnp-internal" plugin/check command
#
$opt[1] = " --vertical-label \"Count\" -b 1000 --title \"Statistics of collected hosts and ports\" ";

$ds_name[1] = "Collected hosts/ports";

$def[1] = "DEF:ports=$RRDFILE[1]:$DS[1]:MAX ";
$def[1] .= "DEF:hosts=$RRDFILE[2]:$DS[2]:MAX ";
$def[1] .= "CDEF:pperh=ports,hosts,/ ";
$def[1] .= "AREA:ports#0000FF:\" Ports          \" ";
$def[1] .= "GPRINT:ports:LAST:\"%5.1lf last,\" ";
$def[1] .= "GPRINT:ports:AVERAGE:\"%5.1lf avg,\" ";
$def[1] .= "GPRINT:ports:MAX:\"%5.1lf max\\n\" ";
$def[1] .= "AREA:hosts#FFFF00:\" Hosts          \" ";
$def[1] .= "GPRINT:hosts:LAST:\"%5.1lf last,\" ";
$def[1] .= "GPRINT:hosts:AVERAGE:\"%5.1lf avg,\" ";
$def[1] .= "GPRINT:hosts:MAX:\"%5.1lf max\\n\" ";
$def[1] .= "LINE1:pperh#000000:\" Ports per host \" ";
$def[1] .= "GPRINT:pperh:LAST:\"%5.1lf last,\" ";
$def[1] .= "GPRINT:pperh:AVERAGE:\"%5.1lf avg,\" ";
$def[1] .= "GPRINT:pperh:MAX:\"%5.1lf max\\n\" ";


$opt[2] = " --vertical-label \"Time\" -b 1000 --title \"Time statistics\" ";

$ds_name[2] = "Time statistics";

$def[2] = "DEF:runtime=$RRDFILE[3]:$DS[3]:MAX ";
$def[2] .= "DEF:interval=$RRDFILE[4]:$DS[4]:MAX ";
$def[2] .= "AREA:runtime#FFFF00:\" Runtime    \" ";
$def[2] .= "GPRINT:runtime:LAST:\"%5.2lf sec last,\" ";
$def[2] .= "GPRINT:runtime:AVERAGE:\"%5.2lf sec avg,\" ";
$def[2] .= "GPRINT:runtime:MAX:\"%5.2lf sec max\\n\" ";
$def[2] .= "LINE1:runtime#000000 ";
if($WARN[2] != "") {
	$def[2] .= "HRULE:".$WARN[2]."#FFFF00:\"Warning  ".$WARN[2].$UNIT[2]." \\n\" ";
}
if($CRIT[2] != "") {
	$def[2] .= "HRULE:".$CRIT[2]."#FF0000:\"Critical ".$CRIT[2].$UNIT[2]." \\n\" ";
}
?>
