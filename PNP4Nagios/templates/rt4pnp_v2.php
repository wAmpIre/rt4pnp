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
# For faked "rt4pnp" plugin/check command
#
$opt[1] = " --vertical-label \"Traffic\" -b 1000 --title \"Interface Traffic for $hostname / $servicedesc\" ";

$ds_name[1] = "Interface Traffic in Bits/sec";

$def[1] = "DEF:bytesin=$RRDFILE[1]:$DS[1]:AVERAGE " ;
$def[1] .= "DEF:bytesout=$RRDFILE[2]:$DS[2]:AVERAGE " ;
$def[1] .= "CDEF:bitsin=bytesin,8,* ";
$def[1] .= "CDEF:bitsout=bytesout,8,* ";
$def[1] .= "AREA:bitsin#00FF00:\"in  \" " ;
$def[1] .= "GPRINT:bitsin:LAST:\"%7.2lf %Sb/s last\" " ;
$def[1] .= "GPRINT:bitsin:AVERAGE:\"%7.2lf %Sb/s avg\" " ;
$def[1] .= "GPRINT:bitsin:MAX:\"%7.2lf %Sb/s max\\n\" " ;
$def[1] .= "LINE2:bitsout#0000FF:\"out \" " ;
$def[1] .= "GPRINT:bitsout:LAST:\"%7.2lf %Sb/s last\" " ;
$def[1] .= "GPRINT:bitsout:AVERAGE:\"%7.2lf %Sb/s avg\" " ;
$def[1] .= "GPRINT:bitsout:MAX:\"%7.2lf %Sb/s max\\n\" ";
if($this->MACRO['TIMET'] != ""){
    $def[1] .= "VRULE:".$this->MACRO['TIMET']."#000000:\"Last Service Check \\n\" ";
}
?>
