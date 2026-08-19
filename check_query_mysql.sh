#!/bin/bash
#
# Copyright (C) 2016 - DMC Ingenieria SAS. http://dmci.co
# Author: <nombre completo> - <correo electronico>
# SPDX-License-Identifier: GPL-3.0+
#
# Descripcion: Descripcion
#
# Version: 0.1.0 - dd-mmm-aaaa
#

USAGE="`basename $0` [-q]<my_query> [-u]<my_user> [-p]<my_passwd> [-db]<my_db> [-h]<my_host> [-w|--warning]<warning> [-c|--critical]<critical> [-t]<informational_text> [-P]<parameter>"
THRESHOLD_USAGE="CRITICAL threshold must be greater than WARNING: `basename $0` $*"
if [ $# -lt 18 ]; then
	echo ""
	echo "Wrong Syntax: `basename $0` $*"
	echo ""
	echo "Usage: $USAGE"
	echo ""
	exit 0
fi
while [ $# -gt 0 ]
  do
        case "$1" in
               -q)
               shift
               my_query=$1
        ;;
               -u)
               shift
               my_user=$1
        ;;
               -p)
               shift
               my_passwd=$1
        ;;
               -db)
               shift
               my_db=$1
        ;;
               -h)
               shift
               my_host=$1
        ;;
               -w|--warning)
               shift
               warning=$1
        ;;
               -c|--critical)
               shift
               critical=$1
        ;;
               -t)
               shift
               info_text=$1
        ;;
               -P)
               shift
               parameter=$1
        ;;
        esac
        shift
  done

if [ $warning -eq $critical ] || [ $warning -gt $critical ]
then
	echo ""
	echo "$THRESHOLD_USAGE"
	echo ""
        echo "Usage: $USAGE"
	echo ""
        exit 0
fi

output=$(mysql -u ${my_user} -p"${my_passwd}" -D ${my_db} -h ${my_host} -N -s -e "${my_query}")


if [ $output -gt $critical ];
	then
		echo "CRITICAL: ${info_text} ${parameter} = $output | ${parameter}=$output;$warning;$critical"
		exit 2
fi
if [ $output -gt $warning ];
        then
		echo "WARNING: ${info_text} ${parameter} = $output | ${parameter}=$output;$warning;$critical"
                exit 1
fi
if [ $output -le $warning ];
        then
		echo "OK: ${info_text} ${parameter} = $output | ${parameter}=$output;$warning;$critical"
                exit 0
fi
