#!/bin/bash
#
# Copyright (C) 2016 - DMC Ingenieria SAS. http://dmci.co
# Author: Dorance Martinez  - dorancemc@gmail.com
# SPDX-License-Identifier: GPL-3.0+
#
# Descripcion: Descripcion
#
# Version: 0.2.0 - 18-feb-2023
#

USAGE="`basename $0` [-h]<host> "
if [ $# -ne 2 ]; then
  echo "$#"
  echo "Wrong Syntax: `basename $0` $*"
  echo ""
  echo "Usage: $USAGE"
  echo ""
  exit 0
fi
while [ $# -gt 0 ]
  do
    case "$1" in
      -h)
      shift
      host=$1
    ;;
    esac
    shift
  done


function cert_expdays(){
  nowtimestamp=$(date +%s)
  diffseconds=$((${1}-nowtimestamp))
  return $((diffseconds/86400))
}

output=$(echo "Q" | openssl s_client -connect ${host}:25 -starttls smtp -servername ${host} -verify_return_error 2>&1 | grep error | wc -l)
error=$(echo "Q" | openssl s_client -connect ${host}:25 -starttls smtp -servername ${host} -verify_return_error 2>&1 | grep error )
notAfter=$(echo "Q" | openssl s_client -starttls smtp -crlf -connect ${host}:25 -servername ${host} -showcerts | openssl x509 -noout -enddate | awk -F'=' '{print $2}' | sed 's/GMT//g' | xargs -I{} date -u -d "{}" +"%s" 2>/dev/null)

if [ $output -gt 0 ];
  then
    echo "CRITICAL: ${host} ${error} | error=${output}"
    exit 2
fi
if [ $output -eq 0 ];
  then
    if [ $(((notAfter - $(date +%s))/86400)) -le 5 ]; then
      echo "CRITICAL: ${host} certificate will expire soon | error=${output}"
      exit 2
    fi
    echo "OK: ${host} ${error} | error=${output}"
    exit 0
fi
