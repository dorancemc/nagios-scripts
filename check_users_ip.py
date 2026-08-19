#!/usr/bin/env python3
#
# Copyright (C) 2016 - DMC Ingenieria SAS. http://dmci.co
# Author: Jaime Andres Cardona jacardona@outlook.com
# SPDX-License-Identifier: GPL-3.0+
#
# Descripcion: Script de validacion de usuarios
# Version: 0.2 - port a Python de check_users_ip.pl
#
# Objetivo      : Conocer los usuarios conectados con el comando who, sin que se repita
#                 informacion de las ip(s) desde donde se conectan
#
# Nota sobre el port: el original evaluaba exit($STATUSCODE{...}) contra un hash que nunca
# fue declarado (el declarado es %RETCODES), por lo que siempre terminaba con codigo 0 y
# Nagios nunca alertaba. Aqui se devuelven los codigos reales 0/1/2/3. El parseo de who,
# el conteo, la deduplicacion por subcadena y el texto de salida quedan identicos.
#

import subprocess
import sys

RETCODES = {'UNKNOWN': 3, 'OK': 0, 'WARNING': 1, 'CRITICAL': 2}

USAGE = """Use: ./check_users_ip.py -w # -c #
opciones:
		-w numero warning de conexiones
		-c numero critical de conexiones
Ejemplo: ./check_users_ip.py -w 2 -c 4
"""


def parse_args(argv):
    """Replica el manejo de opciones del original: exige 4 argumentos y lee -w y -c."""
    if len(argv) < 4:
        print(USAGE, end='')
        sys.exit(RETCODES['UNKNOWN'])

    warning = None
    critical = None
    i = 0
    try:
        while i < len(argv):
            if argv[i] == '-w' and i + 1 < len(argv):
                warning = int(argv[i + 1])
                i += 2
            elif argv[i] == '-c' and i + 1 < len(argv):
                critical = int(argv[i + 1])
                i += 2
            else:
                i += 1
    except ValueError:
        print(USAGE, end='')
        sys.exit(RETCODES['UNKNOWN'])

    if warning is None or critical is None:
        print(USAGE, end='')
        sys.exit(RETCODES['UNKNOWN'])

    return warning, critical


def read_connections():
    """Cuenta sesiones de 'who' descartando las que repiten origen.

    who
    root     pts/0        2016-07-13 09:07 (fredy_portatil.tecnoquimicas.com)
    oraprod  pts/1        2016-07-13 10:58 (10.0.50.2)
    nagios   pts/2        2016-07-13 11:19 (172.22.4.219)

    La comparacion es por subcadena sobre el acumulado, igual que el index() del original:
    una sesion sin campo de origen produce la cadena vacia, que siempre "ya esta presente"
    y por lo tanto nunca se cuenta.
    """
    contador = 0
    resultado = ""

    try:
        proc = subprocess.run(['who'], stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL, universal_newlines=True)
    except OSError as err:
        print("UNKNOWN - no se pudo ejecutar who: %s" % err)
        sys.exit(RETCODES['UNKNOWN'])

    for linea in proc.stdout.splitlines():
        campos = linea.split()
        strlogin = campos[0] if len(campos) > 0 else ''
        strtype = campos[1] if len(campos) > 1 else ''
        strsource = campos[4] if len(campos) > 4 else ''

        if strsource not in resultado:
            resultado += "%s,%s,%s\n" % (strlogin, strtype, strsource)
            contador += 1

    return contador, resultado


def main():
    warning, critical = parse_args(sys.argv[1:])
    contador, resultado = read_connections()

    perf = "'conn'=%d;%d;%d;0;%d" % (contador, warning, critical, critical)

    if contador >= critical:
        estado = 'CRITICAL'
    elif contador >= warning:
        estado = 'WARNING'
    else:
        estado = 'OK'

    print("%s - %d usuarios actualmente logueados | %s\n%s" % (estado, contador, perf, resultado), end='')
    sys.exit(RETCODES[estado])


if __name__ == '__main__':
    main()
