#!/usr/bin/env python3
#
# Nagios plugin para monitorear interfaces de red remotas por SNMP.
#
# Derivado del modo SNMP de check_netint.pl / check_snmp_netint.pl v2.4a9
#   (c)2004-2007 Patrick Proy, (c)2007-2012 William Leibzon
# SPDX-License-Identifier: GPL-2.0+
#
# Para interfaces del propio servidor Linux use check_netint.py.
#
# El transporte SNMP son los binarios de net-snmp-utils (snmpget, snmpwalk, snmpbulkwalk)
# invocados por subprocess, en vez de la libreria Net::SNMP de Perl. No hay dependencias
# de pip: esos binarios ya estan en cualquier poller de Nagios porque check_snmp los usa.
#
# Dos consecuencias de ese cambio de transporte, ambas sin efecto sobre los resultados:
#
#   1. -o/--octetlength se acepta y se valida por compatibilidad de linea de comandos,
#      pero net-snmp administra el tamano del mensaje por su cuenta. En su lugar las
#      consultas se parten en bloques de OIDs, que resuelve el mismo problema de fondo
#      ("Message size exceeded maxMsgSize") sin tener que calibrar un numero a mano.
#   2. --bulk_snmp_queries cambia los recorridos de tabla a snmpbulkwalk. Sobre lecturas
#      de instancias puntuales no hace nada, porque net-snmp ya las agrupa en un PDU.
#
# Sobre credenciales: net-snmp las recibe por linea de comandos, asi que quedan visibles
# en 'ps' para otros usuarios del poller mientras dura la consulta. La invocacion del
# propio plugin ya las expone igual, de modo que no es una via nueva, pero si un proceso
# mas. En hosts compartidos conviene dejar las credenciales v3 en ~/.snmp/snmp.conf del
# usuario nagios (defSecurityName, defAuthPassphrase, defPrivPassphrase) y no pasar -l/-x/-X.
# En el log de -v las credenciales salen ocultas.
#
# La seleccion por regexp, los estados, umbrales, calculo de tasas, cache de indices en
# perfdata, tablas Cisco, STP y el formato de salida se comportan igual que el original.
#

import re
import signal
import subprocess
import sys
import time

import netint_common as nc

INDEX_TABLE = '1.3.6.1.2.1.2.2.1.1'
DESCR_TABLE = '1.3.6.1.2.1.2.2.1.2'
OPER_TABLE = '1.3.6.1.2.1.2.2.1.8.'
ADMIN_TABLE = '1.3.6.1.2.1.2.2.1.7.'
SPEED_TABLE = '1.3.6.1.2.1.2.2.1.5.'
SPEED_TABLE_64 = '1.3.6.1.2.1.31.1.1.1.15.'
IN_OCTET_TABLE = '1.3.6.1.2.1.2.2.1.10.'
IN_OCTET_TABLE_64 = '1.3.6.1.2.1.31.1.1.1.6.'
IN_ERROR_TABLE = '1.3.6.1.2.1.2.2.1.14.'
IN_DISCARD_TABLE = '1.3.6.1.2.1.2.2.1.13.'
OUT_OCTET_TABLE = '1.3.6.1.2.1.2.2.1.16.'
OUT_OCTET_TABLE_64 = '1.3.6.1.2.1.31.1.1.1.10.'
OUT_ERROR_TABLE = '1.3.6.1.2.1.2.2.1.20.'
OUT_DISCARD_TABLE = '1.3.6.1.2.1.2.2.1.19.'

CISCO_PORT_NAME_TABLE = '1.3.6.1.4.1.9.5.1.4.1.1.4'
CISCO_PORT_IFINDEX_MAP = '1.3.6.1.4.1.9.5.1.4.1.1.11'
CISCO_PORT_LINKFAULTSTATUS_TABLE = '1.3.6.1.4.1.9.5.1.4.1.1.22.'
CISCO_PORT_OPERSTATUS_TABLE = '1.3.6.1.4.1.9.5.1.4.1.1.6.'
CISCO_PORT_ADDOPERSTATUS_TABLE = '1.3.6.1.4.1.9.5.1.4.1.1.23.'

CISCO_LINKFAULTSTATUS = {1: 'UP', 2: 'nearEndFault', 3: 'nearEndConfigFail',
                         4: 'farEndDisable', 5: 'farEndFault', 6: 'farEndConfigFail',
                         7: 'otherFailure'}
CISCO_OPERSTATUS = {0: 'operstatus:unknown', 1: 'operstatus:other', 2: 'operstatus:ok',
                    3: 'operstatus:minorFault', 4: 'operstatus:majorFault'}
CISCO_ADDOPERSTATUS = {0: 'other', 1: 'connected', 2: 'standby', 3: 'faulty',
                       4: 'notConnected', 5: 'inactive', 6: 'shutdown', 7: 'dripDis',
                       8: 'disable', 9: 'monitor', 10: 'errdisable', 11: 'linkFaulty',
                       12: 'onHook', 13: 'offHook', 14: 'reflector'}

STP_IFINDEX_MAP = '1.3.6.1.2.1.17.1.4.1.2'
STP_PORTSTATE = '1.3.6.1.2.1.17.2.15.1.3.'
STP_PORTSTATE_NAMES = {0: 'unknown', 1: 'disabled', 2: 'blocking', 3: 'listening',
                       4: 'learning', 5: 'forwarding', 6: 'broken'}

STP_WARNTIME = 900
RECACHE_TRIGGER = 43200
RECACHE_MAX = 259200
OIDS_PER_REQUEST = 50

NO_SUCH = re.compile(r'No Such (Instance|Object)', re.IGNORECASE)


def build_parser():
    parser = nc.PluginParser(
        prog='check_snmp_netint.py',
        description='Network Interfaces Monitor Plugin for Nagios (SNMP) v. ' + nc.VERSION,
        epilog='GPL 2.0 or 3.0 licence, (c)2004-2007 Patrick Proy, (c)2007-2012 William Leibzon')
    nc.add_common_arguments(parser)

    parser.add_argument('-H', '--hostname', default=None)
    parser.add_argument('-p', '--port', type=int, default=161)
    parser.add_argument('-C', '--community', default=None)
    parser.add_argument('-2', '--v2c', action='store_true')
    parser.add_argument('-l', '--login', default=None)
    parser.add_argument('-x', '--passwd', default=None)
    parser.add_argument('-X', '--privpass', default=None)
    parser.add_argument('-L', '--protocols', default=None)
    parser.add_argument('-o', '--octetlength', type=int, default=None)
    parser.add_argument('-N', '--descrname_oid', default=None)
    parser.add_argument('-O', '--optionaltext_oid', default=None)
    parser.add_argument('-g', '--64bits', dest='highperf', action='store_true')
    parser.add_argument('-m', dest='minsnmp', action='count', default=0)
    parser.add_argument('--minimize_queries', dest='minimize_queries', action='store_true')
    parser.add_argument('--minimum_queries', dest='minimum_queries', action='store_true')
    parser.add_argument('--bulk_snmp_queries', action='store_true')
    parser.add_argument('--cisco', nargs='?', const='', default=None)
    parser.add_argument('--stp', nargs='?', const='', default=None)
    return parser


def validate_snmp_options(opts, parser):
    """Reproduce las validaciones SNMP de check_options() del original."""
    if opts.hostname is None:
        nc.exit_usage(parser, "Specify hostname with -H. To check the local server "
                              "use check_netint.py instead.")
    if (opts.name is None and opts.community is None
            and (opts.login is None or opts.passwd is None)):
        nc.exit_usage(parser, "Specify community and put snmp login info!")
    if ((opts.login is not None or opts.passwd is not None)
            and (opts.community is not None or opts.v2c)):
        nc.exit_usage(parser, "Can't mix snmp v1,2c,3 protocols!")

    authproto, privproto = 'md5', 'des'
    if opts.protocols is not None:
        if opts.login is None:
            nc.exit_usage(parser, "Put snmp V3 login info with protocols!")
        parts = opts.protocols.split(',')
        if parts and parts[0]:
            authproto = parts[0]
        if len(parts) > 1:
            privproto = parts[1]
            if opts.privpass is None:
                nc.exit_usage(parser, "Put snmp V3 priv login info with priv protocols!")

    maxmin = opts.minimum_queries or opts.minsnmp >= 2
    minimize = opts.minimize_queries or opts.minsnmp >= 1
    if maxmin and (opts.minimize_queries or opts.minsnmp == 1):
        nc.exit_usage(parser, "You dont need to use -m when you already specified -mm.")
    if maxmin:
        minimize = True

    if opts.highperf and not opts.v2c and opts.community is not None:
        nc.exit_usage(parser, "Can't get 64 bit counters with snmp version 1")

    if opts.optionaltext_oid is not None:
        if '.' not in opts.optionaltext_oid:
            nc.exit_usage(parser, "Comment OID is not specified or is not valid")
        if not opts.optionaltext_oid.endswith('.'):
            opts.optionaltext_oid += '.'

    if opts.octetlength is not None and (opts.octetlength > 65535 or opts.octetlength < 484):
        nc.exit_usage(parser, "octet length must be < 65535 and > 484")

    cisco = {}
    descr_table = opts.descrname_oid if opts.descrname_oid else DESCR_TABLE
    if opts.cisco is not None:
        for token in opts.cisco.split(','):
            if token:
                cisco[token] = token
        if 'use_portnames' in cisco:
            if opts.descrname_oid:
                nc.exit_usage(parser, "Can not use -N when --cisco=use_portnames option is used")
            descr_table = CISCO_PORT_NAME_TABLE
        elif 'show_portnames' in cisco:
            if opts.optionaltext_oid:
                nc.exit_usage(parser, "Can not use -O when --cisco=show_portnames option is used")
            opts.optionaltext_oid = CISCO_PORT_NAME_TABLE
        if not any(key in cisco for key in ('oper', 'addoper', 'linkfault', 'noauto')):
            cisco['auto'] = 'auto'
        nc.verb("Cisco Options: " + ','.join(cisco.keys()))

    stp_reverse = dict((name, code) for code, name in STP_PORTSTATE_NAMES.items())
    if opts.stp:
        if opts.stp not in stp_reverse:
            nc.exit_usage(parser, "Incorrect STP state specified after --stp=")

    return {
        'authproto': authproto,
        'privproto': privproto,
        'minimize': minimize,
        'maxmin': maxmin,
        'cisco': cisco,
        'descr_table': descr_table,
        'stp_reverse': stp_reverse,
    }


def snmp_base_args(opts, snmp):
    args = []
    if opts.login is not None and opts.passwd is not None:
        args += ['-v', '3', '-u', opts.login,
                 '-a', snmp['authproto'].upper(), '-A', opts.passwd]
        if opts.privpass is not None:
            args += ['-x', snmp['privproto'].upper(), '-X', opts.privpass, '-l', 'authPriv']
        else:
            args += ['-l', 'authNoPriv']
    elif opts.v2c:
        args += ['-v', '2c', '-c', opts.community]
    else:
        args += ['-v', '1', '-c', opts.community]
    args += ['-t', str(opts.timeout), '-r', '1', '-Onq', '-Ln']
    return args


def snmp_target(opts):
    if opts.port and opts.port != 161:
        return '%s:%d' % (opts.hostname, opts.port)
    return opts.hostname


def snmp_version(opts):
    if opts.login is not None and opts.passwd is not None:
        return 3
    return 2 if opts.v2c else 1


def parse_snmp_output(text):
    """Convierte la salida 'OID valor' de net-snmp en un diccionario."""
    results = {}
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        oid, _, value = line.partition(' ')
        oid = oid.lstrip('.')
        value = value.strip()
        missing = NO_SUCH.search(value)
        if missing:
            # Net::SNMP devolvia estos literales y el resto del plugin los compara asi.
            value = ('noSuchInstance' if missing.group(1).lower() == 'instance'
                     else 'noSuchObject')
        elif len(value) >= 2 and value[0] == '"' and value[-1] == '"':
            value = value[1:-1]
        results[oid] = value
    return results


def redacted(cmd):
    """Oculta community y contrasenas v3 antes de escribirlas al log de depuracion."""
    secrets = {'-c', '-A', '-X'}
    out = []
    hide = False
    for arg in cmd:
        if hide:
            out.append('<oculto>')
            hide = False
            continue
        out.append(arg)
        hide = arg in secrets
    return ' '.join(out)


def run_snmp(command, opts, snmp, arguments, table_name):
    cmd = [command] + snmp_base_args(opts, snmp) + [snmp_target(opts)] + arguments
    nc.verb("Executing: " + redacted(cmd))
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              universal_newlines=True, timeout=opts.timeout + 5)
    except FileNotFoundError:
        nc.exit_unknown("UNKNOWN ERROR - could not execute %s. "
                        "Install net-snmp-utils." % command)
    except subprocess.TimeoutExpired:
        nc.exit_unknown("ERROR: alarm timeout. No answer from host %s" % opts.hostname)
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or '').strip().splitlines()
        nc.exit_unknown("SNMP ERROR getting %s : %s." % (table_name,
                                                        detail[0] if detail else 'no output'))
    return parse_snmp_output(proc.stdout)


def snmp_walk(opts, snmp, baseoid, table_name):
    command = 'snmpbulkwalk' if (opts.bulk_snmp_queries and snmp_version(opts) > 1) else 'snmpwalk'
    return run_snmp(command, opts, snmp, [baseoid], table_name)


def snmp_get(opts, snmp, oids, table_name, results):
    """Lee instancias puntuales en bloques, para no exceder el tamano de mensaje."""
    wanted = [oid for oid in oids if oid]
    if not wanted:
        return results
    nc.verb("Doing snmp request on %s OIDs: %s" % (table_name, ' '.join(wanted)))
    for start in range(0, len(wanted), OIDS_PER_REQUEST):
        chunk = wanted[start:start + OIDS_PER_REQUEST]
        results.update(run_snmp('snmpget', opts, snmp, chunk, table_name))
    return results


def bits_value(raw):
    """Interpreta el campo BITS de portAdditionalOperStatus en sus formatos posibles."""
    text = raw.strip()
    if text.lower().startswith('0x'):
        return int(text, 16)
    compact = text.replace(' ', '')
    if compact and re.fullmatch(r'[0-9A-Fa-f]+', compact) and len(compact) % 2 == 0:
        return int(compact, 16)
    return int(nc.ascii_to_hex(text), 16) if text else 0


def load_cached_index(opts, snmp, perf_data, timenow, specified_speed, perfcache_time):
    """Recupera de la perfdata previa los indices ya descubiertos (opciones -m y -mm)."""
    def cached_list(key):
        value = nc.prev_perf(perf_data, key)
        return value.split(',') if value else []

    tindex = cached_list('cache_descr_ids')
    cport = cached_list('cache_descr_cport')
    stpport = cached_list('cache_descr_stpport')
    descr = cached_list('cache_descr_names')
    portspeed = cached_list('cache_int_speed') if specified_speed == 0 else []
    has_speed_cache = nc.prev_perf(perf_data, 'cache_int_speed') is not None

    trigger = RECACHE_MAX if snmp['maxmin'] else RECACHE_TRIGGER
    invalid = (
        len(tindex) != len(set(tindex))
        or len(tindex) != len(descr)
        or (opts.cisco is not None and (nc.prev_perf(perf_data, 'cache_descr_cport') is None
                                        or len(tindex) != len(cport)))
        or (opts.stp is not None and (nc.prev_perf(perf_data, 'cache_descr_stpport') is None
                                      or len(tindex) != len(stpport)))
        or (has_speed_cache and len(tindex) != len(portspeed))
        or perfcache_time is None
        or timenow < perfcache_time
        or (timenow - perfcache_time) > trigger
    )
    if invalid:
        return [], [], [], [], {}

    interfaces = []
    for position, name in enumerate(descr):
        interface = {'descr': name}
        if has_speed_cache and position < len(portspeed):
            interface['portspeed'] = nc.num(portspeed[position])
        interfaces.append(interface)

    copt = {}
    cached_opt = nc.prev_perf(perf_data, 'cache_cisco_opt')
    if cached_opt:
        for token in cached_opt.split(','):
            copt[token] = token

    if tindex:
        nc.verb("Using cached data:")
        nc.verb("  tindex=" + ','.join(tindex))
        nc.verb("  descr=" + ','.join(descr))
        if cport:
            nc.verb("  cport=" + ','.join(cport))
            if cport[0] == '-1':
                cport = []
        if stpport:
            nc.verb("  stpport=" + ','.join(stpport))
            if stpport[0] == '-1':
                stpport = []

    return tindex, interfaces, cport, stpport, copt


def discover_index(opts, snmp, results_cache):
    """Recorre la tabla de descripciones y arma los indices de las interfaces a chequear."""
    cisco_timap = {}
    cisco_map = {}
    if opts.cisco is not None:
        cisco_map = snmp_walk(opts, snmp, CISCO_PORT_IFINDEX_MAP, "Cisco port-index map table")
        prefix = CISCO_PORT_IFINDEX_MAP + '.'
        for oid, value in cisco_map.items():
            if oid.startswith(prefix):
                cisco_timap[value] = oid[len(prefix):]

    stp_ifmap = {}
    if opts.stp is not None:
        stp_map = snmp_walk(opts, snmp, STP_IFINDEX_MAP, "STP port-index map table")
        prefix = STP_IFINDEX_MAP + '.'
        for oid, value in stp_map.items():
            if oid.startswith(prefix):
                stp_ifmap[value] = oid[len(prefix):]

    descr_table = snmp['descr_table']
    nc.verb("Getting Interfaces Description Table (%s):" % descr_table)
    table = snmp_walk(opts, snmp, descr_table, "Description table")
    results_cache.update(table)

    tindex, interfaces, cport, stpport = [], [], [], []
    prefix = descr_table + '.'
    for oid in sorted(table, key=_oid_sort_key):
        raw = table[oid]
        name = nc.clean_int_name(raw)
        nc.verb(" OID : %s, Clean Desc : %s, Raw Desc: %s" % (oid, name, raw))
        if not oid.startswith(prefix):
            continue
        if not nc.int_name_match(name, opts.name, opts.noregexp):
            continue

        suffix = oid[len(prefix):]
        interface = {'descr': name, 'admin_up': 0, 'oper_up': 0,
                     'in_bytes': 0, 'out_bytes': 0, 'in_packets': 0, 'out_packets': 0,
                     'in_errors': 0, 'out_errors': 0}

        this_cport = None
        if opts.cisco is not None:
            mapped = cisco_map.get(CISCO_PORT_IFINDEX_MAP + '.' + suffix)
            if 'use_portnames' in snmp['cisco'] and mapped is not None:
                this_cport = suffix
                this_index = mapped
            elif suffix in cisco_timap:
                this_cport = cisco_timap[suffix]
                this_index = suffix
            else:
                this_index = suffix
        else:
            this_index = suffix

        tindex.append(this_index)
        cport.append(this_cport)
        stpport.append(stp_ifmap.get(this_index) if opts.stp is not None else None)
        interfaces.append(interface)

    return tindex, interfaces, cport, stpport


def _oid_sort_key(oid):
    return tuple(int(part) if part.isdigit() else -1 for part in oid.split('.'))


def getdata_snmp(opts, snmp, perf_data, timenow, check_speed, specified_speed):
    """Obtiene por SNMP los datos de todas las interfaces que coinciden con -n."""
    results = {}
    perf_out = ''
    saved_out = ''
    copt_next = {}
    perfcache_time = nc.num(nc.prev_perf(perf_data, 'cache_descr_time'), None)

    tindex, interfaces, cport, stpport, copt = [], [], [], [], {}
    if snmp['minimize'] and perf_data:
        tindex, interfaces, cport, stpport, copt = load_cached_index(
            opts, snmp, perf_data, timenow, specified_speed, perfcache_time)

    from_cache = bool(tindex)
    if not tindex:
        perfcache_time = timenow
        tindex, interfaces, cport, stpport = discover_index(opts, snmp, results)

    num_int = len(interfaces)
    if num_int == 0:
        return interfaces, perf_out, saved_out, perfcache_time

    in_octet = IN_OCTET_TABLE_64 if opts.highperf else IN_OCTET_TABLE
    out_octet = OUT_OCTET_TABLE_64 if opts.highperf else OUT_OCTET_TABLE

    status_oids, descr_oids, perf_oids = [], [], []
    speed_oids, speed_high_oids, comment_oids = [], [], []
    cisco_oids, stp_oids = [], []
    inoct, outoct, inerr, outerr, indisc, outdisc = [], [], [], [], [], []

    for i in range(num_int):
        nc.verb("Name : %s, Index : %s" % (interfaces[i]['descr'], tindex[i]))
        status_oids.append((ADMIN_TABLE if opts.admin else OPER_TABLE) + tindex[i])
        if opts.admindown_ok:
            status_oids.append(ADMIN_TABLE + tindex[i])

        if snmp['minimize'] and not snmp['maxmin']:
            if 'use_portnames' in snmp['cisco'] and cport[i]:
                descr_oids.append(snmp['descr_table'] + '.' + cport[i])
            else:
                descr_oids.append(snmp['descr_table'] + '.' + tindex[i])

        if opts.cisco is not None and cport[i]:
            auto = not copt and 'auto' in snmp['cisco']
            if 'linkfault' in snmp['cisco'] or 'linkfault' in copt or auto:
                cisco_oids.append(CISCO_PORT_LINKFAULTSTATUS_TABLE + cport[i])
            if 'oper' in snmp['cisco'] or 'oper' in copt or auto:
                cisco_oids.append(CISCO_PORT_OPERSTATUS_TABLE + cport[i])
            if 'addoper' in snmp['cisco'] or 'addoper' in copt or auto:
                cisco_oids.append(CISCO_PORT_ADDOPERSTATUS_TABLE + cport[i])

        if opts.stp is not None and stpport[i]:
            stp_oids.append(STP_PORTSTATE + stpport[i])

        if opts.perfparse or opts.perfcheck:
            inoct.append(in_octet + tindex[i])
            outoct.append(out_octet + tindex[i])
            if opts.extperfcheck or opts.error:
                indisc.append(IN_DISCARD_TABLE + tindex[i])
                outdisc.append(OUT_DISCARD_TABLE + tindex[i])
                inerr.append(IN_ERROR_TABLE + tindex[i])
                outerr.append(OUT_ERROR_TABLE + tindex[i])
        else:
            inoct.append(None)
            outoct.append(None)

        if check_speed and ('portspeed' not in interfaces[i] or not snmp['maxmin']):
            speed_oids.append(SPEED_TABLE + tindex[i])
            speed_high_oids.append(SPEED_TABLE_64 + tindex[i])
        else:
            speed_oids.append(None)
            speed_high_oids.append(None)

        if opts.optionaltext_oid is not None:
            # Con show_portnames el OID viene de la tabla Cisco y no trae punto final,
            # a diferencia del que normaliza -O, por eso aqui se agrega explicitamente.
            if opts.cisco is not None and 'show_portnames' in snmp['cisco']:
                comment_oids.append(opts.optionaltext_oid + '.' + cport[i] if cport[i] else None)
            else:
                comment_oids.append(opts.optionaltext_oid + tindex[i])

    if opts.perfparse or opts.perfcheck or opts.intspeed is not None:
        perf_oids = [oid for oid in outoct + inoct + speed_oids if oid]
        if opts.highperf:
            perf_oids += [oid for oid in speed_high_oids if oid]
        if opts.extperfcheck or opts.error:
            perf_oids += inerr + outerr + indisc + outdisc

    if snmp['minimize']:
        status_oids += perf_oids + descr_oids + comment_oids + cisco_oids + stp_oids
        snmp_get(opts, snmp, status_oids, "status table", results)
    else:
        snmp_get(opts, snmp, status_oids, "status table", results)
        if perf_oids:
            snmp_get(opts, snmp, perf_oids, "statistics table", results)
        if cisco_oids:
            snmp_get(opts, snmp, cisco_oids, "cisco status tables", results)
        if stp_oids:
            snmp_get(opts, snmp, stp_oids, "stp state table", results)
        if comment_oids:
            snmp_get(opts, snmp, comment_oids, "comments table", results)

    for i in range(num_int):
        interface = interfaces[i]
        extratext = ""

        if from_cache and snmp['minimize'] and not snmp['maxmin']:
            if 'use_portnames' in snmp['cisco'] and cport[i]:
                found = results.get(snmp['descr_table'] + '.' + cport[i])
            else:
                found = results.get(snmp['descr_table'] + '.' + tindex[i])
            if found is not None:
                found = nc.clean_int_name(found)
            if found is None:
                nc.exit_unknown("ERROR: Cached port description is %s while retrieved "
                                "port name is not available" % interface['descr'])
            if found != interface['descr']:
                nc.exit_unknown("ERROR: Cached port description %s is different then "
                                "retrieved port name %s" % (interface['descr'], found))
            nc.verb("Name : %s [confirmed cached name for port %d]" % (found, i))

        if ADMIN_TABLE + tindex[i] in results:
            interface['admin_up'] = nc.num(results[ADMIN_TABLE + tindex[i]])
        if OPER_TABLE + tindex[i] in results:
            interface['oper_up'] = nc.num(results[OPER_TABLE + tindex[i]])

        if results.get(inoct[i]) is not None and results.get(outoct[i]) is not None:
            interface['in_bytes'] = nc.num(results[inoct[i]])
            interface['out_bytes'] = nc.num(results[outoct[i]])
            interface['in_errors'] = 0
            interface['out_errors'] = 0
            interface['in_dropped'] = 0
            interface['out_dropped'] = 0
            if opts.extperfcheck:
                for key, table in (('in_errors', IN_ERROR_TABLE),
                                   ('out_errors', OUT_ERROR_TABLE),
                                   ('in_dropped', IN_DISCARD_TABLE),
                                   ('out_dropped', OUT_DISCARD_TABLE)):
                    value = results.get(table + tindex[i])
                    if value is not None:
                        interface[key] = nc.num(value)

        if opts.optionaltext_oid is not None:
            if 'show_portnames' in snmp['cisco'] and cport[i]:
                label = results.get(opts.optionaltext_oid + '.' + cport[i])
            else:
                label = results.get(opts.optionaltext_oid + tindex[i])
            if label:
                interface['descr_extra'] = '(' + label + ')'

        if opts.cisco is not None and cport[i]:
            extratext = apply_cisco_status(interface, i, cport[i], results, opts, snmp,
                                           copt, copt_next, extratext)

        if opts.stp is not None and stpport[i]:
            extratext, stp_perf = apply_stp_status(interface, stpport[i], results, opts,
                                                   snmp, perf_data, timenow, extratext)
            perf_out += stp_perf

        if speed_oids[i] and results.get(speed_oids[i]) is not None:
            speed = nc.num(results[speed_oids[i]])
            if speed == 4294967295:
                if not opts.highperf and check_speed:
                    nc.exit_unknown("Cannot get interface speed with standard MIB, "
                                    "use highperf mib (-g) : UNKNOWN")
                high = results.get(speed_high_oids[i])
                if high is not None and nc.num(high) != 0:
                    interface['portspeed'] = nc.num(high) * 1000000
                elif specified_speed == 0:
                    nc.exit_unknown("Cannot get interface speed using highperf mib : UNKNOWN")
            else:
                interface['portspeed'] = speed

        if extratext:
            if interface.get('status_extratext'):
                interface['status_extratext'] += ', ' + extratext
            else:
                interface['status_extratext'] = extratext

    if snmp['minimize'] and opts.prev_perfdata is not None:
        saved_out += build_index_cache(interfaces, tindex, cport, stpport, opts, snmp,
                                       copt, copt_next, check_speed, specified_speed,
                                       perfcache_time)

    return interfaces, perf_out, saved_out, perfcache_time


def apply_cisco_status(interface, position, port, results, opts, snmp, copt, copt_next, extratext):
    """Anexa el estado de las tablas especificas de Cisco CatOS."""
    linkfault = operstat = addoperstat = None
    cisco_text = ""
    auto = not copt and 'auto' in snmp['cisco']

    if 'linkfault' in snmp['cisco'] or 'linkfault' in copt or auto:
        value = results.get(CISCO_PORT_LINKFAULTSTATUS_TABLE + port)
        if value is not None:
            linkfault = value
            if not re.search(r'\d+', str(linkfault)):
                nc.verb("Received non-integer value for cisco linkfault status when "
                        "checking port %d: %s" % (position, linkfault))
                linkfault = None
            else:
                linkfault = nc.num(linkfault)
                if linkfault != 1:
                    if cisco_text:
                        cisco_text += ','
                    cisco_text += CISCO_LINKFAULTSTATUS.get(linkfault, str(linkfault))
        if linkfault is not None and ((not opts.inverse and linkfault != 1)
                                      or (opts.inverse and linkfault == 1)):
            interface['nagios_status'] = nc.ERRORS['CRITICAL']

    if 'oper' in snmp['cisco'] or 'oper' in copt or auto:
        value = results.get(CISCO_PORT_OPERSTATUS_TABLE + port)
        if value is not None:
            operstat = value
            if not re.search(r'\d+', str(operstat)):
                nc.verb("Received non-integer value for cisco operport status when "
                        "checking port %d: %s" % (position, operstat))
                operstat = None
            else:
                operstat = nc.num(operstat)
                if operstat != 2:
                    if cisco_text:
                        cisco_text += ','
                    cisco_text += CISCO_OPERSTATUS.get(operstat, str(operstat))
        if operstat is not None and ((not opts.inverse and operstat != 2)
                                     or (opts.inverse and operstat == 2)):
            interface['nagios_status'] = nc.ERRORS['CRITICAL']

    if 'addoper' in snmp['cisco'] or 'addoper' in copt or auto:
        addoperstat = results.get(CISCO_PORT_ADDOPERSTATUS_TABLE + port)
        if addoperstat in ('noSuchInstance', 'noSuchObject'):
            nc.verb("Received invalid value for cisco addoper status when checking "
                    "port %d: %s" % (position, addoperstat))
            addoperstat = None
        if addoperstat is not None:
            bits = bits_value(addoperstat)
            for bit in range(16):
                if bits & (1 << (15 - bit)):
                    name = CISCO_ADDOPERSTATUS.get(bit)
                    if name and name != 'connected':
                        if cisco_text:
                            cisco_text += ','
                        cisco_text += name

    if auto:
        if linkfault is not None:
            copt_next['linkfault'] = 1
        if operstat is not None:
            copt_next['oper'] = 1
        if addoperstat is not None:
            copt_next['addoper'] = 1

    if cisco_text:
        if extratext:
            extratext += ", "
        extratext += "CISCO: " + cisco_text
    return extratext


def apply_stp_status(interface, port, results, opts, snmp, perf_data, timenow, extratext):
    """Anexa el estado STP del puerto y su historico de cambios."""
    perf = ''
    state = results.get(STP_PORTSTATE + port)
    if state is None or not re.search(r'\d+', str(state)):
        nc.verb("Received non-numeric status for STP for port %s: %s" % (port, state))
        return extratext, perf

    state = nc.num(state)
    descr = interface['descr']
    prev_state = nc.prev_perf(perf_data, descr, "stp_state")
    prev_change = nc.prev_perf(perf_data, descr, "stp_changetime")

    if extratext:
        extratext += ','
    extratext += 'STP:' + STP_PORTSTATE_NAMES.get(state, str(state))

    perf += " " + nc.perf_name(descr, "stp_state") + "=" + str(state)
    if prev_state is not None:
        perf += " " + nc.perf_name(descr, "prev_stp_state") + "=" + str(prev_state)

    if prev_change is not None and prev_state is not None and nc.num(prev_state) == state:
        perf += " " + nc.perf_name(descr, 'stp_changetime') + '=' + str(prev_change)
    elif prev_state is None or prev_change is None:
        perf += " " + nc.perf_name(descr, 'stp_changetime') + '=' + str(timenow - STP_WARNTIME)
    else:
        perf += " " + nc.perf_name(descr, 'stp_changetime') + '=' + str(timenow)

    if opts.stp and state != snmp['stp_reverse'][opts.stp]:
        extratext += ":CRIT"
        interface['nagios_status'] = nc.ERRORS['CRITICAL']
    elif ((prev_change is not None and (timenow - nc.num(prev_change)) < STP_WARNTIME)
            or (prev_state is not None and nc.num(prev_state) != state)):
        extratext += ":WARN(change from %s)" % STP_PORTSTATE_NAMES.get(nc.num(prev_state),
                                                                      str(prev_state))
        interface['nagios_status'] = nc.ERRORS['WARNING']

    return extratext, perf


def build_index_cache(interfaces, tindex, cport, stpport, opts, snmp, copt, copt_next,
                      check_speed, specified_speed, perfcache_time):
    """Guarda en la perfdata los indices descubiertos para no volver a recorrer la tabla."""
    out = ''
    descr = [interface['descr'] for interface in interfaces]
    portspeed = [str(interface['portspeed']) for interface in interfaces
                 if interface.get('portspeed') is not None]

    if tindex:
        out += " cache_descr_ids=" + ','.join(str(value) for value in tindex)
    if descr:
        out += " cache_descr_names=" + ','.join(descr)
    if perfcache_time is not None:
        out += " cache_descr_time=" + str(perfcache_time)
    if check_speed and portspeed and snmp['maxmin'] and specified_speed == 0:
        out += " cache_int_speed=" + ','.join(portspeed)

    if opts.cisco is not None:
        values = [str(value) for value in cport if value] or ['-1']
        out += " cache_descr_cport=" + ','.join(values)
        if copt:
            out += " cache_cisco_opt=" + ','.join(copt.keys())
        elif copt_next:
            out += " cache_cisco_opt=" + ','.join(copt_next.keys())

    if opts.stp is not None:
        values = [str(value) for value in stpport if value] or ['-1']
        out += " cache_descr_stpport=" + ','.join(values)

    return out


def main():
    argv = nc.fix_negative_args(sys.argv[1:])
    parser = build_parser()
    opts = parser.parse_args(argv)

    perf_data, prev_time = nc.validate_common_options(opts, parser)
    snmp = validate_snmp_options(opts, parser)
    thresholds = nc.parse_thresholds(opts, parser)

    check_speed = bool(opts.prct or opts.perfprct)
    specified_speed, speed_alert, override = nc.parse_intspeed(opts.intspeed, parser)
    if override is not None:
        check_speed = override

    def on_alarm(signum, frame):
        nc.exit_unknown("ERROR: alarm timeout. No answer from host %s" % opts.hostname)

    signal.signal(signal.SIGALRM, on_alarm)
    signal.alarm(opts.timeout + 10)

    timenow = int(time.time())
    if opts.name is not None:
        nc.verb("Filter : %s" % opts.name)

    interfaces, perf_out, saved_out, _ = getdata_snmp(opts, snmp, perf_data, timenow,
                                                      check_speed, specified_speed)

    if not interfaces:
        if opts.name is not None:
            nc.exit_unknown("ERROR : Unknown interface %s" % opts.name)
        nc.exit_unknown("ERROR : can not find any network interfaces")

    exit_code, output = nc.run_checks(interfaces, opts, thresholds, perf_data, prev_time,
                                      timenow, specified_speed=specified_speed,
                                      speed_alert=speed_alert, perf_out=perf_out,
                                      saved_out=saved_out)
    signal.alarm(0)
    print(output)
    sys.exit(exit_code)


if __name__ == '__main__':
    main()
