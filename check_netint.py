#!/usr/bin/env python3
#
# Nagios plugin para monitorear interfaces de red locales en Linux.
#
# Derivado del modo local de check_netint.pl v2.4a9
#   (c)2004-2007 Patrick Proy, (c)2007-2012 William Leibzon
# SPDX-License-Identifier: GPL-2.0+
#
# Para interfaces remotas por SNMP use check_snmp_netint.py.
#
# Diferencias deliberadas frente al Perl, todas en la obtencion de datos:
#
#   1. Los datos salen de /proc/net/dev y /sys/class/net en vez de parsear la salida de
#      ifconfig, ethtool e iwconfig. El parser del Perl exigia el formato viejo de
#      net-tools ("eth0 Link encap:Ethernet"), que ya no existe en RHEL 8+ ni Ubuntu 20+,
#      donde el plugin respondia "can not find any network interfaces".
#   2. La velocidad se convierte a bps con 10**6 por Mbit/s. El Perl usaba 1024*1024, un
#      4.9% de error. Afecta solo a -u, -y y -S.
#   3. Un -S sin valor activa la lectura de velocidad. En el Perl no lo hacia, asi que la
#      metrica speed_bps que promete la ayuda nunca se emitia salvo que se pasara -u o -y.
#
# El resto (seleccion por regexp, estados, umbrales, calculo de tasas, cache de perfdata,
# archivo temporal y formato de salida) se comporta igual que el original.
#

import os
import platform
import signal
import sys
import time

import netint_common as nc

SYS_CLASS_NET = '/sys/class/net'
PROC_NET_DEV = '/proc/net/dev'

IFF_UP = 0x1
IFF_RUNNING = 0x40

OPERSTATE_MAP = {
    'up': nc.STATUS['UP'],
    'down': nc.STATUS['DOWN'],
    'testing': nc.STATUS['TESTING'],
    'unknown': nc.STATUS['UNKNOWN'],
    'dormant': nc.STATUS['DORMANT'],
    'notpresent': nc.STATUS['NotPresent'],
    'lowerlayerdown': nc.STATUS['lowerLayerDown'],
}

SNMP_ONLY_FLAGS = ('-H', '--hostname', '-C', '--community', '-2', '--v2c', '-l', '--login',
                   '-x', '--passwd', '-X', '--privpass', '-L', '--protocols', '-p', '--port',
                   '-o', '--octetlength', '-N', '--descrname_oid', '-O', '--optionaltext_oid',
                   '-g', '--64bits', '-m', '-mm', '--minimize_queries', '--minimum_queries',
                   '--bulk_snmp_queries', '--cisco', '--stp')


def reject_snmp_options(argv):
    for arg in argv:
        base = arg.split('=', 1)[0]
        if base in SNMP_ONLY_FLAGS:
            nc.exit_unknown("Option you specified is only valid with SNMP. "
                            "Use check_snmp_netint.py to check a remote host.")


def build_parser():
    parser = nc.PluginParser(
        prog='check_netint.py',
        description='Network Interfaces Monitor Plugin for Nagios (local Linux) v. ' + nc.VERSION,
        epilog='GPL 2.0 or 3.0 licence, (c)2004-2007 Patrick Proy, (c)2007-2012 William Leibzon')
    nc.add_common_arguments(parser)
    parser.set_defaults(highperf=False, hostname=None)
    return parser


def read_proc_net_dev():
    """Devuelve {interfaz: [16 contadores]} respetando el orden del archivo."""
    counters = {}
    try:
        with open(PROC_NET_DEV, 'r') as handle:
            for line in handle:
                if ':' not in line:
                    continue
                name, _, values = line.partition(':')
                fields = values.split()
                if len(fields) < 16:
                    continue
                counters[name.strip()] = [int(value) for value in fields[:16]]
    except OSError as err:
        nc.exit_unknown("UNKNOWN ERROR - could not read %s - %s" % (PROC_NET_DEV, err))
    return counters


def read_sysfs(name, attribute):
    try:
        with open(os.path.join(SYS_CLASS_NET, name, attribute), 'r') as handle:
            return handle.read().strip()
    except OSError:
        return None


def interface_speed(name):
    """Velocidad en bps segun sysfs. El kernel devuelve EINVAL en interfaces virtuales."""
    raw = read_sysfs(name, 'speed')
    if raw is None:
        return None
    try:
        speed = int(raw)
    except ValueError:
        return None
    if speed <= 0:
        return None
    return speed * 10 ** 6


def getdata_localhost(opts, check_speed):
    """Arma la lista de interfaces que coinciden con -n, leyendo procfs y sysfs."""
    if platform.system() != 'Linux':
        nc.exit_unknown("Only Linux is currently supported for local interfaces")

    interfaces = []
    for name, fields in read_proc_net_dev().items():
        if name == 'lo':
            continue
        if not nc.int_name_match(name, opts.name, opts.noregexp):
            continue

        try:
            flags = int(read_sysfs(name, 'flags') or '0x0', 16)
        except ValueError:
            flags = 0

        operstate = (read_sysfs(name, 'operstate') or 'unknown').lower()
        oper_up = OPERSTATE_MAP.get(operstate, nc.STATUS['UNKNOWN'])
        if oper_up == nc.STATUS['UNKNOWN']:
            # Puentes, tun y veth suelen reportar 'unknown'; ahi vale el IFF_RUNNING que
            # el original leia del campo RUNNING de ifconfig.
            oper_up = nc.STATUS['UP'] if flags & IFF_RUNNING else nc.STATUS['DOWN']

        interface = {
            'descr': name,
            'admin_up': nc.STATUS['UP'] if flags & IFF_UP else nc.STATUS['DOWN'],
            'oper_up': oper_up,
            'in_bytes': fields[0], 'in_packets': fields[1],
            'in_errors': fields[2], 'in_dropped': fields[3], 'in_overruns': fields[4],
            'out_bytes': fields[8], 'out_packets': fields[9],
            'out_errors': fields[10], 'out_dropped': fields[11], 'out_overruns': fields[12],
        }
        # El original sumaba los overruns a los errores al parsear ifconfig.
        interface['in_errors'] += interface['in_overruns']
        interface['out_errors'] += interface['out_overruns']

        if check_speed:
            speed = interface_speed(name)
            if speed is not None:
                interface['portspeed'] = speed
                nc.verb("   speed of interface %s is %d bps" % (name, speed))

        interfaces.append(interface)
        nc.verb("got interface: %s" % name)

    return interfaces


def main():
    argv = nc.fix_negative_args(sys.argv[1:])
    reject_snmp_options(argv)

    parser = build_parser()
    opts = parser.parse_args(argv)

    perf_data, prev_time = nc.validate_common_options(opts, parser)
    thresholds = nc.parse_thresholds(opts, parser)

    check_speed = bool(opts.prct or opts.perfprct)
    specified_speed, speed_alert, override = nc.parse_intspeed(opts.intspeed, parser)
    if override is not None:
        check_speed = override
    elif opts.intspeed is not None:
        check_speed = True

    def on_alarm(signum, frame):
        nc.exit_unknown("ERROR: alarm timeout")

    signal.signal(signal.SIGALRM, on_alarm)
    signal.alarm(opts.timeout + 10)

    timenow = int(time.time())
    if opts.name is not None:
        nc.verb("Filter : %s" % opts.name)

    interfaces = getdata_localhost(opts, check_speed)

    if not interfaces:
        if opts.name is not None:
            nc.exit_unknown("ERROR : Unknown interface %s" % opts.name)
        nc.exit_unknown("ERROR : can not find any network interfaces")

    exit_code, output = nc.run_checks(interfaces, opts, thresholds, perf_data, prev_time,
                                      timenow, specified_speed=specified_speed,
                                      speed_alert=speed_alert)
    signal.alarm(0)
    print(output)
    sys.exit(exit_code)


if __name__ == '__main__':
    main()
