#!/usr/bin/env python3
#
# Logica compartida por check_netint.py (interfaces locales) y check_snmp_netint.py (SNMP).
#
# Derivado de check_netint.pl / check_snmp_netint.pl v2.4a9
#   (c)2004-2007 Patrick Proy, (c)2007-2012 William Leibzon
# SPDX-License-Identifier: GPL-2.0+
#
# La aritmetica de umbrales, calculo de tasas y formato de salida se reproduce tal cual
# esta en el Perl para no desviar alertas ya calibradas en Nagios. Eso incluye conservar
# tres rarezas del upstream, que estan marcadas en el codigo donde aplican:
#
#   1. Los divisores de unidades mezclan 1000 y 1024 a proposito (125/125000/125000000
#      para bits, 1024/1048576/1073741824 para bytes).
#   2. El promedio de las muestras recorre solo los indices 0..4, por lo que el sexto
#      valor (discard-out) siempre se reporta como 0.0.
#   3. perf_name() sustituye la secuencia literal "'/()" en vez de un conjunto de
#      caracteres, asi que en la practica no limpia nada.
#

import argparse
import os
import re
import sys

VERSION = '2.4'

ERRORS = {'OK': 0, 'WARNING': 1, 'CRITICAL': 2, 'UNKNOWN': 3, 'DEPENDENT': 4}

STATUS = {'UP': 1, 'DOWN': 2, 'TESTING': 3, 'UNKNOWN': 4,
          'DORMANT': 5, 'NotPresent': 6, 'lowerLayerDown': 7}
STATUS_PRINT = dict((v, k) for k, v in STATUS.items())

COUNTER_NAMES = ["in=", "out=", "errors-in=", "errors-out=", "discard-in=", "discard-out="]

BASE_DIR = "/tmp/tmp_Nagios_int."
FILE_HISTORY = 200

_verbose = None


class PluginParser(argparse.ArgumentParser):
    """ArgumentParser que sale con UNKNOWN (3) en vez del 2 que usa argparse."""

    def error(self, message):
        print(message)
        print(self.format_usage().rstrip())
        sys.exit(ERRORS['UNKNOWN'])


def fix_negative_args(argv):
    """Une '-s -4' en '-s=-4' para que argparse no lea el valor como si fuera una opcion."""
    fixed = []
    skip = False
    for index, arg in enumerate(argv):
        if skip:
            skip = False
            continue
        if arg in ('-s', '--short') and index + 1 < len(argv):
            following = argv[index + 1]
            if re.fullmatch(r'-\d+', following):
                fixed.append(arg + '=' + following)
                skip = True
                continue
        fixed.append(arg)
    return fixed


def add_common_arguments(parser):
    """Opciones validas tanto para el chequeo local como para el SNMP."""
    parser.add_argument('-V', '--version', action='version',
                        version='check_netint version : ' + VERSION)
    parser.add_argument('-t', '--timeout', type=int, default=5)
    parser.add_argument('-v', '--verbose', '--debug', nargs='?', const='', default=None)

    parser.add_argument('-n', '--name', dest='name', default=None)
    parser.add_argument('-r', '--noregexp', action='store_true')
    parser.add_argument('-i', '--inverse', action='store_true')
    parser.add_argument('-a', '--admin', action='store_true')
    parser.add_argument('-D', '--dormant', action='store_true')
    parser.add_argument('-I', '--ignorestatus', action='store_true')
    parser.add_argument('-K', '--admindown_ok', action='store_true')
    parser.add_argument('-s', '--short', type=int, default=None)

    parser.add_argument('-f', '--perfparse', action='store_true')
    parser.add_argument('-e', '--error', action='store_true')
    parser.add_argument('-S', '--intspeed', nargs='?', const='', default=None)
    parser.add_argument('-y', '--perfprct', action='store_true')
    parser.add_argument('-Y', '--perfspeed', action='store_true')
    parser.add_argument('-Z', '--perfoctet', action='store_true')

    parser.add_argument('-k', '--perfcheck', action='store_true')
    parser.add_argument('-q', '--extperfcheck', action='store_true')
    parser.add_argument('-w', '--warning', default=None)
    parser.add_argument('-c', '--critical', default=None)
    parser.add_argument('-z', '--zerothresholds', action='store_true')
    parser.add_argument('--label', action='store_true')

    parser.add_argument('-B', '--kbits', action='store_true')
    parser.add_argument('-M', '--mega', action='store_true')
    parser.add_argument('-G', '--giga', action='store_true')
    parser.add_argument('-u', '--prct', action='store_true')

    parser.add_argument('-d', '--delta', type=int, default=300)
    parser.add_argument('-P', '--prev_perfdata', default=None)
    parser.add_argument('-T', '--prev_checktime', default=None)
    parser.add_argument('--pcount', type=int, default=2)
    parser.add_argument('-F', '--filestore', nargs='?', const='', default='')
    parser.add_argument('--nagios_with_saveddata', action='store_true')


def validate_common_options(opts, parser):
    """Reproduce las validaciones cruzadas de check_options() y arma el estado previo."""
    set_verbose(opts.verbose)

    if opts.timeout is not None and (opts.timeout < 2 or opts.timeout > 60):
        exit_usage(parser, "Timeout must be >1 and <60 !")

    if opts.error and not opts.perfparse:
        exit_usage(parser, "Cannot output error without -f option!")
    if opts.perfspeed and opts.perfprct:
        exit_usage(parser, "-Y and -y options are exclusives")
    if (opts.perfspeed or opts.perfprct or opts.perfoctet) and not opts.perfcheck:
        exit_usage(parser, "Cannot put -Y or -y or -Z options without perf check option (-k) ")

    perf_data = {}
    prev_time = []
    if opts.prev_perfdata is not None:
        if not opts.perfparse:
            exit_usage(parser, "need -f option first ")
        perf_data, prev_time = process_perf(opts.prev_perfdata)
        if 'ptime' in perf_data:
            prev_time.append(perf_data['ptime'])
        elif opts.prev_checktime is not None:
            prev_time.append(opts.prev_checktime)
            perf_data['ptime'] = opts.prev_checktime
        else:
            prev_time = []
        prev_time = sorted(set(prev_time), key=lambda stamp: num(stamp))

    if opts.prev_checktime is not None and opts.prev_perfdata is None:
        exit_usage(parser, "Specifying previous servicecheck is only necessary "
                           "when you send previous performance data (-T)")

    return perf_data, prev_time


def set_verbose(value):
    global _verbose
    _verbose = value


def verb(message):
    if _verbose is None:
        return
    if _verbose == "":
        print(message)
        return
    try:
        with open(_verbose, "a") as handle:
            handle.write(message + "\n")
    except OSError:
        print(message)


def exit_unknown(message):
    print(message)
    sys.exit(ERRORS['UNKNOWN'])


def exit_usage(parser, message):
    print(message)
    print(parser.format_usage().rstrip())
    sys.exit(ERRORS['UNKNOWN'])


def num(value, default=0):
    """Convierte a int cuando el valor es entero, a float si no, como hace Perl al operar."""
    if value is None:
        return default
    if isinstance(value, (int, float)):
        return value
    try:
        return int(value)
    except (TypeError, ValueError):
        pass
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def fmt_num(value):
    """Formatea sin notacion cientifica ni '.0' sobrante, como interpola Perl."""
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value)


def ascii_to_hex(text):
    return ''.join('%02x' % ord(char) for char in text)


def clean_int_name(name):
    """Quita el relleno no ASCII que agregan algunos agentes SNMP de Windows."""
    if name and (ord(name[-1]) > 127 or ord(name[-1]) == 0):
        name = name[:-1]
    name = re.sub(r'[\x00-\x1f\x7f]', '', name)
    return name.rstrip('\n')


def int_name_match(name, pattern, noregexp):
    if pattern is None:
        return True
    if noregexp:
        return name == pattern
    return re.search(pattern, name) is not None


def perf_name(iname, vtype):
    return "'" + iname.replace("'/()", "_") + "_" + vtype + "'"


# Separa por espacios sin romper dentro de comillas y conservandolas, que es lo que hace
# quotewords('\s+', 1, ...) en el original. shlex no sirve aqui: en modo no POSIX corta el
# token en la comilla de cierre y en modo POSIX se come las comillas, y los nombres de
# metrica que genera perf_name() las llevan.
_PERF_TOKEN = re.compile(r'''(?:[^\s"']+|"[^"]*"|'[^']*')+''')


def process_perf(perfstring):
    """Lee el $SERVICEPERFDATA$ previo. Devuelve (datos, marcas_de_tiempo)."""
    data = {}
    ptimes = []
    for token in _PERF_TOKEN.findall(perfstring):
        match = re.match(r'(.*)=(.*)', token)
        if not match:
            continue
        name, value = match.group(1), match.group(2)
        verb("prev_perf: %s = %s" % (name, value))
        data[name] = value
        counter = re.search(r'(\d+)c', value)
        if counter:
            data[name] = counter.group(1)
        stamp = re.match(r'.*\.(\d+)', name)
        if stamp and (not ptimes or ptimes[0] != stamp.group(1)):
            ptimes.append(stamp.group(1))
    return data, ptimes


def prev_perf(data, name, vtype=None):
    if vtype is not None:
        name = perf_name(name, vtype)
    if name in data:
        return data[name]
    # El upstream escribio un backtick de cierre en vez de comilla simple, asi que este
    # respaldo para nombres a los que Nagios quito las comillas nunca llega a dispararse.
    stripped = re.match(r"^'(.*)`$", name)
    if stripped and stripped.group(1) in data:
        return data[stripped.group(1)]
    return None


def parse_intspeed(option, parser):
    """Interpreta -S/--intspeed. Devuelve (velocidad_bps, alerta, fija_check_speed)."""
    specified_speed = 0
    speed_alert = None
    check_speed = None

    if option is None:
        return specified_speed, speed_alert, check_speed

    digits = re.search(r'(\d+)', option)
    if not digits:
        return specified_speed, speed_alert, check_speed

    specified_speed = int(digits.group(1))
    if re.search(r'Kb?$', option):
        specified_speed *= 1024
    if re.search(r'Mb?$', option):
        specified_speed *= 1024 * 1024

    alert = re.match(r'^(.*)<>', option)
    if alert:
        speed_alert = alert.group(1)
        check_speed = True
        if speed_alert not in ERRORS:
            exit_usage(parser, "Incorrect alert type %s specified at --intspeed=" % speed_alert)
        if specified_speed == 0:
            exit_usage(parser, "Must specify speed after alert type with --intspeed")
    else:
        check_speed = False

    return specified_speed, speed_alert, check_speed


def parse_thresholds(opts, parser):
    """Valida y expande -w y -c. Devuelve (warn_min, warn_max, crit_min, crit_max)."""
    warn_min, warn_max, crit_min, crit_max = {}, {}, {}, {}

    if not opts.perfcheck:
        return warn_min, warn_max, crit_min, crit_max

    warn_list = opts.warning.split(',') if opts.warning else []
    crit_list = opts.critical.split(',') if opts.critical else []

    if not opts.zerothresholds:
        if opts.extperfcheck and len(warn_list) != 6:
            exit_usage(parser, "Add '-z' or specify 6 warning levels for extended checks ")
        if not opts.extperfcheck and len(warn_list) != 2:
            exit_usage(parser, "Add 'z' or specify 2 warning levels for bandwidth checks ")
        if opts.extperfcheck and len(crit_list) != 6:
            exit_usage(parser, "Add '-z' or specify 6 critical levels for extended checks ")
        if not opts.extperfcheck and len(crit_list) != 2:
            exit_usage(parser, "Add '-z' or specify 2 critical levels for bandwidth checks ")

    for levels, mins, maxs, kind in ((warn_list, warn_min, warn_max, 'warning'),
                                     (crit_list, crit_min, crit_max, 'critical')):
        for index, raw in enumerate(levels):
            if re.fullmatch(r'\d+', raw):
                maxs[index] = float(raw)
                continue
            span = re.fullmatch(r'(\d+)?-(\d+)?', raw)
            if not span:
                exit_usage(parser, "Can't parse %s level: %s" % (kind, raw))
            if span.group(1):
                mins[index] = float(span.group(1))
            if span.group(2):
                maxs[index] = float(span.group(2))

    for index in range(len(warn_list)):
        if crit_max.get(index) and warn_max.get(index) and warn_max[index] > crit_max[index]:
            exit_usage(parser, "Warning max must be < Critical max level ")
        if crit_min.get(index) and warn_min.get(index) and warn_min[index] < crit_min[index]:
            exit_usage(parser, "Warning min must be > Critical min level ")

    if (opts.mega and opts.giga) or (opts.mega and opts.prct) or (opts.giga and opts.prct):
        exit_usage(parser, "-M -G and -u options are exclusives")

    return warn_min, warn_max, crit_min, crit_max


def read_file(path, items_number):
    """Lee el archivo temporal de historico. Devuelve (error, filas, valores)."""
    rows = []
    try:
        with open(path, "r") as handle:
            for line in handle:
                values = line.rstrip('\n').split(':')
                if len(values) >= items_number:
                    rows.append([num(v) for v in values[:items_number]])
    except OSError:
        return 1, 0, []
    if not rows:
        return 1, 0, []
    return 0, len(rows), rows


def write_file(path, rows, items, values):
    start = rows - FILE_HISTORY if rows > FILE_HISTORY else 0
    try:
        with open(path, "w") as handle:
            for i in range(start, rows):
                handle.write(':'.join(str(values[i][j]) for j in range(items)))
                handle.write("\n")
    except OSError:
        return 1
    return 0


def speed_metric_unit(opts, portspeed):
    """Divisor y unidad de la salida. Los valores son literales a proposito (ver cabecera)."""
    if opts.prct:
        if portspeed is None:
            return None, None
        return portspeed / 800, '%'
    if opts.kbits:
        if opts.mega:
            return 125000, "Mbps"
        if opts.giga:
            return 125000000, "Gbps"
        return 125, "Kbps"
    if opts.mega:
        return 1048576, "MBps"
    if opts.giga:
        return 1073741824, "GBps"
    return 1024, "KBps"


def compute_rates(prev_values, n_rows, timenow, opts, speed_metric):
    """Promedia las tasas sobre las muestras que caen dentro de la ventana de delta.

    Devuelve (usable, checkperf_out) donde usable es 0 cuando hay datos utilizables,
    replicando la convencion invertida del original.
    """
    trigger = timenow - (opts.delta - opts.delta / 4)
    trigger_low = timenow - 4 * opts.delta
    overflow_mod = 18446744073709551616 if opts.highperf else 4294967296

    checkperf_out = [0, 0, 0, 0, 0, 0]
    raw = []

    index = n_rows - 1
    while True:
        if index + 1 < n_rows and trigger_low < prev_values[index][0] < trigger:
            tdiff = prev_values[index + 1][0] - prev_values[index][0]
            if tdiff != 0:
                sample = [0, 0, 0, 0, 0, 0]
                if prev_values[index + 1][1] != 0 and prev_values[index][1] != 0:
                    overflow = 0 if prev_values[index + 1][1] >= prev_values[index][1] else overflow_mod
                    sample[0] = ((overflow + prev_values[index + 1][1] - prev_values[index][1])
                                 / tdiff) / speed_metric
                if prev_values[index + 1][2] != 0 and prev_values[index][2] != 0:
                    overflow = 0 if prev_values[index + 1][2] >= prev_values[index][2] else overflow_mod
                    sample[1] = ((overflow + prev_values[index + 1][2] - prev_values[index][2])
                                 / tdiff) / speed_metric
                if opts.extperfcheck:
                    for offset in range(4):
                        sample[2 + offset] = ((prev_values[index + 1][3 + offset]
                                               - prev_values[index][3 + offset]) / tdiff) * 60
                if sample[0] != 0 or sample[1] != 0:
                    raw.append(sample)
        index -= 1
        if index < 0 or len(raw) >= opts.pcount:
            break

    if not raw:
        return 1, checkperf_out

    # El upstream promedia solo hasta el indice 4, por lo que discard-out queda en 0.
    for position in range(5):
        counted = 0
        for sample in raw:
            if sample[position] != 0:
                counted += 1
                checkperf_out[position] += sample[position]
        if counted > 0:
            checkperf_out[position] = checkperf_out[position] / counted

    return 0, checkperf_out


def _load_prev_values_from_perf(descr, opts, perf_data, prev_time):
    """Arma el historico a partir del perfdata previo en vez del archivo temporal."""
    prev_values = []
    ptime = prev_perf(perf_data, 'ptime')
    fields = ('in_octet', 'out_octet', 'in_error', 'out_error', 'in_discard', 'out_discard')

    for position in range(opts.pcount):
        if position >= len(prev_time):
            break
        timeref = '.' + str(prev_time[position])
        if ptime is not None and str(ptime) == str(prev_time[position]):
            timeref = ''

        row = [num(prev_time[position])]
        row.extend(prev_perf(perf_data, descr, name + timeref) for name in fields)

        data_ok = True
        for position_in_row in range(1, 7 if opts.extperfcheck else 3):
            value = row[position_in_row]
            if value is None or not re.search(r'\d+', str(value)):
                row[position_in_row] = 0
                if position_in_row < 3:
                    data_ok = False
            else:
                row[position_in_row] = num(value)
        for position_in_row in range(1, 7):
            row[position_in_row] = num(row[position_in_row])

        if data_ok and row[1] != 0 and row[2] != 0:
            prev_values.append(row)

    return prev_values


def _temp_file_name(descr, opts):
    if opts.filestore and len(opts.filestore) > 1 and not os.path.isdir(opts.filestore):
        return opts.filestore
    name = re.sub(r'[ ;/]', '_', descr)
    base = opts.filestore if (opts.filestore and len(opts.filestore) > 1
                              and os.path.isdir(opts.filestore)) else BASE_DIR
    host = (opts.hostname + ".") if getattr(opts, 'hostname', None) else ""
    return base + host + name


def run_checks(interfaces, opts, thresholds, perf_data, prev_time, timenow,
               specified_speed=0, speed_alert=None, perf_out="", saved_out=""):
    """Recorre las interfaces, evalua umbrales y arma la salida y el codigo de Nagios."""
    warn_min, warn_max, crit_min, crit_max = thresholds

    num_int = len(interfaces)
    num_ok = 0
    num_admindown = 0
    ok_val = 2 if opts.inverse else 1
    final_status = 0
    print_out = ''
    temp_file_name = None
    n_items_check = 7 if opts.extperfcheck else 3

    for i in range(num_int):
        interface = interfaces[i]
        if print_out:
            print_out += ", "
        if perf_out:
            perf_out += " "
        usable_data = 1
        checkperf_out = None
        speed_metric = None
        speed_unit = None

        int_status = ok_val
        admin_int_status = ok_val
        extratext = ""

        if not opts.ignorestatus:
            if 'up_status' not in interface:
                if opts.admin and 'admin_up' in interface:
                    interface['up_status'] = interface['admin_up']
                elif 'oper_up' in interface:
                    interface['up_status'] = interface['oper_up']
                else:
                    exit_unknown("ERROR: Can not find up status for interface " + interface['descr'])
            if opts.admindown_ok and 'admin_up' in interface:
                admin_int_status = interface['admin_up']
                if admin_int_status != interface['up_status']:
                    extratext += "ADMIN:" + STATUS_PRINT[admin_int_status]
            int_status = interface.get('up_status', int_status)

        if interface.get('status_extratext'):
            if extratext:
                extratext += ", "
            extratext += interface['status_extratext']

        descr = interface['descr']
        if opts.short is not None:
            int_desc = descr[opts.short:] if opts.short < 0 else descr[:opts.short]
        else:
            int_desc = descr
        if 'descr_extra' in interface:
            int_desc += interface['descr_extra']
        interface['full_descr'] = int_desc

        if specified_speed != 0 and 'portspeed' not in interface:
            interface['portspeed'] = specified_speed
        portspeed = interface.get('portspeed')
        if speed_alert is not None and portspeed is not None and portspeed != specified_speed:
            if extratext:
                extratext += ','
            extratext += "%s: Speed=%s bps" % (speed_alert, portspeed)
            extratext += " (should be %s bps)" % specified_speed
            if ('nagios_status' not in interface
                    or ERRORS[speed_alert] > interface['nagios_status']):
                interface['nagios_status'] = ERRORS[speed_alert]
        if portspeed is not None:
            verb("Interface %d speed : %s" % (i, portspeed))

        if 'nagios_status' in interface and final_status < interface['nagios_status']:
            final_status = interface['nagios_status']

        if opts.perfcheck and int_status == STATUS['UP']:
            if opts.filestore or not opts.prev_perfdata:
                temp_file_name = _temp_file_name(descr, opts)
                usable_data, n_rows, prev_values = read_file(temp_file_name, n_items_check)
                verb("File read returns : %s with %s rows" % (usable_data, n_rows))
            else:
                prev_values = _load_prev_values_from_perf(descr, opts, perf_data, prev_time)
                n_rows = len(prev_values)
                usable_data = 1 if n_rows == 0 else 0
            verb("Previous data array created: %d rows" % n_rows)

            if interface.get('in_bytes') is not None and interface.get('out_bytes') is not None:
                prev_values.append([timenow, interface['in_bytes'], interface['out_bytes'],
                                    interface['in_errors'], interface['out_errors'],
                                    interface['in_dropped'], interface['out_dropped']])
                n_rows += 1

            if usable_data == 0:
                speed_metric, speed_unit = speed_metric_unit(opts, portspeed)
                if speed_metric is None:
                    verb("we do not have information on speed of interface %d (%s)" % (i, descr))
                    usable_data = 1
                else:
                    usable_data, checkperf_out = compute_rates(prev_values, n_rows, timenow,
                                                              opts, speed_metric)

            if temp_file_name is not None and not opts.zerothresholds and (
                    opts.filestore or not opts.prev_perfdata or not opts.prev_checktime):
                written = write_file(temp_file_name, n_rows, n_items_check, prev_values)
                if written != 0:
                    final_status = 3
                    print_out += " !!Unable to write file " + temp_file_name + " !! "
                    verb("Write file returned : %s" % written)

            print_out += "%s:%s" % (int_desc, STATUS_PRINT[int_status])
            if extratext:
                print_out += ' [' + extratext + ']'

            if usable_data == 0 and checkperf_out is not None:
                print_out += " ("
                num_checkperf = 6 if opts.extperfcheck else 2
                for level in range(num_checkperf):
                    label = COUNTER_NAMES[level] if opts.label else ""
                    verb("Interface %d, threshold check %d : %s" % (i, level, checkperf_out[level]))
                    if level != 0:
                        print_out += "/"
                    if ((crit_max.get(level) and checkperf_out[level] > crit_max[level])
                            or (crit_min.get(level) and checkperf_out[level] < crit_min[level])):
                        final_status = 2
                        print_out += "CRIT %s%.1f" % (label, checkperf_out[level])
                    elif ((warn_max.get(level) and checkperf_out[level] > warn_max[level])
                            or (warn_min.get(level) and checkperf_out[level] < warn_min[level])):
                        final_status = 2 if final_status == 2 else 1
                        print_out += "WARN %s%.1f" % (label, checkperf_out[level])
                    else:
                        print_out += "%s%.1f" % (label, checkperf_out[level])
                    if speed_unit is not None and level in (0, 1):
                        print_out += speed_unit
                print_out += ")"
            elif not opts.zerothresholds:
                print_out += " (no usable data - %d rows) " % n_rows
        else:
            print_out += "%s:%s" % (int_desc, STATUS_PRINT[int_status])
            if extratext:
                print_out += ' [' + extratext + ']'

        if int_status == ok_val or (opts.dormant and int_status == STATUS['DORMANT']):
            num_ok += 1
        elif (opts.admindown_ok and ok_val == 1 and not opts.admin
                and int_status == STATUS['DOWN'] and admin_int_status == STATUS['DOWN']):
            num_admindown += 1

        suppressed = (opts.admindown_ok and ok_val == 1 and int_status == STATUS['DOWN']
                      and admin_int_status == STATUS['DOWN'])
        wants_perf = (opts.perfparse or opts.intspeed is not None or opts.perfspeed
                      or opts.perfprct or opts.perfcheck)
        if not suppressed and descr is not None and wants_perf:
            perf_out += _interface_perfdata(interface, descr, opts, thresholds, usable_data,
                                            checkperf_out, speed_metric, portspeed)
            if opts.prev_perfdata and opts.nagios_with_saveddata:
                saved_out += " " + perf_name(descr, "in_octet") + "=" + str(interface['in_bytes'])
                saved_out += " " + perf_name(descr, "out_octet") + "=" + str(interface['out_bytes'])

    saved_out += _history_perfdata(interfaces, opts, perf_data, prev_time, timenow)

    if num_ok == num_int or (opts.admindown_ok and num_ok + num_admindown == num_int):
        exit_status = {0: "OK", 1: "WARNING", 2: "CRITICAL"}.get(final_status, "UNKNOWN")
        if opts.admindown_ok:
            output = print_out + " (%d UP, %d ADMIN DOWN): %s" % (num_ok, num_admindown, exit_status)
        else:
            output = print_out + " (%d UP): %s" % (num_ok, exit_status)
    else:
        exit_status = "CRITICAL"
        output = print_out + ": %d int NOK : CRITICAL" % (num_int - num_ok - num_admindown)

    if perf_out:
        output += " | " + perf_out
    if saved_out:
        if opts.nagios_with_saveddata:
            output += " ||"
        output += saved_out

    return ERRORS[exit_status], output


def _interface_perfdata(interface, descr, opts, thresholds, usable_data, checkperf_out,
                        speed_metric, portspeed):
    warn_min, warn_max, crit_min, crit_max = thresholds
    out = ''

    def level_field(table, index):
        value = table.get(index)
        return (fmt_num(value) + ";") if value else ";"

    if opts.perfprct:
        if usable_data == 0 and checkperf_out is not None:
            if opts.prct:
                out += " " + perf_name(descr, "in_prct") + "="
                out += "%.0f" % checkperf_out[0] + '%;'
                out += level_field(warn_max, 0)
                out += level_field(crit_max, 0)
                out += "0;100 "
                out += " " + perf_name(descr, "out_prct") + "="
                out += "%.0f" % checkperf_out[1] + '%;'
                out += level_field(warn_max, 1)
                out += level_field(crit_max, 1)
                out += "0;100 "
            elif portspeed:
                out += " " + perf_name(descr, "in_prct") + "="
                out += "%.0f" % (checkperf_out[0] * speed_metric / portspeed * 800) + '%'
                out += " " + perf_name(descr, "out_prct") + "="
                out += "%.0f" % (checkperf_out[1] * speed_metric / portspeed * 800) + '%'
            else:
                verb("we do not have information on speed of interface (%s)" % descr)
    elif opts.perfspeed:
        if usable_data == 0 and checkperf_out is not None:
            if opts.kbits:
                if opts.prct:
                    warn_factor = portspeed / 100 if portspeed else None
                else:
                    warn_factor = 1000000 if opts.mega else (1000000000 if opts.giga else 1000)
                if warn_factor is not None:
                    for index, direction in ((0, "in_bps"), (1, "out_bps")):
                        out += " " + perf_name(descr, direction) + "="
                        out += "%.0f" % (checkperf_out[index] * 8 * speed_metric) + ";"
                        out += _scaled_level(warn_max, index, warn_factor)
                        out += _scaled_level(crit_max, index, warn_factor)
                        if portspeed is not None:
                            out += "0;" + str(portspeed) + " "
            else:
                if opts.prct:
                    warn_factor = portspeed / 800 if portspeed else None
                else:
                    warn_factor = 1048576 if opts.mega else (1073741824 if opts.giga else 1024)
                if warn_factor is not None:
                    for index, direction in ((0, "in_Bps"), (1, "out_Bps")):
                        out += " " + perf_name(descr, direction) + "="
                        out += "%.0f" % (checkperf_out[index] * speed_metric) + ";"
                        out += _scaled_level(warn_max, index, warn_factor)
                        out += _scaled_level(crit_max, index, warn_factor)
                        if portspeed is not None:
                            out += "0;" + fmt_num(portspeed / 8) + " "

    if opts.perfoctet or (opts.prev_perfdata and not opts.nagios_with_saveddata):
        # La 'c' final le indica al graficador que es un contador acumulado.
        out += " " + perf_name(descr, "in_octet") + "=" + str(interface['in_bytes']) + "c"
        out += " " + perf_name(descr, "out_octet") + "=" + str(interface['out_bytes']) + "c"

    if opts.error and opts.extperfcheck:
        out += " " + perf_name(descr, "in_error") + "=" + str(interface['in_errors'])
        out += " " + perf_name(descr, "out_error") + "=" + str(interface['out_errors'])
        if interface.get('in_dropped') is not None:
            out += " " + perf_name(descr, "in_discard") + "=" + str(interface['in_dropped'])
        if interface.get('out_dropped') is not None:
            out += " " + perf_name(descr, "out_discard") + "=" + str(interface['out_dropped'])

    if portspeed is not None and opts.perfparse and opts.intspeed is not None:
        out += " " + perf_name(descr, "speed_bps") + "=" + str(portspeed)

    return out


def _scaled_level(table, index, factor):
    value = table.get(index)
    return (fmt_num(value * factor) + ";") if value else ";"


def _history_perfdata(interfaces, opts, perf_data, prev_time, timenow):
    """Reemite sets anteriores de contadores para suavizar el calculo de ancho de banda."""
    if not opts.prev_perfdata or opts.pcount <= 0:
        return ''

    out = ''
    ptime = prev_perf(perf_data, 'ptime')
    for interface in interfaces:
        descr = interface.get('descr')
        pcount = 0
        for loop_time in sorted(prev_time, reverse=True):
            if descr is None or pcount >= opts.pcount - 1:
                continue
            timeref = '.' + str(loop_time)
            if ptime is not None and str(ptime) == str(loop_time):
                timeref = ''
            if (prev_perf(perf_data, descr, 'in_octet' + timeref) is not None
                    and prev_perf(perf_data, descr, 'out_octet' + timeref) is not None):
                for direction in ('in_octet', 'out_octet'):
                    out += " " + perf_name(descr, '%s.%s' % (direction, loop_time)) + '='
                    out += str(prev_perf(perf_data, descr, direction + timeref))
            if opts.error and all(prev_perf(perf_data, descr, field + timeref) is not None
                                  for field in ('in_error', 'out_error',
                                                'in_discard', 'out_discard')):
                for field in ('in_error', 'out_error', 'in_discard', 'out_discard'):
                    out += " " + perf_name(descr, '%s.%s' % (field, loop_time)) + '='
                    out += str(prev_perf(perf_data, descr, field + timeref))
            pcount += 1

    out += " ptime=" + str(timenow)
    return out
