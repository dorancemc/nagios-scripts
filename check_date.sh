#!/usr/bin/env bash

# Nagios plugin
# Creado 27.02.2021 por: Edwar Alzate
# Valida el numero de dias faltantes hasta una fecha
# Retorna una salida para nagios:
# 0 = OK
# 1 = WARNING
# 2 = CRITICAL

# for help printing
print_help() {
        echo " USO : $0 -f <YYYYMMDD> -w <num> -c <num>"
        echo " -f parametro : fecha en formato YYYYMMDD. Ejemplo: 20220205"
        echo " -c parametro : numero de dias faltantes para determinar el estado CRITICAL. Ejemplo: 3"
        echo " -w parametro : numero de dias faltantes para determinar el estado WARNING. Ejemplo: 7"
        echo " Retorno : numero de dias faltantes para la fecha establecida"
        exit 3
}
# Verifica que tenga almenos un argumento
if [ -z $1 ]
        then echo "Missing arguments"
        echo "try \'$0 --help\' for help"
        exit 3
fi

# Imprimir ayuda
if [[ ( $1 = "--help" || $1 = "-h" ) ]]
        then print_help
        exit 3
fi

# Asignacion de variables
while getopts ":w:c:f:" options
do
    case $options in
        w ) advertencia=$OPTARG ;;
        c ) critico=$OPTARG ;;
        f ) fecha=$OPTARG ;;
        * ) echo "Unknown argument"
        echo "try \'$0 --help\' for help"
        exit 3 ;;
    esac
done

# Verifica que todos los argumentos esten presentes
if [[ ( -z $advertencia || -z $fecha  || -z $critico ) ]]
        then echo "Missing argument"
        echo "try \'$0 --help\' for help"
        exit 3
fi

# Calculos con fechas
FECHA_INICIO=$(date +%s)
FECHA_FIN=$(date --date=$fecha +%s)

SEGUNDOS=$(( $FECHA_FIN - $FECHA_INICIO ))
HORAS=$(( $SEGUNDOS / 3600 ))
DIAS=$(( $HORAS / 24 ))
# SEMANAS=$(( $DIAS / 7 ))

# Condicionales
if [[ $DIAS -le $advertencia ]]; then
  if [[ $DIAS -le $critico ]]; then
      if [[ $DIAS -le 0 ]]; then
        echo "CRITICAL: El producto ha vencido, por favor renueve [${fecha}]"
      else
        echo "CRITICAL: Faltan $DIAS dias para el vencimiento del producto [${fecha}]"
      fi
    exit 2
  else
    echo "WARNING: Faltan $DIAS dias para el vencimiento del producto [${fecha}]"
    exit 1
  fi
else
  echo "OK: Faltan $DIAS dias para el vencimiento del producto [${fecha}]"
  exit 0
fi
