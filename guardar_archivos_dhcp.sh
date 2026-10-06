#!/usr/bin/env bash
# =============================================================================
# guardar_archivos_dhcp.sh  -  Copia en UN solo .txt el contenido de todos los
# ficheros importantes de la practica DHCP (SOLO LECTURA, no cambia nada).
# Solo usa bash y utilidades basicas de Ubuntu: sin red y sin Python.
#
# Uso:   sudo bash guardar_archivos_dhcp.sh [--anon] [--sin-numeros]
#   --anon         oculta IPs, MAC, nombre de la maquina y usuario (para compartir)
#   --sin-numeros  no numera las lineas de los ficheros
# Resultado: <home del usuario>/sh/archivos_dhcp.txt   (home detectado solo,
#            tambien con sudo; otra carpeta con REPORT_DIR=/ruta)
# Siempre oculta el valor de lineas con password / secret / psk.
# =============================================================================
ANON=0; NUM=1
for a in "$@"; do
  case "$a" in
    --anon) ANON=1;; --sin-numeros) NUM=0;;
    -h|--help) sed -n '2,/^# =====/p' "$0"; exit 0;;
  esac
done

ROOT="${ROOT:-}"      # solo para pruebas: prefijo de las rutas de ficheros
have() { command -v "$1" >/dev/null 2>&1; }
IS_ROOT=0; [ "$(id -u)" -eq 0 ] && IS_ROOT=1
FOUND=""; MISSING=""

hide_secrets() { sed -E 's/(password|secret|psk)([^A-Za-z0-9_]*[[:space:]:=]+).*/\1\2***OCULTO***/I'; }

# ---- vuelca un fichero con cabecera (ruta, permisos, propietario, fecha)
dump_file() {
  local p="$1" max="${2:-0}" f="$ROOT$1"
  if [ -f "$f" ]; then
    if [ ! -r "$f" ]; then
      printf '\n######## FICHERO: %s\n(existe pero NO se puede leer: ejecuta con sudo)\n' "$p"; MISSING="$MISSING\n  [sin permiso] $p"; return
    fi
    FOUND="$FOUND\n  [ok] $p"
    printf '\n######## FICHERO: %s\n' "$p"
    printf '# permisos=%s propietario=%s tamano=%s bytes modificado=%s\n' \
      "$(stat -c '%a' "$f" 2>/dev/null)" "$(stat -c '%U:%G' "$f" 2>/dev/null)" "$(stat -c '%s' "$f" 2>/dev/null)" "$(stat -c '%y' "$f" 2>/dev/null | cut -d. -f1)"
    [ -L "$f" ] && printf '# es un enlace simbolico -> %s\n' "$(readlink -f "$f")"
    [ ! -s "$f" ] && { echo "(fichero vacio)"; return; }
    local tot; tot="$(wc -l < "$f")"
    if [ "$max" -gt 0 ] && [ "$tot" -gt "$max" ]; then
      printf '# (fichero largo: se muestran solo las ultimas %s de %s lineas)\n' "$max" "$tot"
      tail -n "$max" "$f" | hide_secrets | { [ "$NUM" = 1 ] && cat -n || cat; }
    else
      hide_secrets < "$f" | { [ "$NUM" = 1 ] && cat -n || cat; }
    fi
    printf '######## FIN: %s\n' "$p"
  else
    printf '\n######## FICHERO: %s\n(NO EXISTE)\n' "$p"; MISSING="$MISSING\n  [no existe]   $p"
  fi
}

# ---- ejecuta un comando y guarda su salida
run_cmd() {
  local title="$1"; shift
  printf '\n######## COMANDO: %s\n' "$title"
  if have "$1"; then "$@" 2>&1 | head -${LIMIT:-80}; else echo "($1 no esta disponible)"; fi
}

main() {
  echo "ARCHIVOS DE LA PRACTICA DHCP - $(date '+%Y-%m-%d %H:%M')  (solo lectura)"
  echo "Usuario: $(id -un)$([ "$IS_ROOT" = 0 ] && echo '  (sin sudo: algunos ficheros/logs pueden faltar)')"
  echo "Las lineas con password/secret/psk salen con el valor oculto."

  echo; echo "################################################################"
  echo "# 1. SISTEMA, NOMBRE DE LA MAQUINA Y RESOLUCION DE NOMBRES"
  echo "################################################################"
  dump_file /etc/os-release
  dump_file /etc/hostname
  dump_file /etc/hosts
  dump_file /etc/nsswitch.conf
  dump_file /etc/resolv.conf
  dump_file /etc/systemd/resolved.conf
  local f; for f in "$ROOT"/etc/systemd/resolved.conf.d/*.conf; do [ -f "$f" ] && dump_file "${f#$ROOT}"; done

  echo; echo "################################################################"
  echo "# 2. RED (NETPLAN)"
  echo "################################################################"
  local n=0; for f in "$ROOT"/etc/netplan/*.yaml; do [ -f "$f" ] && { dump_file "${f#$ROOT}"; n=$((n+1)); }; done
  [ "$n" = 0 ] && { printf '\n(No hay ficheros .yaml en /etc/netplan)\n'; MISSING="$MISSING\n  [no existe]   /etc/netplan/*.yaml"; }

  echo; echo "################################################################"
  echo "# 3. SERVIDOR DHCP (isc-dhcp-server)"
  echo "################################################################"
  dump_file /etc/default/isc-dhcp-server
  dump_file /etc/dhcp/dhcpd.conf
  dump_file /etc/dhcp/dhcpd.conf.bak
  # ficheros incluidos con: include "/ruta";
  local inc; inc="$(sed 's/#.*//' "$ROOT/etc/dhcp/dhcpd.conf" 2>/dev/null | grep -oE 'include +"[^"]+"' | sed 's/include *"//;s/"//')"
  for f in $inc; do dump_file "$f"; done
  dump_file /etc/dhcp/dhcpd6.conf 60
  dump_file /var/lib/dhcp/dhcpd.leases 150
  [ -f "$ROOT/var/lib/dhcp/dhcpd.leases~" ] && dump_file /var/lib/dhcp/dhcpd.leases~ 60

  echo; echo "################################################################"
  echo "# 4. CLIENTE DHCP (si esta maquina es un cliente)"
  echo "################################################################"
  dump_file /etc/dhcp/dhclient.conf 80
  for f in "$ROOT"/var/lib/dhcp/dhclient*.leases "$ROOT"/var/lib/NetworkManager/*.lease; do [ -f "$f" ] && dump_file "${f#$ROOT}" 80; done
  dump_file /etc/NetworkManager/NetworkManager.conf 60

  echo; echo "################################################################"
  echo "# 5. ESTADO ACTUAL (salida de comandos)"
  echo "################################################################"
  printf '\n######## COMANDO: nombre de la maquina\n'
  echo "hostname:    $(hostname 2>&1)"; echo "hostname -f: $(hostname -f 2>&1)"; echo "hostname -d: $(hostname -d 2>&1)"; echo "hostname -i: $(hostname -i 2>&1)"
  run_cmd "ip -br addr"  ip -br addr
  run_cmd "ip -4 addr"   ip -4 addr
  run_cmd "ip route"     ip route
  printf '\n######## COMANDO: interfaces (/sys/class/net)\n'
  for f in /sys/class/net/*; do [ -e "$f" ] && echo "$(basename "$f"): $(cat "$f/operstate" 2>/dev/null)  mac=$(cat "$f/address" 2>/dev/null)"; done
  printf '\n######## COMANDO: ss -ulpn (puertos UDP; el DHCP usa el 67)\n'
  if have ss; then ss -ulpn 2>&1 | head -30; else echo "(ss no esta disponible)"; fi
  run_cmd "dpkg -l isc-dhcp-server" dpkg -l isc-dhcp-server
  run_cmd "systemctl status isc-dhcp-server" systemctl status isc-dhcp-server --no-pager -l
  run_cmd "systemctl is-active systemd-resolved" systemctl is-active systemd-resolved
  LIMIT=40 run_cmd "resolvectl status" resolvectl status
  run_cmd "ls -l /etc/netplan /etc/dhcp /var/lib/dhcp" ls -l /etc/netplan /etc/dhcp /var/lib/dhcp
  if have dhcpd; then run_cmd "dhcpd -t -cf /etc/dhcp/dhcpd.conf (valida la sintaxis)" dhcpd -t -cf /etc/dhcp/dhcpd.conf
  else printf '\n######## COMANDO: dhcpd -t\n(dhcpd no esta instalado)\n'; fi
  if [ "$IS_ROOT" = 1 ]; then
    have ufw && LIMIT=30 run_cmd "ufw status" ufw status
    have nmcli && LIMIT=30 run_cmd "nmcli device" nmcli device
  fi

  echo; echo "################################################################"
  echo "# 6. LOGS DEL SERVIDOR DHCP (ultimas lineas)"
  echo "################################################################"
  if have journalctl && [ "$IS_ROOT" = 1 ]; then
    printf '\n######## COMANDO: journalctl -u isc-dhcp-server -n 80\n'
    journalctl -u isc-dhcp-server -n 80 --no-pager 2>&1 | tail -80
  elif [ -r /var/log/syslog ]; then
    printf '\n######## COMANDO: grep -i dhcp /var/log/syslog | tail -80\n'
    grep -i dhcp /var/log/syslog | tail -80
  else printf '\n(Sin acceso a los logs: ejecuta con sudo)\n'; fi

  echo; echo "################################################################"
  echo "# RESUMEN: ficheros leidos y ficheros que faltan"
  echo "################################################################"
  printf 'Leidos:%b\n' "${FOUND:-\n  (ninguno)}"
  printf '\nFaltan o sin permiso:%b\n' "${MISSING:-\n  (ninguno)}"
}

anon_filter() {
  if [ "$ANON" = 1 ]; then
    local hn; hn="$(hostname 2>/dev/null)"
    sed -E '/(^|[^0-9.])(127|255)\./!s/\b([0-9]{1,3}\.){3}[0-9]{1,3}\b/x.x.x.x/g; s/\b(10|172|192|169)\.([0-9]{1,3}\.){2}[0-9]{1,3}\b/x.x.x.x/g; s/\b([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b/xx:xx:xx:xx:xx:xx/g; s#/home/[^/ ]+#/home/USER#g' \
      | { if [ "${#hn}" -ge 3 ]; then sed -E "s/\b${hn}\b/HOST/g"; else cat; fi; }
  else cat; fi
}

# ---- carpeta de salida: <home real>/sh  (con sudo, $HOME puede ser /root)
if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ]; then REAL_USER="$SUDO_USER"; else REAL_USER="${USER:-$(id -un)}"; fi
REAL_HOME="$(getent passwd "$REAL_USER" 2>/dev/null | cut -d: -f6)"; [ -z "$REAL_HOME" ] && REAL_HOME="${HOME:-.}"
OUTDIR="${REPORT_DIR:-$REAL_HOME/sh}"
mkdir -p "$OUTDIR" 2>/dev/null || { OUTDIR="."; echo "No pude crear $REAL_HOME/sh; guardo en $(pwd)"; }
OUT="$OUTDIR/archivos_dhcp.txt"

main 2>&1 | anon_filter > "$OUT"
if [ "$(id -u)" -eq 0 ] && [ "$REAL_USER" != root ]; then chown "$REAL_USER": "$OUTDIR" "$OUT" 2>/dev/null; fi

echo "Listo. Archivos copiados en:"
printf '  %s%s\n' "$OUT" "$([ "$ANON" = 1 ] && echo '  (anonimizado)')" | anon_filter
echo "Lineas: $(wc -l < "$OUT")  |  Tamano: $(stat -c %s "$OUT") bytes"
