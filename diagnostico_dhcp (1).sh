#!/usr/bin/env bash
# =============================================================================
# diagnostico_dhcp.sh  -  Diagnostico de SOLO LECTURA (no cambia nada)
# Funciona SIN red y SIN Python: usa solo bash, awk y utilidades basicas de Ubuntu.
# Si hay python3 y diagnostico_dhcp.py esta al lado, usa ese analisis (mas fino);
# si no, hace el analisis de dhcpd.conf con awk (detecta lo mismo).
#
# Uso:   bash diagnostico_dhcp.sh [--server|--client] [--anon]
#        sudo bash diagnostico_dhcp.sh        (recomendado: lee mas logs/ficheros)
#   --server  fuerza el modo servidor      --client  fuerza el modo cliente
#   --anon    oculta IPs, MAC y nombres en pantalla y en el informe (para compartir)
# Genera 2 informes en <home del usuario>/sh/: informe_dhcp.txt e informe_dhcp.html
# (el home se detecta solo, tambien con sudo; cambia la carpeta con REPORT_DIR=/ruta)
# Codigo de salida: 0 = sin errores, 1 = hay algun [ERROR]
# =============================================================================
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODE=auto; ANON=0
for a in "$@"; do
  case "$a" in
    --server) MODE=server;; --client) MODE=client;; --anon) ANON=1;;
    -h|--help) sed -n '2,/^# =====/p' "$0"; exit 0;;
  esac
done

DHCPD_CONF="${DHCPD_CONF:-/etc/dhcp/dhcpd.conf}"
DHCP_DEFAULTS="${DHCP_DEFAULTS:-/etc/default/isc-dhcp-server}"
HOSTS_FILE="${HOSTS_FILE:-/etc/hosts}"
NSS_FILE="${NSS_FILE:-/etc/nsswitch.conf}"
RESOLVED_CONF="${RESOLVED_CONF:-/etc/systemd/resolved.conf}"
NETPLAN_DIR="${NETPLAN_DIR:-/etc/netplan}"
SYS_NET="${SYS_NET:-/sys/class/net}"
export DHCPD_CONF DHCP_DEFAULTS     # para que el .py use los mismos ficheros

if [ -t 1 ] && [ "$ANON" = 0 ]; then G=$'\e[32m'; Y=$'\e[33m'; R=$'\e[31m'; B=$'\e[36m'; N=$'\e[0m'; else G=; Y=; R=; B=; N=; fi
OKS=0; WARNS=0; FAILS=0
ok()   { OKS=$((OKS+1));     printf "  %s[ OK ]%s %s\n" "$G" "$N" "$1"; }
warn() { WARNS=$((WARNS+1)); printf "  %s[AVISO]%s %s\n" "$Y" "$N" "$1"; [ -n "$2" ] && printf "          -> %s\n" "$2"; }
fail() { FAILS=$((FAILS+1)); printf "  %s[ERROR]%s %s\n" "$R" "$N" "$1"; [ -n "$2" ] && printf "          -> %s\n" "$2"; }
info() { printf "  [ i ] %s\n" "$1"; }
sec()  { printf "\n%s== %s ==%s\n" "$B" "$1" "$N"; }
have() { command -v "$1" >/dev/null 2>&1; }
strip() { sed 's/#.*//' "$1" 2>/dev/null; }          # fichero sin comentarios
PY_OK=0; have python3 && [ -f "$DIR/diagnostico_dhcp.py" ] && PY_OK=1

# lee lineas TIPO|mensaje|pista (de los analizadores awk) y las pasa por ok/warn/fail/info
relay() { local t m h; while IFS='|' read -r t m h; do case "$t" in OK) ok "$m";; INFO) info "$m";; WARN) warn "$m" "$h";; FAIL) fail "$m" "$h";; esac; done; }

# caracteres raros (comillas tipograficas, espacios no separables) y CRLF en un fichero
check_enc() {
  local f="$1" l; [ -r "$f" ] || return
  grep -q $'\r' "$f" 2>/dev/null && warn "$f tiene saltos de linea de Windows (CRLF)" "Convierte: sudo sed -i 's/\r\$//' $f"
  l="$(strip "$f" | LC_ALL=C grep -nP '[^\x00-\x7F]' 2>/dev/null | cut -d: -f1 | head -5 | tr '\n' ' ')"
  [ -n "$l" ] && fail "$f tiene caracteres no ASCII (comillas tipograficas, espacios raros...) en las lineas: $l" "Suele venir de copiar/pegar de un PDF o Word: reteclea esas lineas a mano"
}

# ---- analizador de dhcpd.conf en awk (se usa si no hay Python)
read -r -d '' SEM_AWK <<'AWKEOF'
# Analisis semantico de dhcpd.conf en awk puro (compatible con mawk).
# Entrada: ficheros de configuracion (principal + includes). Variables: -v ifips="IP IP"
# Salida: lineas  TIPO|mensaje|pista   (TIPO = OK, INFO, WARN, FAIL)

function emit(t, m, h) { print t "|" m "|" h }
function ip2n(s,   a, n, i, v) {
  n = split(s, a, ".")
  if (n != 4) return -1
  v = 0
  for (i = 1; i <= 4; i++) {
    if (a[i] !~ /^[0-9]+$/ || length(a[i]) > 3 || a[i] + 0 > 255) return -1
    v = v * 256 + a[i]
  }
  return v
}
function n2ip(v) { return sprintf("%d.%d.%d.%d", int(v / 16777216) % 256, int(v / 65536) % 256, int(v / 256) % 256, v % 256) }
function pow2(sz,   x) { x = 1; while (x < sz) x *= 2; return x == sz }
function lev(a, b,   la, lb, i, j, d, c, m) {
  la = length(a); lb = length(b)
  for (i = 0; i <= la; i++) d[i, 0] = i
  for (j = 0; j <= lb; j++) d[0, j] = j
  for (i = 1; i <= la; i++) for (j = 1; j <= lb; j++) {
    c = (substr(a, i, 1) == substr(b, j, 1)) ? 0 : 1
    m = d[i - 1, j] + 1
    if (d[i, j - 1] + 1 < m) m = d[i, j - 1] + 1
    if (d[i - 1, j - 1] + c < m) m = d[i - 1, j - 1] + c
    d[i, j] = m
  }
  return d[la, lb]
}
function closest(w, set,   k, best, bd, dd) {   # palabra mas parecida (distancia <= 2)
  best = ""; bd = 3
  for (k in set) { dd = lev(w, k); if (dd < bd) { bd = dd; best = k } }
  return best
}
function fw(s,   a) { split(s, a, " "); return a[1] }
function addstmt(t) { nst++; st[nst] = t; sb[nst] = cur; sl[nst] = lbl }
function openblk(h) { nb++; bh[nb] = h; bp[nb] = cur; bl[nb] = lbl; cur = nb }
function subnet_of(b) { while (b > 0 && fw(bh[b]) != "subnet") b = bp[b]; return b }
function getopt(b, name,   i, cb, re) {
  re = "^(option +)?" name "( |$)"
  cb = b
  while (1) {
    for (i = 1; i <= nst; i++) if (sb[i] == cb && st[i] ~ re) return st[i]
    if (cb == 0) break
    cb = bp[cb]
  }
  return ""
}
function inpool(ip,   i) { for (i = 1; i <= nr; i++) if (ip >= ra[i] && ip <= rb[i]) return i; return 0 }

BEGIN {
  split("option default-lease-time max-lease-time min-lease-time authoritative not ddns-update-style ddns-updates ddns-domainname ddns-rev-domainname deny allow ignore range hardware fixed-address filename next-server server-name log-facility include update-static-leases ping-check ping-timeout one-lease-per-client get-lease-hostnames use-host-decl-names server-identifier set unset if elsif else match boot-unknown-clients bootp-broadcast-always always-broadcast always-reply-rfc1048 dynamic-bootp-lease-cutoff dynamic-bootp-lease-length min-secs adaptive-lease-time-threshold lease-file-name pid-file-name local-address local-port omapi-port omapi-key key algorithm secret primary secondary address port peer max-response-delay max-unacked-updates mclt split load site-option-space vendor-option-space stash-agent-options ignore-client-uids prefix6 range6 preferred-lifetime host-identifier failover zone dns-update", tA, " ")
  for (i in tA) KS[tA[i]] = 1
  split("subnet-mask time-offset routers time-servers name-servers domain-name-servers log-servers cookie-servers lpr-servers impress-servers resource-location-servers host-name boot-size merit-dump domain-name swap-server root-path extensions-path ip-forwarding non-local-source-routing policy-filter max-dgram-reassembly default-ip-ttl path-mtu-aging-timeout path-mtu-plateau-table interface-mtu all-subnets-local broadcast-address perform-mask-discovery mask-supplier router-discovery router-solicitation-address static-routes trailer-encapsulation arp-cache-timeout ieee802-3-encapsulation default-tcp-ttl tcp-keepalive-interval tcp-keepalive-garbage nis-domain nis-servers ntp-servers vendor-encapsulated-options netbios-name-servers netbios-dd-server netbios-node-type netbios-scope font-servers x-display-manager dhcp-requested-address dhcp-lease-time dhcp-option-overload dhcp-message-type dhcp-server-identifier dhcp-message dhcp-max-message-size dhcp-renewal-time dhcp-rebinding-time vendor-class-identifier dhcp-client-identifier nisplus-domain nisplus-servers tftp-server-name bootfile-name mobile-ip-home-agent smtp-server pop-server nntp-server www-server finger-server irc-server streettalk-server streettalk-directory-assistance-server user-class slp-directory-agent slp-service-scope fqdn nds-servers nds-tree-name nds-context domain-search classless-static-routes ms-classless-static-routes tftp-server-address space", tB, " ")
  for (i in tB) KO[tB[i]] = 1
  split("subnet pool host group shared-network class subclass zone key failover", tC, " ")
  for (i in tC) KB[tC[i]] = 1
  nip = split(ifips, IFS_, " ")
  cur = 0; nb = 0; nst = 0; instr = 0; buf = ""; started = 0; lbl = ""; nerr = 0
}

{   # lectura caracter a caracter de cada linea (sin comentarios)
  line = $0; gsub(/\r/, "", line)
  fl = FILENAME; sub(/.*\//, "", fl)
  here = fl ":" FNR
  out = ""
  for (i = 1; i <= length(line); i++) {          # quita comentarios fuera de comillas
    c = substr(line, i, 1)
    if (c == "\"") instr = !instr
    if (c == "#" && !instr) break
    out = out c
  }
  instr = 0
  line = out " "
  for (i = 1; i <= length(line); i++) {
    c = substr(line, i, 1)
    if (c == "\"") instr = !instr
    if (!instr && (c == ";" || c == "{" || c == "}")) {
      b = buf; gsub(/^ +| +$/, "", b); gsub(/ +/, " ", b)
      if (c == ";") { if (b != "") addstmt(b) }
      else if (c == "{") {
        w0 = fw(b)
        if (b != "" && !(w0 in KB)) {
          # cabecera rara: quiza falta ';' en la linea anterior
          nw = split(b, ws, " "); found = 0
          for (k = 2; k <= nw; k++) if (ws[k] in KB) { found = k; break }
          if (found) {
            pre = ""; for (k = 1; k < found; k++) pre = pre ws[k] " "
            emit("FAIL", here ": '" substr(pre, 1, 50) "' parece NO acabar en ';' y se junta con el bloque siguiente", "Anade ';' al final de esa linea")
            b = ""; for (k = found; k <= nw; k++) b = b ws[k] " "; gsub(/ +$/, "", b)
          } else {
            sug = closest(w0, KB)
            emit("FAIL", here ": bloque desconocido '" substr(b, 1, 40) "'", (sug != "" ? "Quisiste decir '" sug "'?" : "Los bloques validos son subnet, pool, host, group, shared-network, class..."))
          }
        }
        openblk(b)
      } else {
        if (b != "") emit("FAIL", here ": falta ';' antes de '}' -> '" substr(b, 1, 60) "'", "Cada directiva acaba en ';'")
        if (cur == 0) emit("FAIL", here ": '}' sobrante (no hay bloque abierto)", "Quita esa llave o abre el bloque que falta")
        else cur = bp[cur]
      }
      buf = ""; started = 0
    } else {
      if (!started && c != " " && c != "\t") { lbl = here; started = 1 }
      buf = buf (c == "\t" ? " " : c)
    }
  }
}

END {
  b = buf; gsub(/^ +| +$/, "", b)
  if (b != "") emit("FAIL", lbl ": la ultima directiva no termina en ';' -> '" substr(b, 1, 60) "'", "Anade el ';' final")
  if (cur != 0) emit("FAIL", "Falta cerrar el bloque abierto en " bl[cur] " ('" substr(bh[cur], 1, 40) "')", "Falta una llave '}'")

  # ---- ';' olvidado: dos directivas pegadas en una sola sentencia
  split("default-lease-time max-lease-time min-lease-time option range authoritative ddns-update-style fixed-address hardware include filename next-server server-name", tS, " ")
  for (i in tS) STARTER[tS[i]] = 1
  for (i = 1; i <= nst; i++) {
    n = split(st[i], w, " ")
    if (w[1] == "not" || w[1] == "deny" || w[1] == "allow" || w[1] == "ignore") continue
    for (k = 2; k <= n; k++) if (w[k] in STARTER && !(w[1] == "hardware" && k == 2)) {
      pre = ""; rest = ""
      for (qq = 1; qq < k; qq++) pre = pre w[qq] " "
      for (qq = k; qq <= n; qq++) rest = rest w[qq] " "
      gsub(/ +$/, "", pre); gsub(/ +$/, "", rest)
      emit("FAIL", sl[i] ": falta ';' al final de '" substr(pre, 1, 50) "' (se junta con '" w[k] "')", "Anade ';' despues de '" pre "'")
      st[i] = pre
      nst++; st[nst] = rest; sb[nst] = sb[i]; sl[nst] = sl[i]
      break
    }
  }

  # ---- erratas en directivas y opciones
  for (i = 1; i <= nst; i++) {
    n = split(st[i], w, " "); w1 = w[1]
    if (w1 in KS) {
      if (w1 == "option" && n >= 2 && st[i] !~ / code / && !(w[2] in KO)) {
        s = closest(w[2], KO)
        if (s != "") emit("FAIL", sl[i] ": la opcion '" w[2] "' no existe", "Quisiste decir 'option " s "'?")
        else emit("INFO", sl[i] ": opcion '" w[2] "' no es estandar (valida solo si la defines tu)", "")
      }
    } else if (w1 ~ /^[a-z0-9-]+$/) {
      s = closest(w1, KS)
      if (s != "") emit("FAIL", sl[i] ": la directiva '" w1 "' no existe", "Quisiste decir '" s "'?")
      else emit("WARN", sl[i] ": directiva desconocida '" w1 "'", "Revisa que este bien escrita")
    } else emit("WARN", sl[i] ": sentencia rara: '" substr(st[i], 1, 50) "'", "")
  }

  # ---- opciones globales
  gl = ""; for (i = 1; i <= nst; i++) if (sb[i] == 0) gl = gl " | " st[i]
  if (gl ~ /\| (not +)?authoritative/ && gl !~ /not +authoritative/) emit("OK", "Servidor autoritativo (authoritative)", "")
  else emit("WARN", "Falta 'authoritative;' en opciones globales", "Si el enunciado dice que el servidor es el autorizado, anade authoritative;")
  if (gl ~ /ddns-update-style none/) emit("OK", "DNS dinamico desactivado (ddns-update-style none)", "")
  else emit("WARN", "Falta 'ddns-update-style none;'", "El servidor NO debe actualizar el DNS segun el enunciado")
  if (gl ~ /deny client-updates/) emit("OK", "Denegadas las actualizaciones del cliente (deny client-updates)", "")
  else emit("WARN", "Falta 'deny client-updates;'", "Denegar que el cliente actualice sus asignaciones")
  if (gl ~ /log-facility/) emit("WARN", "Has tocado log-facility", "El enunciado pide dejar el log por defecto")

  # ---- subredes
  ns = 0
  for (b = 1; b <= nb; b++) {
    if (fw(bh[b]) != "subnet") continue
    n = split(bh[b], h, " ")
    if (n < 4 || h[3] != "netmask") { emit("FAIL", bl[b] ": cabecera de subnet mal escrita: '" bh[b] "'", "Formato: subnet 192.168.50.0 netmask 255.255.255.0 {"); continue }
    nn = ip2n(h[2]); mm = ip2n(h[4])
    if (nn < 0 || mm < 0) { emit("FAIL", bl[b] ": IP o mascara no valida en '" bh[b] "'", "Cada numero de la IP va de 0 a 255"); continue }
    sz = 4294967296 - mm
    if (!pow2(sz) || mm == 0) { emit("FAIL", bl[b] ": la mascara " h[4] " no es valida", "Ejemplos: 255.255.255.0, 255.255.0.0, 255.255.255.128"); continue }
    if (nn % sz != 0) { emit("FAIL", bl[b] ": subnet/netmask incoherentes: " h[2] " no es direccion de red para " h[4], "Para /24 la red debe acabar en .0 (ej. 192.168.50.0)"); continue }
    ns++; SB[ns] = b; SN[ns] = nn; SS[ns] = sz; SM[ns] = h[4]
    emit("INFO", "Subred " h[2] "/" (32 - int(log(sz) / log(2) + 0.5)) " (" bl[b] ")", "")
  }
  if (ns == 0) emit("FAIL", "No hay ninguna declaracion 'subnet' valida", "Sin subnet para la interfaz del servidor aparece 'No subnet declaration'")
  for (i = 1; i <= ns; i++) for (j = i + 1; j <= ns; j++)
    if (SN[i] < SN[j] + SS[j] && SN[j] < SN[i] + SS[i]) emit("FAIL", "Las subredes " n2ip(SN[i]) " y " n2ip(SN[j]) " se solapan", "Cada subred debe ser un rango distinto")

  # ---- opciones por subred
  for (i = 1; i <= ns; i++) {
    b = SB[i]; net = SN[i]; sz = SS[i]; bc = net + sz - 1
    t = getopt(b, "subnet-mask")
    if (t != "" && index(t, SM[i]) == 0) emit("WARN", "subnet-mask distinta de la mascara de la subnet: " t, "")
    t = getopt(b, "broadcast-address")
    if (t != "") { if (index(t, n2ip(bc)) > 0) emit("OK", "broadcast-address correcto (" n2ip(bc) ")", ""); else emit("FAIL", "broadcast-address incorrecto: '" t "'", "Deberia ser " n2ip(bc)) }
    else emit("WARN", "Falta option broadcast-address en la subnet", "Si el enunciado pide dar el broadcast, anade option broadcast-address " n2ip(bc) ";")
    t = getopt(b, "domain-name")
    if (t == "") emit("WARN", "Falta option domain-name", "El enunciado pide el nombre de dominio (domXXX.internal)")
    else if (t !~ /"[^"]+"/) emit("FAIL", "option domain-name sin comillas: '" t "'", "Va entre comillas: option domain-name \"dom100.internal\";")
    t = getopt(b, "domain-name-servers")
    if (t == "") emit("WARN", "Falta option domain-name-servers", "Anade los servidores DNS que pida el enunciado")
    else {
      sub(/^option +domain-name-servers +/, "", t); gsub(/,/, " ", t); nd = split(t, dn, " ")
      for (k = 1; k <= nd; k++) if (dn[k] ~ /^[0-9.]+$/ && ip2n(dn[k]) < 0) emit("FAIL", "DNS con IP no valida: " dn[k], "Cada numero va de 0 a 255 y son 4 numeros")
    }
    t = getopt(b, "routers")
    if (t != "") {
      sub(/^option +routers +/, "", t); gsub(/,/, " ", t); fr = ip2n(fw(t))
      if (fr < 0) emit("FAIL", "option routers con IP no valida: " t, "")
      else if (int(fr / sz) != int(net / sz)) emit("FAIL", "option routers " n2ip(fr) " esta FUERA de la subred " n2ip(net), "El gateway debe pertenecer a la misma subred")
      else emit("INFO", "option routers esta ACTIVA (" n2ip(fr) "). Si el enunciado la pide comentada, ponle # delante", "")
    } else emit("OK", "option routers comentada/ausente (coherente con 'gateway comentado, se activara mas adelante')", "")
    dl = getopt(b, "default-lease-time"); ml = getopt(b, "max-lease-time")
    dv = dl; sub(/^[^0-9]*/, "", dv); sub(/[^0-9].*/, "", dv)
    mv = ml; sub(/^[^0-9]*/, "", mv); sub(/[^0-9].*/, "", mv)
    if (dv != "" && mv != "" && dv + 0 > mv + 0) emit("FAIL", "default-lease-time (" dv ") es MAYOR que max-lease-time (" mv ")", "El maximo debe ser igual o mayor que el normal")
    if (dv == "86400" && mv == "172800") emit("OK", "Lease 1 dia (86400) renovable 2 dias (172800)", "")
    else emit("WARN", "Lease distinto de 86400/172800 (default=" dl ", max=" ml ")", "1 dia = 86400 s; 2 dias = 172800 s. Ignora este aviso si tu enunciado pide otros tiempos")
  }

  # ---- rangos
  nr = 0
  for (i = 1; i <= nst; i++) {
    if (st[i] !~ /^range /) continue
    n = split(st[i], w, " "); k = 2
    if (w[k] == "dynamic-bootp") k++
    a = ip2n(w[k]); bb = (w[k + 1] == "" ? a : ip2n(w[k + 1]))
    if (a < 0 || bb < 0) { emit("FAIL", sl[i] ": IP del 'range' no valida: '" st[i] "'", "Cada numero va de 0 a 255"); continue }
    if (a > bb) emit("FAIL", sl[i] ": el range empieza despues de acabar (" n2ip(a) " > " n2ip(bb) ")", "Pon primero la IP menor")
    ins = 0; sp = subnet_of(sb[i])
    for (j = 1; j <= ns; j++) if (a >= SN[j] && bb < SN[j] + SS[j] && (!ins || SB[j] == sp)) ins = j
    if (!ins) emit("FAIL", sl[i] ": el range " n2ip(a) "-" n2ip(bb) " NO esta dentro de ninguna subnet declarada", "Revisa la red y la mascara")
    else if (a <= bb) {
      emit("OK", "range " n2ip(a) " - " n2ip(bb) " dentro de " n2ip(SN[ins]), "")
      if (a == SN[ins] || bb == SN[ins] + SS[ins] - 1) emit("WARN", "El range incluye la direccion de red o de broadcast", "Empieza en .1 o mas y acaba antes del broadcast")
      if (sp && SB[ins] != sp) emit("WARN", sl[i] ": el range esta en una subnet pero pertenece a otra", "")
    }
    for (k2 = 1; k2 <= nip; k2++) { x = ip2n(IFS_[k2]); if (x >= a && x <= bb) emit("FAIL", "El range " n2ip(a) "-" n2ip(bb) " incluye la IP del propio servidor (" IFS_[k2] ")", "Deja la IP del servidor fuera del pool") }
    nr++; ra[nr] = a; rb[nr] = bb
  }
  for (i = 1; i <= nr; i++) for (j = i + 1; j <= nr; j++)
    if (ra[i] <= rb[j] && ra[j] <= rb[i]) emit("WARN", "Dos range se solapan: " n2ip(ra[i]) "-" n2ip(rb[i]) " y " n2ip(ra[j]) "-" n2ip(rb[j]), "")
  dk = 0; for (i = 1; i <= nst; i++) if (st[i] ~ /^deny known-clients/) dk = 1

  # ---- hosts / reservas
  nh = 0
  for (b = 1; b <= nb; b++) {
    if (fw(bh[b]) != "host") continue
    split(bh[b], hw, " "); hn = hw[2]; mac = ""; fix = ""; ml_ = ""; fl_ = ""
    for (i = 1; i <= nst; i++) if (sb[i] == b) {
      if (st[i] ~ /^hardware ethernet /) { split(st[i], q, " "); mac = q[3]; ml_ = sl[i] }
      if (st[i] ~ /^fixed-address /) { split(st[i], q, " "); fix = q[2]; fl_ = sl[i] }
    }
    nh++
    if (hn in HN) emit("FAIL", "Nombre de host repetido: '" hn "'", "Cada 'host' necesita un nombre distinto")
    HN[hn] = 1
    if (mac == "") emit("FAIL", "host '" hn "' (" bl[b] ") sin 'hardware ethernet'", "Anade hardware ethernet XX:XX:XX:XX:XX:XX;")
    else {
      if (mac !~ /^[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]$/)
        emit("FAIL", "host '" hn "': MAC con formato incorrecto '" mac "'", "dhcpd separa los pares con DOS PUNTOS, no con guiones (Windows los muestra con guiones)")
      else emit("OK", "host '" hn "': MAC con formato correcto", "")
      lm = tolower(mac); if (lm in MC) emit("FAIL", "MAC repetida en '" MC[lm] "' y '" hn "'", ""); MC[lm] = hn
    }
    if (fix == "") emit("FAIL", "host '" hn "' (" bl[b] ") sin 'fixed-address'", "Anade fixed-address <IP>;")
    else {
      ip = ip2n(fix)
      if (ip < 0) { if (fix ~ /^[0-9.]+$/) emit("FAIL", "host '" hn "': fixed-address no es una IP valida (" fix ")", "Cada numero va de 0 a 255"); else emit("INFO", "host '" hn "': fixed-address usa un nombre (" fix "), no se comprueba", ""); continue }
      if (ip in HI) emit("FAIL", "IP " fix " repetida en '" HI[ip] "' y '" hn "'", "Cada host necesita una IP distinta")
      HI[ip] = hn
      ins = 0; for (j = 1; j <= ns; j++) if (ip >= SN[j] && ip < SN[j] + SS[j]) ins = j
      if (!ins) emit("FAIL", "host '" hn "': " fix " no esta dentro de ninguna subnet", "La reserva debe pertenecer a la subred")
      else emit("OK", "host '" hn "': " fix " dentro de la subred", "")
      p = inpool(ip); if (p) emit("FAIL", "host '" hn "': " fix " cae DENTRO del pool " n2ip(ra[p]) "-" n2ip(rb[p]), "La reserva debe ir fuera del pool (ej. .10-.99 vs pool .100-.200)")
      for (k2 = 1; k2 <= nip; k2++) if (ip2n(IFS_[k2]) == ip) emit("FAIL", "host '" hn "': " fix " es la IP del propio servidor", "Elige otra IP para la reserva")
    }
  }
  if (nh > 0) {
    emit("INFO", nh " reserva(s) (host) encontradas", "")
    if (nr > 0 && !dk) emit("WARN", "Hay reservas y pool, pero no hay 'deny known-clients;' en el pool", "Asi un cliente con reserva podria coger IP del pool")
    else if (dk) emit("OK", "El pool deniega a los clientes con reserva (deny known-clients)", "")
    ng = 0; for (b = 1; b <= nb; b++) if (fw(bh[b]) == "group") ng++
    if (!ng) emit("INFO", "No hay bloque 'group' (el enunciado suele pedirlo para unificar dominio y DNS)", "")
  } else emit("INFO", "No hay reservas (host). Si tu practica incluye cliente Windows registrado, falta la reserva por MAC", "")

  # ---- IP del servidor dentro de alguna subnet
  for (k2 = 1; k2 <= nip; k2++) {
    x = ip2n(IFS_[k2]); ins = 0
    for (j = 1; j <= ns; j++) if (x >= SN[j] && x < SN[j] + SS[j]) ins = j
    if (ins) emit("OK", "La interfaz del servidor tiene " IFS_[k2] " y hay una subnet que la contiene (sin esto: 'No subnet declaration')", "")
    else emit("FAIL", "La interfaz del servidor tiene " IFS_[k2] " pero NINGUNA subnet de dhcpd.conf la contiene", "Anade una subnet que incluya esa IP o corrige INTERFACESv4")
  }
}
AWKEOF

# ---- analizador de netplan (YAML) en awk
read -r -d '' NP_AWK <<'AWKEOF'
function emit(t, m, h) { print t "|" m "|" h }
{ sub(/\r$/, "") }
/^[ ]*#/ || /^[ ]*$/ { next }
/^[ ]*[A-Za-z0-9_-]+:[^ ]/ { l = $0; gsub(/^ +/, "", l); emit("FAIL", "linea " FNR ": falta un espacio despues de ':' -> " l, "YAML necesita 'clave: valor' con espacio") }
/^[ ]*-[^ ]/ { l = $0; gsub(/^ +/, "", l); emit("FAIL", "linea " FNR ": falta un espacio despues de '-' -> " l, "Las listas son '- valor'") }
/^    [A-Za-z0-9_.-]+:[ ]*$/ { cur = $1; sub(/:$/, "", cur); next }
/dhcp4:[ ]*(true|yes)/ { if (cur != "") dh[cur] = 1 }
/addresses:/ { if (cur != "") ad[cur] = 1; if ($0 ~ /\[/ && $0 !~ /\//) emit("FAIL", "linea " FNR ": direccion sin /prefijo -> " $0, "Ejemplo: 192.168.50.1/24") }
/^[ ]*-[ ]+[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+[ ]*$/ { l = $0; gsub(/^[ -]+/, "", l); emit("FAIL", "linea " FNR ": direccion " l " sin /prefijo", "Ejemplo: " l "/24") }
/gateway4:/ { emit("INFO", "linea " FNR ": gateway4 esta obsoleto en netplan nuevo", "Se sustituye por routes: - to: default via: IP") }
END { for (i in dh) if (dh[i] && ad[i]) emit("WARN", "La interfaz " i " tiene dhcp4: true Y addresses a la vez", "Elige una: DHCP o IP fija, no las dos") }
AWKEOF

# analisis de contenido de dhcpd.conf con awk (principal + includes)
semantic_awk() {
  local ips="$1" files="$DHCPD_CONF" inc f
  inc="$(strip "$DHCPD_CONF" | grep -oE 'include +"[^"]+"' | sed 's/include *"//;s/"//')"
  for f in $inc; do [ -f "$f" ] && files="$files $f"; done
  relay < <(awk -v ifips="$ips" "$SEM_AWK" $files 2>&1)
}

# ---------------------------------------------------------------- 0. contexto
section_context() {
  sec "0. Contexto"
  info "Usuario: $(id -un) (uid $(id -u))  |  Kernel: $(uname -r)"
  [ "$(id -u)" -ne 0 ] && warn "No eres root: algunas comprobaciones pueden quedar incompletas" "Ejecuta: sudo bash $0"
  if have python3; then info "Python3 disponible: $(python3 --version 2>&1)"; else info "Python3 NO disponible (se usa solo el analisis bash, es suficiente para lo basico)"; fi
  if ip route 2>/dev/null | grep -q '^default'; then info "Hay ruta por defecto (puede haber salida a Internet)"; else info "Sin ruta por defecto: normal en una red interna sin gateway (el script no usa red)"; fi
  if [ "$MODE" = auto ]; then
    if dpkg -s isc-dhcp-server >/dev/null 2>&1 || [ -f "$DHCPD_CONF" ]; then MODE=server; else MODE=client; fi
  fi
  info "Modo: $MODE"
}

# ---------------------------------------------------------------- 1. identidad
section_identity() {
  sec "1. Nombre de la maquina y /etc/hosts"
  local hn fqdn dom ip
  hn="$(hostname 2>/dev/null)"; fqdn="$(hostname -f 2>/dev/null)"; dom="$(hostname -d 2>/dev/null)"; ip="$(hostname -i 2>/dev/null)"
  info "hostname=$hn | fqdn=$fqdn | dominio=$dom | hostname -i=$ip"
  [ "$hn" = "$(cat /etc/hostname 2>/dev/null)" ] && ok "El hostname en uso coincide con /etc/hostname" || warn "El hostname en uso no coincide con /etc/hostname" "Usa: sudo hostnamectl set-hostname NOMBRE"
  if [ -f "$HOSTS_FILE" ]; then
    check_enc "$HOSTS_FILE"
    grep -qE '^\s*127\.0\.1\.1\b' "$HOSTS_FILE" && warn "Existe la loopback secundaria 127.0.1.1 en $HOSTS_FILE" "Si el enunciado dice 'no hay interfaz secundaria de loopback', borra esa linea" || ok "No hay loopback secundaria (127.0.1.1)"
    grep -qE '^\s*127\.0\.0\.1\s+localhost' "$HOSTS_FILE" && ok "Esta la linea 127.0.0.1 localhost" || warn "Falta '127.0.0.1 localhost' en $HOSTS_FILE"
    local line; line="$(strip "$HOSTS_FILE" | grep -E "\s$hn(\s|$)" | grep -vE '^\s*(127\.|::1)' | head -1)"
    if [ -n "$line" ]; then
      ok "Hay una linea con IP real para el nombre corto: $(echo $line)"
      local f2; f2="$(echo "$line" | awk '{print $2}')"
      case "$f2" in *.*) ok "El FQDN va primero y el nombre corto despues";; *) warn "El segundo campo no parece un FQDN ($f2)" "Formato: IP  nombre.dominio  nombre";; esac
    else warn "No hay linea que relacione una IP fija con el nombre '$hn'" "Anade:  IP_FIJA   $hn.TU-DOMINIO   $hn"; fi
  else fail "No existe $HOSTS_FILE"; fi
  [ -z "$dom" ] && warn "hostname -d no devuelve dominio" "Revisa que el FQDN este en /etc/hosts (nombre.dominio nombre)"
  case "$fqdn" in *.*) :;; *) warn "hostname -f no devuelve un FQDN (sin punto)" "Falta el FQDN en /etc/hosts";; esac
}

# ---------------------------------------------------------------- 2. red
section_network() {
  sec "2. Interfaces y rutas"
  local ifs; ifs="$(ls $SYS_NET 2>/dev/null | grep -v '^lo$')"
  [ -z "$ifs" ] && fail "No se ven interfaces de red" "Revisa la maquina virtual (adaptadores)"
  local dyn=0 sta=0 none=0 i nets=""
  for i in $ifs; do
    local a st; a="$(ip -4 -o addr show dev "$i" 2>/dev/null | awk '{print $4, $0}')"
    st="$(cat $SYS_NET/$i/operstate 2>/dev/null)"
    if [ -z "$a" ]; then none=$((none+1)); info "$i ($st): SIN IPv4"
    elif echo "$a" | grep -q 'dynamic'; then dyn=$((dyn+1)); info "$i ($st): IP por DHCP -> $(echo "$a" | awk '{print $1}' | head -1)"
    else sta=$((sta+1)); info "$i ($st): IP fija -> $(echo "$a" | awk '{print $1}' | head -1)"; fi
    if [ -n "$a" ]; then
      local cidr; cidr="$(echo "$a" | awk '{print $1}' | head -1)"
      echo "$cidr" | grep -q '^169\.254\.' && fail "$i tiene una IP 169.254.x.x (autoasignada): no ha recibido respuesta de ningun servidor DHCP" "Revisa servidor DHCP, cable/adaptador virtual y que esten en la misma red interna"
      nets="$nets $cidr"
    fi
  done
  # dos interfaces en la misma red
  local x y; for x in $nets; do for y in $nets; do
    [ "$x" \< "$y" ] && [ "${x%.*}" = "${y%.*}" ] && warn "Dos interfaces parecen estar en la misma red ($x y $y)" "Cada adaptador debe estar en una red distinta"
  done; done
  if [ "$MODE" = server ]; then
    [ "$dyn" -ge 1 ] && ok "Hay una interfaz con DHCPv4 (primera interfaz)" || warn "Ninguna interfaz tiene IP dinamica" "Primera interfaz: dhcp4: true en netplan"
    [ "$sta" -ge 1 ] && ok "Hay una interfaz con IP fija (red interna del servidor DHCP)" || fail "Ninguna interfaz tiene IP fija" "Sin IP fija en la red interna el servidor DHCP no puede escuchar"
  fi
  ip route 2>/dev/null | sed 's/^/        ruta: /'
  if [ "$MODE" = server ]; then
    local d; d="$(ip route 2>/dev/null | awk '/^default/ {print $5}')"
    if [ -n "$d" ] && ip -4 -o addr show dev "$d" | grep -q 'dynamic'; then ok "La puerta de enlace viene por la interfaz DHCP ($d), no por la interna"; fi
    [ -n "$d" ] && ! ip -4 -o addr show dev "$d" | grep -q 'dynamic' && warn "La puerta de enlace sale por $d, que tiene IP fija" "El gateway debe venir por la interfaz DHCP; la interna va sin gateway"
  fi
  # netplan
  sec "2b. Netplan"
  if [ -d "$NETPLAN_DIR" ] && ls "$NETPLAN_DIR"/*.yaml >/dev/null 2>&1; then
    local f; for f in "$NETPLAN_DIR"/*.yaml; do
      info "Fichero: $f"
      grep -qP '\t' "$f" 2>/dev/null && fail "$f contiene TABULADORES" "YAML solo admite espacios"
      check_enc "$f"
      local perm; perm="$(stat -c '%a' "$f" 2>/dev/null)"
      [ -n "$perm" ] && [ "$perm" -gt 600 ] && warn "Permisos de $f = $perm (netplan avisa si no es 600)" "sudo chmod 600 $f"
      grep -qE '^\s*version:\s*2' "$f" && ok "version: 2 presente" || warn "Falta 'version: 2' en $f"
      grep -qE 'dhcp4:\s*true' "$f" && ok "Hay 'dhcp4: true' (interfaz DHCP)" || info "Sin dhcp4: true en $f"
      grep -qE 'dhcp4:\s*false' "$f" && ok "Hay 'dhcp4: false' (interfaz con IP fija)" || info "Sin dhcp4: false en $f"
      [ "$MODE" = server ] && grep -qE 'gateway4|routes:|nameservers:' "$f" && warn "Hay gateway/routes/nameservers en netplan" "La interfaz interna debe ir SIN gateway ni DNS (revisa que no sea de la interna)"
      grep -qE '^\s*-\s*[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+' "$f" && ok "Hay una direccion fija con prefijo (addresses: - X.X.X.X/NN)" || info "No hay addresses con prefijo en $f"
      relay < <(awk "$NP_AWK" "$f" 2>&1)
      local n; for n in $(grep -E '^\s{4}[a-z0-9]+:\s*$' "$f" | tr -d ' :'); do [ -d "$SYS_NET/$n" ] || fail "netplan menciona la interfaz '$n' que NO existe" "Mira los nombres reales con: ip a"; done
    done
    if have netplan && [ "$(id -u)" -eq 0 ]; then
      local npo; if npo="$(timeout 20 netplan get 2>&1 >/dev/null)"; [ -z "$npo" ]; then ok "netplan lee la configuracion sin errores"
      else fail "netplan detecta problemas al leer la configuracion:" "Corrige el YAML y prueba: sudo netplan try"; echo "$npo" | head -6 | sed 's/^/          /'; fi
    fi
  else warn "No hay ficheros .yaml en $NETPLAN_DIR" "Ubuntu Server usa netplan; ls $NETPLAN_DIR"; fi
}

# ---------------------------------------------------------------- 3. resolucion de nombres
section_resolution() {
  sec "3. Resolucion de nombres (nsswitch, resolv.conf, systemd-resolved)"
  local h; h="$(strip "$NSS_FILE" | grep -E '^\s*hosts:')"
  if [ -n "$h" ]; then info "$(echo $h)"
    echo "$h" | grep -qE 'files.*(resolve|dns)' && ok "Orden de busqueda: primero /etc/hosts (files), despues resolve/dns" || warn "El orden de 'hosts:' es raro" "Esperado: hosts: files resolve [!UNAVAIL=return] dns"
  else warn "No se encuentra la linea 'hosts:' en $NSS_FILE"; fi
  if [ -L /etc/resolv.conf ]; then
    info "resolv.conf es un enlace simbolico -> $(readlink -f /etc/resolv.conf)"
    case "$(readlink -f /etc/resolv.conf)" in *stub-resolv.conf) ok "Apunta a stub-resolv.conf (stub resolver)";; *) warn "No apunta a stub-resolv.conf" "Puede que systemd-resolved no se este usando";; esac
  else warn "/etc/resolv.conf no es un enlace simbolico"; fi
  grep -q '^nameserver 127.0.0.53' /etc/resolv.conf 2>/dev/null && ok "Stub resolver 127.0.0.53 en uso" || info "resolv.conf no muestra 127.0.0.53"
  if have systemctl; then
    systemctl is-active --quiet systemd-resolved 2>/dev/null && ok "systemd-resolved activo" || warn "systemd-resolved NO activo" "sudo systemctl enable --now systemd-resolved"
  fi
  if [ -f "$RESOLVED_CONF" ]; then
    local d dm; d="$(grep -E '^\s*DNS=' "$RESOLVED_CONF" | head -1)"; dm="$(grep -E '^\s*Domains=' "$RESOLVED_CONF" | head -1)"
    [ -n "$d" ]  && ok "DNS configurado en resolved.conf: ${d#*=}"      || info "DNS= comentado en resolved.conf (normal hasta tener servidor DNS)"
    [ -n "$dm" ] && ok "Domains configurado: ${dm#*=}"                  || info "Domains= comentado en resolved.conf (normal hasta tener dominio)"
    grep -qE '^\s*\[Resolve\]' "$RESOLVED_CONF" || warn "No hay seccion [Resolve] sin comentar"
  fi
}

# ---------------------------------------------------------------- 4. servidor DHCP
section_dhcp_server() {
  sec "4. Servidor DHCP (isc-dhcp-server)"
  IFIPS=""; local inst=0
  dpkg -s isc-dhcp-server >/dev/null 2>&1 && { inst=1; ok "Paquete isc-dhcp-server instalado"; } || fail "isc-dhcp-server NO esta instalado" "sudo apt install isc-dhcp-server -y"
  if [ -f "$DHCP_DEFAULTS" ]; then
    local iv4; iv4="$(grep -E '^\s*INTERFACESv4=' "$DHCP_DEFAULTS" | sed 's/.*="\?\([^"]*\)"\?/\1/')"
    if [ -z "$iv4" ]; then fail "INTERFACESv4 vacio o comentado en $DHCP_DEFAULTS" "Pon la interfaz de la red interna: INTERFACESv4=\"enpXsY\""
    else
      info "INTERFACESv4=\"$iv4\""
      local one; for one in $iv4; do
        [ -d "$SYS_NET/$one" ] || { fail "La interfaz '$one' no existe" "Mira los nombres con ip a"; continue; }
        case "$(cat $SYS_NET/$one/operstate 2>/dev/null)" in down) fail "La interfaz $one esta DOWN (sin enlace)" "Revisa el adaptador/cable de la VM o: sudo ip link set $one up";; esac
        if ip -4 -o addr show dev "$one" | grep -q 'inet '; then
          ip -4 -o addr show dev "$one" | grep -q dynamic && warn "$one tiene IP DINAMICA; el servidor deberia escuchar en la interfaz de IP fija" || ok "$one tiene IP fija"
          IFIPS="$IFIPS $(ip -4 -o addr show dev "$one" | awk '{print $4}' | cut -d/ -f1 | tr '\n' ' ')"
        else fail "$one no tiene IPv4" "Configura la IP fija en netplan"; fi
      done
    fi
    grep -qE '^\s*INTERFACES(v4)?=' "$DHCP_DEFAULTS" && [ "$(grep -cE '^\s*INTERFACESv4=' "$DHCP_DEFAULTS")" -gt 1 ] && warn "INTERFACESv4 aparece varias veces en $DHCP_DEFAULTS" "Solo cuenta la ultima; deja una"
  else fail "No existe $DHCP_DEFAULTS"; fi

  if [ -f "$DHCPD_CONF" ]; then
    ok "Existe $DHCPD_CONF"
    [ "$PY_OK" = 0 ] && check_enc "$DHCPD_CONF"   # con Python lo hace el .py
    [ -f "$DHCPD_CONF.bak" ] && ok "Existe la copia $DHCPD_CONF.bak" || warn "No existe $DHCPD_CONF.bak" "Antes de editar: sudo cp $DHCPD_CONF $DHCPD_CONF.bak"
    local inc f; inc="$(strip "$DHCPD_CONF" | grep -oE 'include +"[^"]+"' | sed 's/include *"//;s/"//')"
    for f in $inc; do [ -f "$f" ] && { ok "include existe: $f"; check_enc "$f"; } || fail "include apunta a un fichero inexistente: $f" "Crea el fichero de reservas"; done
    if have dhcpd; then
      if dhcpd -t -cf "$DHCPD_CONF" >/tmp/.dhcpd_t 2>&1; then ok "dhcpd -t: sintaxis correcta"; else fail "dhcpd -t detecta errores de sintaxis:" "Corrige lo siguiente y vuelve a probar"; sed 's/^/          /' /tmp/.dhcpd_t | head -10; fi
      rm -f /tmp/.dhcpd_t
    else warn "No se encuentra el binario dhcpd (no se puede validar con -t)"; fi
    if [ "$PY_OK" = 1 ]; then info "El analisis detallado del contenido (subredes, rangos, reservas...) esta en la seccion 6"
    else info "Sin Python: analisis del contenido hecho con awk"; semantic_awk "$IFIPS"; fi
  else fail "No existe $DHCPD_CONF"; fi

  sec "4b. Servicio, puerto y concesiones"
  if have systemctl; then
    if systemctl is-active --quiet isc-dhcp-server 2>/dev/null; then ok "Servicio isc-dhcp-server ACTIVO"
    else
      fail "Servicio isc-dhcp-server NO activo" "Mira el motivo: sudo journalctl -xeu isc-dhcp-server | tail -30"
      if have journalctl && [ "$(id -u)" -eq 0 ]; then
        journalctl -u isc-dhcp-server -n 40 --no-pager -o cat 2>/dev/null | grep -iE "error|fail|can.t|not configured|no subnet|permission|bind|already|exiting|line [0-9]+" | tail -6 | sed 's/^/          motivo: /'
      fi
    fi
    systemctl is-enabled --quiet isc-dhcp-server 2>/dev/null && info "Habilitado en el arranque" || info "No habilitado en el arranque (sudo systemctl enable isc-dhcp-server)"
  fi
  if have ss; then
    local l; l="$(ss -ulpn 2>/dev/null | grep -E ':67[[:space:]]')"
    if [ -z "$l" ]; then fail "Nadie escucha en UDP 67" "El servicio esta parado o fallo al arrancar"
    elif echo "$l" | grep -q 'dhcpd'; then ok "dhcpd escucha en UDP 67"
    elif echo "$l" | grep -q 'users:'; then fail "El puerto UDP 67 lo ocupa otro programa: $(echo "$l" | grep -o '(("[^"]*"' | head -1 | tr -d '("')" "Para ese servicio (p. ej. dnsmasq u otro dhcpd): sudo systemctl stop NOMBRE"
    else ok "Hay un proceso escuchando en UDP 67 (ejecuta con sudo para ver cual)"; fi
  fi
  if [ "$inst" = 1 ]; then
    if [ -f /var/lib/dhcp/dhcpd.leases ]; then
      local n; n=$(grep -c '^lease ' /var/lib/dhcp/dhcpd.leases 2>/dev/null); info "Concesiones registradas en dhcpd.leases: $n"
      [ "$n" = 0 ] && warn "Ningun cliente ha obtenido IP todavia" "Pide IP en el cliente: sudo dhclient -r && sudo dhclient -v"
    else fail "No existe /var/lib/dhcp/dhcpd.leases" "Sin ese fichero el servicio no arranca: sudo touch /var/lib/dhcp/dhcpd.leases"; fi
    if [ -f /run/dhcp-server/dhcpd.pid ]; then
      kill -0 "$(cat /run/dhcp-server/dhcpd.pid 2>/dev/null)" 2>/dev/null || warn "Hay un fichero pid antiguo de dhcpd sin proceso" "sudo rm /run/dhcp-server/dhcpd.pid y reinicia el servicio"
    fi
  fi
  if [ "$(id -u)" -eq 0 ]; then
    if have ufw && ufw status 2>/dev/null | head -1 | grep -q 'Status: active'; then
      ufw status 2>/dev/null | grep -qE '(^|[^0-9])67(/udp)?[[:space:]]' && ok "ufw activo con regla para UDP 67" || warn "ufw esta activo y no hay regla para UDP 67 (DHCP)" "sudo ufw allow 67/udp"
    fi
    if have iptables && iptables -S INPUT 2>/dev/null | head -1 | grep -q 'DROP'; then
      iptables -S INPUT 2>/dev/null | grep -q 'dport 67' || warn "iptables tiene INPUT en DROP y no hay regla para el puerto 67" "iptables -I INPUT -p udp --dport 67 -j ACCEPT"
    fi
  fi

  sec "4c. Logs recientes"
  local LOG=""
  if have journalctl && [ "$(id -u)" -eq 0 ]; then LOG="$(journalctl -u isc-dhcp-server -n 200 --no-pager 2>/dev/null)"; fi
  [ -z "$LOG" ] && [ -r /var/log/syslog ] && LOG="$(grep -i dhcp /var/log/syslog | tail -200)"
  if [ -z "$LOG" ]; then info "Sin acceso a logs (ejecuta con sudo)"; else
    local disc off req ack nak
    disc=$(echo "$LOG" | grep -c DHCPDISCOVER); off=$(echo "$LOG" | grep -c DHCPOFFER); req=$(echo "$LOG" | grep -c DHCPREQUEST); ack=$(echo "$LOG" | grep -c DHCPACK); nak=$(echo "$LOG" | grep -c DHCPNAK)
    info "DISCOVER=$disc OFFER=$off REQUEST=$req ACK=$ack NAK=$nak"
    [ "$disc" -gt 0 ] && [ "$off" = 0 ] && fail "Llegan DISCOVER pero el servidor no ofrece nada" "Subnet que no encaja con la interfaz, pool agotado o 'deny' mal puesto"
    [ "$off" -gt 0 ] && [ "$req" = 0 ] && warn "El servidor ofrece IP (OFFER) pero el cliente no la solicita (sin REQUEST)" "Cliente con firewall, otro servidor DHCP en la red o cliente que no acepta la oferta"
    [ "$nak" -gt 0 ] && warn "Hay DHCPNAK (el servidor rechaza solicitudes)" "Cliente con IP antigua de otra red o reserva incoherente"
    [ "$ack" -gt 0 ] && ok "Hay DHCPACK: el servidor ya ha concedido IPs"
    echo "$LOG" | grep -qi 'No subnet declaration' && fail "Log: 'No subnet declaration'" "La IP de la interfaz no esta dentro de ninguna subnet de dhcpd.conf"
    echo "$LOG" | grep -qi 'Not configured to listen' && fail "Log: 'Not configured to listen on any interfaces'" "INTERFACESv4 mal puesto o interfaz sin IP"
    echo "$LOG" | grep -qi 'Configuration file errors' && fail "Log: errores en dhcpd.conf" "dhcpd -t -cf $DHCPD_CONF"
    echo "$LOG" | grep -qi 'no free leases' && fail "Log: 'no free leases' (pool agotado)" "Amplia el range o baja el lease-time"
    echo "$LOG" | grep -qiE 'Address already in use|Can.t bind' && fail "Log: el puerto ya esta en uso" "Otro DHCP ocupa el puerto 67: ss -ulpn | grep 67"
    echo "$LOG" | grep -qiE "Can.t open .*dhcpd.leases|Permission denied" && fail "Log: no puede abrir/escribir un fichero (leases o conf)" "Revisa permisos: ls -l /var/lib/dhcp/"
    echo "$LOG" | grep -qiE 'DENIED' && warn "Log: AppArmor ha denegado algo a dhcpd" "sudo dmesg | grep -i apparmor | tail"
    echo "$LOG" | grep -qi 'unknown-' && info "Log: peticiones de clientes sin reserva (normal para el cliente Linux)"
  fi
}

# ---------------------------------------------------------------- 5. cliente
section_client() {
  sec "5. Cliente Linux (DHCP)"
  have nmcli && { info "NetworkManager disponible"; nmcli -t -f DEVICE,STATE,TYPE device 2>/dev/null | grep -v '^lo' | sed 's/^/        /'
    nmcli -t -f STATE device 2>/dev/null | grep -qE '^(disconnected|unavailable)' && warn "NetworkManager marca un dispositivo desconectado/no disponible" "Activa el adaptador en la VM y: nmcli device connect NOMBRE"; }
  local i; for i in $(ls $SYS_NET 2>/dev/null | grep -v '^lo$'); do
    case "$(cat $SYS_NET/$i/operstate 2>/dev/null)" in down) warn "La interfaz $i esta DOWN" "Comprueba el adaptador de la VM o: sudo ip link set $i up";; esac
  done
  local d; d="$(ip route 2>/dev/null | awk '/^default/ {print $5; exit}')"
  [ -n "$d" ] && ok "Hay puerta de enlace por $d" || warn "Sin puerta de enlace (normal si el servidor aun no da gateway)"
  if ip -4 -o addr show | grep -v ' lo ' | grep -q ' 169\.254\.'; then fail "El cliente tiene una IP 169.254.x.x: NO ha recibido respuesta del servidor DHCP" "Servidor parado, mala red interna en la VM o firewall. Prueba: sudo dhclient -r ; sudo dhclient -v"
  elif ip -4 -o addr show | grep -v ' lo ' | grep -q dynamic; then ok "El cliente tiene IP asignada por DHCP"
  else fail "El cliente NO tiene IP dinamica" "sudo dhclient -r ; sudo dhclient -v   (y revisa que NetworkManager este en modo Automatico)"; fi
  grep -E 'nameserver' /etc/resolv.conf 2>/dev/null | sed 's/^/        /'
  have resolvectl && resolvectl dns 2>/dev/null | grep -v '^$' | sed 's/^/        dns: /'
  local lf; for lf in /var/lib/dhcp/dhclient*.leases /var/lib/NetworkManager/*.lease; do
    [ -f "$lf" ] || continue
    info "Concesion en $lf:"
    grep -E 'fixed-address|option routers|option domain-name|dhcp-server-identifier|expire' "$lf" 2>/dev/null | tail -6 | sed 's/^ */        /'
    grep -q 'option routers' "$lf" 2>/dev/null || info "La concesion no trae gateway (coherente si el servidor lo tiene comentado)"
  done
  info "Windows no ejecuta este script: usa  ipconfig /release , ipconfig /renew , ipconfig /all"
}

# ---------------------------------------------------------------- 6. python
section_python() {
  sec "6. Analisis avanzado (Python)"
  if [ "$MODE" != server ]; then info "Solo aplica en el servidor"; return; fi
  if [ "$PY_OK" = 1 ]; then
    local out; out="$(python3 "$DIR/diagnostico_dhcp.py" 2>&1)"
    if printf '%s\n' "$out" | grep -q 'Traceback'; then
      warn "El analisis de Python fallo; uso el de awk" "$(printf '%s\n' "$out" | tail -1)"
      [ -f "$DHCPD_CONF" ] && semantic_awk "$IFIPS"
    else printf '%s\n' "$out"; fi
  else info "Python no disponible: el analisis del contenido de dhcpd.conf ya se hizo con awk en la seccion 4."; fi
}

main() {
  echo "DIAGNOSTICO DHCP - $(date '+%Y-%m-%d %H:%M')  (solo lectura)"
  section_context
  section_identity
  section_network
  section_resolution
  if [ "$MODE" = server ]; then section_dhcp_server; else section_client; fi
  section_python
  sec "RESUMEN"
  printf "  %s%d OK%s   %s%d avisos%s   %s%d errores%s\n" "$G" "$OKS" "$N" "$Y" "$WARNS" "$N" "$R" "$FAILS" "$N"
  [ "$FAILS" -gt 0 ] && echo "  Empieza por el PRIMER [ERROR] de arriba: suele arrastrar a los demas." || echo "  Sin errores bloqueantes. Revisa los avisos segun lo que pida tu enunciado."
}

anon_filter() {
  if [ "$ANON" = 1 ]; then
    local hn; hn="$(hostname 2>/dev/null)"
    # oculta IPs (salvo 127.x y mascaras 255.x), MAC, nombre de la maquina y usuario
    sed -E '/(^|[^0-9.])(127|255)\./!s/\b([0-9]{1,3}\.){3}[0-9]{1,3}\b/x.x.x.x/g; s/\b(10|172|192|169)\.([0-9]{1,3}\.){2}[0-9]{1,3}\b/x.x.x.x/g; s/\b([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b/xx:xx:xx:xx:xx:xx/g; s#/home/[^/ ]+#/home/USER#g' \
      | { if [ "${#hn}" -ge 3 ]; then sed -E "s/\b${hn}\b/HOST/g"; else cat; fi; }
  else cat; fi
}

# ---------------------------------------------------------------- informes (txt + html)
# Carpeta de salida: <home del usuario real>/sh  (no hace falta saber el nombre del usuario)
# Con sudo, $HOME puede ser /root; por eso se usa SUDO_USER para encontrar el home real.
if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ]; then REAL_USER="$SUDO_USER"
else REAL_USER="${USER:-$(id -un)}"; fi
REAL_HOME="$(getent passwd "$REAL_USER" 2>/dev/null | cut -d: -f6)"
[ -z "$REAL_HOME" ] && REAL_HOME="${HOME:-.}"
OUTDIR="${REPORT_DIR:-$REAL_HOME/sh}"
mkdir -p "$OUTDIR" 2>/dev/null || { OUTDIR="."; echo "No pude crear $REAL_HOME/sh; guardo en $(pwd)"; }
OUT_TXT="$OUTDIR/informe_dhcp.txt"
OUT_HTML="$OUTDIR/informe_dhcp.html"

RAW="$(main 2>&1)"
CLEAN="$(printf '%s\n' "$RAW" | sed 's/\x1b\[[0-9;]*m//g' | anon_filter)"

# Lista de problemas: tipo<TAB>seccion<TAB>mensaje<TAB>pista
PROB="$(printf '%s\n' "$CLEAN" | awk '
function flush() { if (t != "") print t "\t" sec "\t" msg "\t" hint; t = "" }
/^== .* ==$/ { flush(); sec = $0; sub(/^== /, "", sec); sub(/ ==$/, "", sec); next }
/^  \[ERROR\]/ { flush(); t = "ERROR"; msg = $0; sub(/^  \[ERROR\] /, "", msg); hint = ""; next }
/^  \[AVISO\]/ { flush(); t = "AVISO"; msg = $0; sub(/^  \[AVISO\] /, "", msg); hint = ""; next }
/^ +-> /      { if (t != "") { hint = $0; sub(/^ +-> /, "", hint) } ; next }
              { flush() }
END           { flush() }')"
if [ -n "$PROB" ]; then   # errores primero, luego avisos, sin repeticiones exactas
  PROB="$( { printf '%s\n' "$PROB" | grep '^ERROR'; printf '%s\n' "$PROB" | grep '^AVISO'; } | awk '!seen[$0]++')"
fi
N_ERR="$(printf '%s\n' "$PROB" | grep -c '^ERROR')"
N_WARN="$(printf '%s\n' "$PROB" | grep -c '^AVISO')"
N_OK="$(printf '%s\n' "$CLEAN" | grep -c '^  \[ OK \]')"
FECHA="$(date '+%Y-%m-%d %H:%M')"

# ---- TXT: primero errores/avisos, luego el informe completo
{
  echo "INFORME DHCP - $FECHA$([ "$ANON" = 1 ] && echo '  (anonimizado)')"
  echo "Resultado: $N_ERR errores, $N_WARN avisos, $N_OK comprobaciones correctas"
  echo
  echo "################ ERRORES Y AVISOS (empieza por el primero) ################"
  if [ -z "$PROB" ]; then echo "  Ninguno. Todo correcto."; else
    printf '%s\n' "$PROB" | awk -F'\t' '
      { n++; printf "\n%d. [%s] (%s)\n   %s\n", n, $1, $2, $3; if ($4 != "") printf "   Pista: %s\n", $4 }'
  fi
  echo
  echo "################ INFORME COMPLETO ################"
  printf '%s\n' "$CLEAN"
} > "$OUT_TXT"

# ---- HTML: tarjetas de errores/avisos + informe completo desplegable
{
cat <<'HTMLHEAD'
<!DOCTYPE html>
<html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Informe DHCP</title>
<style>
body{font-family:system-ui,Segoe UI,Arial,sans-serif;max-width:900px;margin:24px auto;padding:0 16px;color:#222;background:#fafafa}
h1{margin-bottom:4px} .meta{color:#666;margin-bottom:16px}
.sum{display:flex;gap:12px;margin:16px 0 24px}
.box{flex:1;padding:14px;border-radius:10px;text-align:center;color:#fff;font-size:1.1em}
.box b{display:block;font-size:2em}
.e{background:#c62828}.w{background:#ef8f00}.o{background:#2e7d32}
.card{background:#fff;border-left:6px solid;border-radius:6px;padding:10px 14px;margin:10px 0;box-shadow:0 1px 3px #0002}
.card.ERROR{border-color:#c62828}.card.AVISO{border-color:#ef8f00}
.tag{font-weight:700;font-size:.8em;padding:2px 8px;border-radius:10px;color:#fff;margin-right:6px}
.ERROR .tag{background:#c62828}.AVISO .tag{background:#ef8f00}
.sec{color:#666;font-size:.85em}.hint{margin-top:6px;color:#0b5394}
.good{padding:14px;background:#e8f5e9;border-radius:8px}
details{margin-top:28px} summary{cursor:pointer;font-weight:700}
pre{background:#1e1e1e;color:#ddd;padding:14px;border-radius:8px;overflow-x:auto;font-size:.85em;line-height:1.4}
</style></head><body>
<h1>Informe de diagn&oacute;stico DHCP</h1>
HTMLHEAD
echo "<div class=\"meta\">$FECHA$([ "$ANON" = 1 ] && echo ' &middot; anonimizado')</div>"
echo "<div class=\"sum\"><div class=\"box e\"><b>$N_ERR</b>errores</div><div class=\"box w\"><b>$N_WARN</b>avisos</div><div class=\"box o\"><b>$N_OK</b>correctas</div></div>"
echo "<h2>Errores y avisos</h2>"
if [ -z "$PROB" ]; then echo '<div class="good">Ninguno. Todo correcto.</div>'; else
  printf '%s\n' "$PROB" | awk -F'\t' '
    function esc(s) { gsub(/&/, "\\&amp;", s); gsub(/</, "\\&lt;", s); gsub(/>/, "\\&gt;", s); return s }
    { n++
      printf "<div class=\"card %s\"><span class=\"tag\">%s %d</span><span class=\"sec\">%s</span><div>%s</div>", $1, $1, n, esc($2), esc($3)
      if ($4 != "") printf "<div class=\"hint\">&rarr; %s</div>", esc($4)
      print "</div>" }'
fi
echo '<details><summary>Ver informe completo</summary><pre>'
printf '%s\n' "$CLEAN" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g'
echo '</pre></details></body></html>'
} > "$OUT_HTML"

# Si se ejecuto con sudo, los ficheros deben ser del usuario real (no de root)
if [ "$(id -u)" -eq 0 ] && [ "$REAL_USER" != root ]; then
  chown "$REAL_USER": "$OUTDIR" "$OUT_TXT" "$OUT_HTML" 2>/dev/null
fi

if [ -t 1 ] && [ "$ANON" = 0 ]; then printf '%s\n' "$RAW"; else printf '%s\n' "$CLEAN"; fi
echo
printf '%s\n' "Resultado: $N_ERR errores, $N_WARN avisos, $N_OK correctas" 
printf '%s\n' "Informes guardados en:
  $OUT_TXT
  $OUT_HTML$([ "$ANON" = 1 ] && echo '  (anonimizados)')" | anon_filter
[ "$N_ERR" -gt 0 ] && exit 1
exit 0
