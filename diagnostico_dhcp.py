#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
diagnostico_dhcp.py - Analisis AVANZADO (solo lectura) de dhcpd.conf.
No necesita red ni paquetes externos (solo libreria estandar de Python 3).
Uso:  python3 diagnostico_dhcp.py [--conf /etc/dhcp/dhcpd.conf] [--iface enp5s0]
"""
import sys, os, re, ipaddress, subprocess, difflib

CONF = os.environ.get("DHCPD_CONF", "/etc/dhcp/dhcpd.conf")
DEFAULTS = os.environ.get("DHCP_DEFAULTS", "/etc/default/isc-dhcp-server")
IFACE = None
args = sys.argv[1:]
for i, a in enumerate(args):
    if a == "--conf" and i + 1 < len(args): CONF = args[i + 1]
    if a == "--iface" and i + 1 < len(args): IFACE = args[i + 1]

res = {"ok": 0, "warn": 0, "fail": 0}
def ok(m):   res["ok"] += 1;   print("  [ OK ] " + m)
def warn(m, h=None):
    res["warn"] += 1; print("  [AVISO] " + m)
    if h: print("          -> " + h)
def fail(m, h=None):
    res["fail"] += 1; print("  [ERROR] " + m)
    if h: print("          -> " + h)
def info(m): print("  [ i ] " + m)

# ---------------------------------------------------------------- parser
KNOWN_STMTS = set("""option default-lease-time max-lease-time min-lease-time authoritative not ddns-update-style ddns-updates
ddns-domainname ddns-rev-domainname deny allow ignore range hardware fixed-address filename next-server server-name log-facility include
update-static-leases ping-check ping-timeout one-lease-per-client get-lease-hostnames use-host-decl-names server-identifier set unset if
elsif else match boot-unknown-clients bootp-broadcast-always always-broadcast always-reply-rfc1048 dynamic-bootp-lease-cutoff
dynamic-bootp-lease-length min-secs adaptive-lease-time-threshold lease-file-name pid-file-name local-address local-port omapi-port
omapi-key key algorithm secret primary secondary address port peer max-response-delay max-unacked-updates mclt split load
site-option-space vendor-option-space stash-agent-options ignore-client-uids prefix6 range6 preferred-lifetime host-identifier failover zone
dns-update""".split())
KNOWN_OPTS = set("""subnet-mask time-offset routers time-servers name-servers domain-name-servers log-servers cookie-servers lpr-servers
impress-servers resource-location-servers host-name boot-size merit-dump domain-name swap-server root-path extensions-path ip-forwarding
non-local-source-routing policy-filter max-dgram-reassembly default-ip-ttl path-mtu-aging-timeout path-mtu-plateau-table interface-mtu
all-subnets-local broadcast-address perform-mask-discovery mask-supplier router-discovery router-solicitation-address static-routes
trailer-encapsulation arp-cache-timeout ieee802-3-encapsulation default-tcp-ttl tcp-keepalive-interval tcp-keepalive-garbage nis-domain
nis-servers ntp-servers vendor-encapsulated-options netbios-name-servers netbios-dd-server netbios-node-type netbios-scope font-servers
x-display-manager dhcp-requested-address dhcp-lease-time dhcp-option-overload dhcp-message-type dhcp-server-identifier dhcp-message
dhcp-max-message-size dhcp-renewal-time dhcp-rebinding-time vendor-class-identifier dhcp-client-identifier nisplus-domain nisplus-servers
tftp-server-name bootfile-name mobile-ip-home-agent smtp-server pop-server nntp-server www-server finger-server irc-server streettalk-server
streettalk-directory-assistance-server user-class slp-directory-agent slp-service-scope fqdn nds-servers nds-tree-name nds-context
domain-search classless-static-routes ms-classless-static-routes tftp-server-address space""".split())
STARTERS = set("default-lease-time max-lease-time min-lease-time option range authoritative ddns-update-style fixed-address hardware include filename next-server server-name".split())

def close(word, universe):
    m = difflib.get_close_matches(word, sorted(universe), n=1, cutoff=0.75)
    return m[0] if m else None

KNOWN_BLOCKS = ("subnet", "pool", "host", "group", "shared-network", "class", "subclass", "zone", "key", "failover", "group")

class Node:
    def __init__(self, header, line, parent=None):
        self.header, self.line, self.parent = header.strip(), line, parent
        self.stmts, self.children = [], []   # stmts: (text, line)
    @property
    def kind(self):
        return self.header.split()[0] if self.header else "global"

def read_conf(path, seen=None, depth=0):
    """Devuelve (texto sin comentarios con include expandidos, lista de errores)."""
    seen = seen or set()
    errs = []
    if path in seen or depth > 5:
        return "", errs
    seen.add(path)
    try:
        raw = open(path, encoding="utf-8", errors="replace").read()
    except OSError as e:
        return "", ["No se puede leer %s (%s)" % (path, e.strerror)]
    out = []
    for n, line in enumerate(raw.splitlines(), 1):
        code = re.sub(r"#.*$", "", line) if '"' not in line else line
        m = re.match(r'\s*include\s+"([^"]+)"\s*;', code)
        if m:
            inc = m.group(1)
            if not os.path.isfile(inc):
                errs.append("%s:%d include apunta a un fichero que NO existe: %s" % (os.path.basename(path), n, inc))
            else:
                txt, e2 = read_conf(inc, seen, depth + 1)
                errs += e2
                out.append(txt)
            continue
        out.append(code)
    return "\n".join(out), errs

def parse(text):
    root = Node("", 0)
    cur, buf, line, buf_line = root, [], 1, 1
    errors, in_str, started = [], False, False
    for ch in text:
        if ch == "\n": line += 1
        if ch == '"': in_str = not in_str
        if not in_str and ch in ";{}":
            b = "".join(buf).strip()
            if ch == ";":
                if b: cur.stmts.append((re.sub(r"\s+", " ", b), buf_line))
            elif ch == "{":
                hdr = re.sub(r"\s+", " ", b)
                first = hdr.split()[0] if hdr else ""
                if hdr and first not in KNOWN_BLOCKS:
                    m2 = re.search(r"\s(%s)\b" % "|".join(KNOWN_BLOCKS), hdr)
                    if m2:
                        errors.append("Linea %d: '%s' parece NO acabar en ';' y se junta con el bloque siguiente" % (buf_line, hdr[:m2.start()][:50]))
                        hdr = hdr[m2.start():].strip()
                    else:
                        sug = close(first, KNOWN_BLOCKS)
                        errors.append("Linea %d: bloque desconocido '%s'%s" % (buf_line, hdr[:40], (" -> quisiste decir '%s'?" % sug) if sug else ""))
                n = Node(hdr, buf_line, cur)
                cur.children.append(n); cur = n
            else:  # }
                if b: errors.append("Linea %d: falta ';' antes de '}' -> '%s'" % (line, b[:60]))
                if cur.parent is None: errors.append("Linea %d: '}' sobrante (no hay bloque abierto)" % line)
                else: cur = cur.parent
            buf, started = [], False
        else:
            if not started and ch.strip(): buf_line, started = line, True
            buf.append(ch)
    if "".join(buf).strip():
        errors.append("Linea %d: la ultima directiva no termina en ';' -> '%s'" % (buf_line, "".join(buf).strip()[:60]))
    if cur.parent is not None:
        errors.append("Falta cerrar un bloque '{' abierto en la linea %d ('%s')" % (cur.line, cur.header[:40]))
    return root, errors

def walk(n):
    yield n
    for c in n.children:
        for x in walk(c): yield x

def server_iface():
    iface = IFACE
    if not iface and os.path.isfile(DEFAULTS):
        m = re.search(r'^\s*INTERFACESv4\s*=\s*"([^"]*)"', open(DEFAULTS, errors="replace").read(), re.M)
        if m: iface = m.group(1).split()[0] if m.group(1).split() else None
    addrs = []
    if iface:
        try:
            outp = subprocess.run(["ip", "-4", "-o", "addr", "show", "dev", iface], capture_output=True, text=True).stdout
            addrs = re.findall(r"inet\s+(\S+)", outp)
        except Exception:
            addrs = []
    return iface, addrs

# ---------------------------------------------------------------- analisis
def main():
    print("== Analisis avanzado de %s ==" % CONF)
    if not os.path.isfile(CONF):
        fail("No existe %s" % CONF, "Instala isc-dhcp-server y crea el fichero (sudo nano %s)" % CONF)
        return
    text, errs = read_conf(CONF)
    for e in errs: fail(e, "Revisa la ruta del include y que el fichero exista")
    try:
        rawtxt = open(CONF, encoding="utf-8", errors="replace").read()
        if "\r" in rawtxt: warn("%s tiene saltos de linea de Windows (CRLF)" % CONF, "Convierte: sudo sed -i 's/\\r$//' %s" % CONF)
        for n_, l_ in enumerate(rawtxt.splitlines(), 1):
            code = re.sub(r"#.*$", "", l_)
            bad_ = [c for c in code if ord(c) > 127]
            if bad_: fail("Linea %d: caracter no ASCII %r (comillas tipograficas, espacio raro...)" % (n_, "".join(bad_[:3])), "Retecle esa linea a mano; suele venir de copiar/pegar de un PDF o Word")
    except OSError:
        pass
    root, perr = parse(text)
    for e in perr: fail(e, "Cada directiva acaba en ';' y cada bloque se cierra con '}'")
    if not errs and not perr: ok("Estructura correcta: llaves equilibradas y todas las directivas terminan en ';'")

    nodes = list(walk(root))
    # ---- ';' olvidado entre dos directivas y erratas en nombres de directivas/opciones
    for n in nodes:
        fixed = []
        queue = list(n.stmts)
        while queue:
            text, ln = queue.pop(0)
            w = text.split()
            if w and w[0] not in ("not", "deny", "allow", "ignore"):
                cut = next((k for k in range(1, len(w)) if w[k] in STARTERS and not (w[0] == "hardware" and k == 1)), None)
                if cut:
                    fail("Linea %d: falta ';' al final de '%s' (se junta con '%s')" % (ln, " ".join(w[:cut])[:50], w[cut]),
                         "Anade ';' despues de '%s'" % " ".join(w[:cut]))
                    text = " ".join(w[:cut]); queue.insert(0, (" ".join(w[cut:]), ln)); w = w[:cut]
            if w:
                if w[0] in KNOWN_STMTS:
                    if w[0] == "option" and len(w) > 1 and w[1] not in KNOWN_OPTS and " code " not in text:
                        sug = close(w[1], KNOWN_OPTS)
                        if sug: fail("Linea %d: la opcion '%s' no existe" % (ln, w[1]), "Quisiste decir 'option %s'?" % sug)
                        else: info("Linea %d: opcion '%s' no es estandar (valida solo si la defines tu)" % (ln, w[1]))
                elif re.match(r"^[a-z0-9-]+$", w[0]):
                    sug = close(w[0], KNOWN_STMTS)
                    if sug: fail("Linea %d: la directiva '%s' no existe" % (ln, w[0]), "Quisiste decir '%s'?" % sug)
                    else: warn("Linea %d: directiva desconocida '%s'" % (ln, w[0]), "Revisa que este bien escrita")
            fixed.append((text, ln))
        n.stmts = fixed
    # ---- opciones globales
    g = [s for s, _ in root.stmts]
    gtxt = " | ".join(g)
    def has(p): return re.search(p, gtxt) is not None
    if has(r"^authoritative|\| authoritative"): ok("Servidor autoritativo (authoritative)")
    else: warn("Falta 'authoritative;' en opciones globales", "Si el enunciado dice que el servidor es el autorizado y revoca IPs, anade authoritative;")
    if has(r"ddns-update-style none"): ok("DNS dinamico desactivado (ddns-update-style none)")
    else: warn("Falta 'ddns-update-style none;'", "El servidor NO debe actualizar el DNS segun el enunciado")
    if has(r"deny client-updates"): ok("Denegadas las actualizaciones del cliente (deny client-updates)")
    else: warn("Falta 'deny client-updates;'", "Denegar que el cliente actualice sus asignaciones")
    if has(r"log-facility"): warn("Has tocado log-facility", "El enunciado pide dejar el log por defecto")
    else: ok("log-facility sin tocar (valor por defecto)")

    # ---- subredes
    subnets = []
    for n in nodes:
        if n.kind == "subnet":
            m = re.match(r"subnet\s+(\S+)\s+netmask\s+(\S+)", n.header)
            if not m:
                fail("Linea %d: cabecera de subnet mal escrita: '%s'" % (n.line, n.header), "Formato: subnet 192.168.50.0 netmask 255.255.255.0 {")
                continue
            try:
                net = ipaddress.ip_network("%s/%s" % (m.group(1), m.group(2)), strict=True)
            except ValueError as e:
                fail("Linea %d: subnet/netmask incoherentes (%s)" % (n.line, e), "La direccion de red debe acabar en el bit de red (ej. .0 para /24)")
                continue
            subnets.append((net, n))
    for i_ in range(len(subnets)):
        for j_ in range(i_ + 1, len(subnets)):
            if subnets[i_][0].overlaps(subnets[j_][0]):
                fail("Las subredes %s y %s se solapan" % (subnets[i_][0], subnets[j_][0]), "Cada subred debe ser un rango distinto")
    iface, srv_addrs = server_iface()
    srv_ips = [ipaddress.ip_interface(a).ip for a in srv_addrs]
    if not subnets:
        fail("No hay ninguna declaracion 'subnet'", "Sin subnet para la interfaz del servidor aparece 'No subnet declaration'")
    for net, n in subnets:
        info("Subred %s (linea %d)" % (net, n.line))
        # herencia de opciones: subnet + global
        def opt(name):
            src = n
            while src is not None:          # sube por group / shared-network hasta el global
                for s, _ in src.stmts:
                    if re.match(r"(option\s+)?%s(\s|$)" % re.escape(name), s): return s
                src = src.parent
            return None
        mask_opt = opt("subnet-mask")
        if mask_opt and str(net.netmask) not in mask_opt: warn("subnet-mask distinta de la mascara de la subnet: " + mask_opt)
        b = opt("broadcast-address")
        if b:
            if str(net.broadcast_address) in b: ok("broadcast-address correcto (%s)" % net.broadcast_address)
            else: fail("broadcast-address incorrecto: '%s'" % b, "Deberia ser %s" % net.broadcast_address)
        else: warn("Falta option broadcast-address en la subnet", "Si el enunciado pide dar el broadcast, anade option broadcast-address %s;" % net.broadcast_address)
        if not opt("domain-name"): warn("Falta option domain-name", "El enunciado pide el nombre de dominio (domXXX.internal)")
        if not opt("domain-name-servers"): warn("Falta option domain-name-servers", "Anade los servidores DNS que pida el enunciado")
        r = [x for x in [opt("routers")] if x]
        if r: info("option routers esta ACTIVA (%s). Si el enunciado la pide comentada, ponle # delante" % r[0])
        else: ok("option routers comentada/ausente (coherente con 'gateway comentado, se activara mas adelante')")
        dn = opt("domain-name")
        if dn and not re.search(r'"[^"]+"', dn): fail("option domain-name sin comillas: '%s'" % dn, 'Va entre comillas: option domain-name "dom100.internal";')
        dns = opt("domain-name-servers")
        if dns:
            for tok in re.split(r"[\s,]+", re.sub(r"^option\s+domain-name-servers\s+", "", dns)):
                if tok and re.match(r"^[0-9.]+$", tok):
                    try: ipaddress.ip_address(tok)
                    except ValueError: fail("DNS con IP no valida: %s" % tok, "Son 4 numeros de 0 a 255")
        rt = opt("routers")
        if rt:
            tok = re.sub(r"^option\s+routers\s+", "", rt).replace(",", " ").split()[0]
            try:
                if ipaddress.ip_address(tok) not in net: fail("option routers %s esta FUERA de la subred %s" % (tok, net), "El gateway debe pertenecer a la misma subred")
            except ValueError: fail("option routers con IP no valida: %s" % tok)
        dl, ml = opt("default-lease-time"), opt("max-lease-time")
        dnum, mnum = re.search(r"(\d+)", dl or ""), re.search(r"(\d+)", ml or "")
        if dnum and mnum and int(dnum.group(1)) > int(mnum.group(1)):
            fail("default-lease-time (%s) es MAYOR que max-lease-time (%s)" % (dnum.group(1), mnum.group(1)), "El maximo debe ser igual o mayor que el normal")
        d_ok = dl and re.search(r"\b86400\b", dl); m_ok = ml and re.search(r"\b172800\b", ml)
        if d_ok and m_ok: ok("Lease 1 dia (86400) renovable 2 dias (172800)")
        else: warn("Lease distinto de 86400/172800 (default=%s, max=%s)" % (dl, ml), "1 dia = 86400 s; 2 dias = 172800 s. Ignora este aviso si tu enunciado pide otros tiempos")

    # ---- pools / rangos
    ranges = []
    for n in nodes:
        for s, ln in n.stmts:
            m = re.match(r"range\s+(?:dynamic-bootp\s+)?(\S+)(?:\s+(\S+))?$", s)
            if m:
                try:
                    a = ipaddress.ip_address(m.group(1)); b = ipaddress.ip_address(m.group(2) or m.group(1))
                except ValueError:
                    fail("Linea %d: IP del 'range' no valida: '%s'" % (ln, s)); continue
                if a > b: fail("Linea %d: el range empieza despues de acabar (%s > %s)" % (ln, a, b), "Pon primero la IP menor")
                inside = [net for net, _ in subnets if a in net and b in net]
                if not inside: fail("Linea %d: el range %s-%s NO esta dentro de ninguna subnet declarada" % (ln, a, b), "Revisa la red y la mascara")
                elif a <= b:
                    ok("range %s - %s dentro de %s" % (a, b, inside[0]))
                    if a == inside[0].network_address or b == inside[0].broadcast_address:
                        warn("El range incluye la direccion de red o de broadcast", "Empieza en .1 o mas y acaba antes del broadcast")
                for sip in srv_ips:
                    if a <= sip <= b: fail("El range %s-%s incluye la IP del propio servidor (%s)" % (a, b, sip), "Deja la IP del servidor fuera del pool")
                ranges.append((a, b, n))
    for i_ in range(len(ranges)):
        for j_ in range(i_ + 1, len(ranges)):
            if ranges[i_][0] <= ranges[j_][1] and ranges[j_][0] <= ranges[i_][1]:
                warn("Dos range se solapan: %s-%s y %s-%s" % (ranges[i_][0], ranges[i_][1], ranges[j_][0], ranges[j_][1]))
    deny_known = any(re.match(r"deny known-clients", s) for n in nodes if n.kind == "pool" for s, _ in n.stmts)

    # ---- hosts / reservas
    hosts, macs, ips, hnames = [], {}, {}, {}
    for n in nodes:
        if n.kind == "host":
            name = n.header.split()[1] if len(n.header.split()) > 1 else "?"
            mac = fix = None
            for s, ln in n.stmts:
                m = re.match(r"hardware ethernet\s+(\S+)", s)
                if m: mac = (m.group(1), ln)
                m = re.match(r"fixed-address\s+(\S+)", s)
                if m: fix = (m.group(1), ln)
            hosts.append((name, mac, fix, n))
    if hosts:
        info("%d reserva(s) (host) encontradas" % len(hosts))
        for name, mac, fix, n in hosts:
            if name in hnames: fail("Nombre de host repetido: '%s'" % name, "Cada 'host' necesita un nombre distinto")
            hnames[name] = 1
            if not mac: fail("host '%s' (linea %d) sin 'hardware ethernet'" % (name, n.line), "Anade hardware ethernet XX:XX:XX:XX:XX:XX;"); 
            else:
                if not re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", mac[0]):
                    fail("host '%s': MAC con formato incorrecto '%s'" % (name, mac[0]), "dhcpd separa los pares con DOS PUNTOS, no con guiones (Windows los muestra con guiones)")
                else: ok("host '%s': MAC con formato correcto" % name)
                key = mac[0].lower()
                if key in macs: fail("MAC repetida en '%s' y '%s'" % (macs[key], name))
                macs[key] = name
            if not fix: fail("host '%s' (linea %d) sin 'fixed-address'" % (name, n.line), "Anade fixed-address <IP>;")
            else:
                try:
                    ip = ipaddress.ip_address(fix[0])
                except ValueError:
                    fail("host '%s': fixed-address no es una IP valida (%s)" % (name, fix[0])); continue
                if ip in srv_ips: fail("host '%s': %s es la IP del propio servidor" % (name, ip), "Elige otra IP para la reserva")
                if ip in ips: fail("IP %s repetida en '%s' y '%s'" % (ip, ips[ip], name))
                ips[ip] = name
                if not any(ip in net for net, _ in subnets): fail("host '%s': %s no esta dentro de ninguna subnet" % (name, ip), "La reserva debe pertenecer a la subred")
                else: ok("host '%s': %s dentro de la subred" % (name, ip))
                for a, b, _ in ranges:
                    if a <= ip <= b:
                        fail("host '%s': %s cae DENTRO del pool %s-%s" % (name, ip, a, b), "La reserva debe ir fuera del pool (ej. .10-.99 vs pool .100-.200)")
        if ranges and not deny_known:
            warn("Hay reservas y pool, pero no hay 'deny known-clients;' en el pool", "Asi un cliente con reserva podria coger IP del pool")
        elif deny_known: ok("El pool deniega a los clientes con reserva (deny known-clients)")
        if not any(n.kind == "group" for n in nodes):
            info("No hay bloque 'group' (el enunciado suele pedirlo para unificar dominio y DNS)")
    else:
        info("No hay reservas (host). Si tu practica incluye cliente Windows registrado, falta la reserva por MAC")

    # ---- interfaz del servidor vs subnets
    if not iface: warn("No se ha podido saber la interfaz del servidor", "Revisa INTERFACESv4 en %s o usa --iface" % DEFAULTS)
    elif not srv_addrs: fail("La interfaz %s no tiene IPv4 (o no existe)" % iface, "Configura la IP fija con netplan y aplica: sudo netplan apply")
    else:
        for a in srv_addrs:
            ip = ipaddress.ip_interface(a).ip
            if any(ip in net for net, _ in subnets): ok("%s tiene %s y hay una subnet que la contiene (sin esto: 'No subnet declaration')" % (iface, a))
            else: fail("%s tiene %s pero NINGUNA subnet de dhcpd.conf la contiene" % (iface, a), "Anade una subnet que incluya esa IP o corrige INTERFACESv4")
    print("\n  Resumen avanzado: %d OK, %d avisos, %d errores" % (res["ok"], res["warn"], res["fail"]))

if __name__ == "__main__":
    main()
    sys.exit(1 if res["fail"] else 0)
