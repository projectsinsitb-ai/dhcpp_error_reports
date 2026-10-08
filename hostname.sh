#!/bin/bash
# paso1_usuario_hostname.sh
# Uso: sudo bash paso1_usuario_hostname.sh

[ "$EUID" -eq 0 ] || { echo "Ejecuta con: sudo bash $0"; exit 1; }

NEWUSER="xx"
NEWHOST="seritb"
OLDHOST="$(hostname)"

# --- 1. Usuario con sudo ---
if id "$NEWUSER" &>/dev/null; then
    echo "[i] El usuario $NEWUSER ya existe, solo me aseguro de que esté en sudo."
else
    adduser --disabled-password --gecos "" "$NEWUSER"
    while true; do
        read -rsp "Contraseña para $NEWUSER: " P1; echo
        read -rsp "Repite la contraseña: " P2; echo
        [ "$P1" = "$P2" ] && [ -n "$P1" ] && break
        echo "No coinciden o está vacía, otra vez."
    done
    echo "$NEWUSER:$P1" | chpasswd
    unset P1 P2
fi
usermod -aG sudo "$NEWUSER"

# --- 2. Hostname ---
hostnamectl set-hostname "$NEWHOST"
if grep -q '^127\.0\.1\.1' /etc/hosts; then
    sed -i "s/^127\.0\.1\.1.*/127.0.1.1 $NEWHOST/" /etc/hosts
else
    echo "127.0.1.1 $NEWHOST" >> /etc/hosts
fi

# --- 3. Log de pruebas (estilo captura de terminal) ---
LOGDIR="/home/$NEWUSER/pruebas"
LOG="$LOGDIR/paso1_usuario_hostname.txt"
mkdir -p "$LOGDIR"
: > "$LOG"

run() {
    printf '%s@%s:~$ %s\n' "$NEWUSER" "$NEWHOST" "$1" | tee -a "$LOG"
    sudo -u "$NEWUSER" -H bash -c "cd ~; $1" 2>&1 | tee -a "$LOG"
}

run 'ls'
run 'echo $HOSTNAME'
run 'whoami'
run "id $NEWUSER"
run 'hostnamectl'
run 'ip a'
run 'ip -br a'

chown -R "$NEWUSER:$NEWUSER" "$LOGDIR"

echo
echo "[OK] Log guardado en: $LOG"
echo "Cierra sesión y entra como $NEWUSER (o haz: su - $NEWUSER)."
