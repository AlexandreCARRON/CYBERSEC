#!/usr/bin/env bash
#
# ssh-audit-interactive.sh
#
# Script d’audit interactif SSH / logs / sécurité pour VPS
# - Chaque test demande confirmation (y/n)
# - Aucune hypothèse fragile sur la présence des paquets
# - Compatible multi-distributions (apt, dnf, yum, apk, pacman)
# - Tolérant aux erreurs (ne casse pas tout si une étape échoue)
# - Sauvegarde les fichiers avant toute modification
#
#  démarrage via commande : sudo chmod +x ssh-audit-interactive.sh     puis         sudo ./ssh-audit-interactive.sh
###### Erreurs connues : 
######################### Intallation des paquets sur demande
######################### Proposition reconfig MaxAuthTry


set -uo pipefail

SCRIPT_NAME="$(basename "$0")"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR="/root/ssh-audit-backups-$TIMESTAMP"

# -------------------------------
# Helpers / UI
# -------------------------------
say() { printf '%s\n' "$*"; }
hr() { printf '%s\n' "------------------------------------------------------------"; }

need_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    say "Ce script doit être exécuté en root. Exemple : sudo ./$SCRIPT_NAME"
    exit 1
  fi
}

have_cmd() { command -v "$1" >/dev/null 2>&1; }

ask_yn() {
  local prompt="$1" default="${2:-N}" ans
  while true; do
    if [[ "$default" =~ ^[Yy]$ ]]; then
      read -r -p "$prompt [Y/n] " ans || true
      ans="${ans:-Y}"
    else
      read -r -p "$prompt [y/N] " ans || true
      ans="${ans:-N}"
    fi
    case "$ans" in
      Y|y) return 0 ;;
      N|n) return 1 ;;
      *) say "Répondre par y ou n." ;;
    esac
  done
}

run_show() {
  local title="$1"; shift
  hr
  say "$title"
  hr
  "$@" 2>&1 || true
}

backup_file() {
  local f="$1"
  [[ -f "$f" ]] || return 0
  mkdir -p "$BACKUP_DIR" 2>/dev/null || true
  local dst="$BACKUP_DIR$(echo "$f" | sed 's#/#_#g')"
  cp -a "$f" "$dst" 2>/dev/null || true
}

# -------------------------------
# Détection services / fichiers
# -------------------------------
detect_ssh_service_name() {
  if have_cmd systemctl && systemctl list-unit-files 2>/dev/null | grep -q '^ssh\.service'; then
    echo "ssh"
  elif have_cmd systemctl && systemctl list-unit-files 2>/dev/null | grep -q '^sshd\.service'; then
    echo "sshd"
  else
    echo "ssh"
  fi
}

sshd_config_path() {
  [[ -f /etc/ssh/sshd_config ]] && echo "/etc/ssh/sshd_config" || echo ""
}

# -------------------------------
# Gestionnaire de paquets (robuste)
# -------------------------------
pkg_mgr_detect() {
  if have_cmd apt-get; then echo "apt"
  elif have_cmd dnf; then echo "dnf"
  elif have_cmd yum; then echo "yum"
  elif have_cmd apk; then echo "apk"
  elif have_cmd pacman; then echo "pacman"
  else echo "none"
  fi
}

pkg_update() {
  local pm="$1"
  case "$pm" in
    apt)    run_show "Mise à jour index paquets (apt-get update)" apt-get update -y ;;
    dnf)    run_show "Mise à jour cache paquets (dnf makecache)" dnf -y makecache ;;
    yum)    run_show "Mise à jour cache paquets (yum makecache)" yum -y makecache ;;
    apk)    run_show "Mise à jour index paquets (apk update)" apk update ;;
    pacman) run_show "Mise à jour index paquets (pacman -Sy)" pacman -Sy --noconfirm ;;
    *)      say "Aucun gestionnaire de paquets supporté détecté." ;;
  esac
}

pkg_available() {
  local pm="$1" pkg="$2"
  case "$pm" in
    apt)
      apt-cache policy "$pkg" 2>/dev/null | grep -q 'Candidate:' || return 1
      ! apt-cache policy "$pkg" 2>/dev/null | grep -q 'Candidate: (none)'
      ;;
    dnf) dnf -q list --available "$pkg" >/dev/null 2>&1 ;;
    yum) yum -q list available "$pkg" >/dev/null 2>&1 ;;
    apk) apk search -x "$pkg" >/dev/null 2>&1 ;;
    pacman) pacman -Si "$pkg" >/dev/null 2>&1 ;;
    *) return 1 ;;
  esac
}

pkg_install() {
  local pm="$1"; shift
  local pkgs=("$@")
  case "$pm" in
    apt)    run_show "Installation (apt-get install ${pkgs[*]})" apt-get install -y "${pkgs[@]}" ;;
    dnf)    run_show "Installation (dnf install ${pkgs[*]})" dnf -y install "${pkgs[@]}" ;;
    yum)    run_show "Installation (yum install ${pkgs[*]})" yum -y install "${pkgs[@]}" ;;
    apk)    run_show "Installation (apk add ${pkgs[*]})" apk add --no-cache "${pkgs[@]}" ;;
    pacman) run_show "Installation (pacman -S ${pkgs[*]})" pacman -S --noconfirm --needed "${pkgs[@]}" ;;
    *)      say "Impossible d’installer : aucun gestionnaire supporté." ; return 1 ;;
  esac
}

is_pkg_installed() {
  # Best-effort multi-distro check
  local pkg="$1"
  if have_cmd dpkg-query; then
    dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "installed" && return 0
  fi
  if have_cmd rpm; then
    rpm -q "$pkg" >/dev/null 2>&1 && return 0
  fi
  if have_cmd apk; then
    apk info -e "$pkg" >/dev/null 2>&1 && return 0
  fi
  if have_cmd pacman; then
    pacman -Qi "$pkg" >/dev/null 2>&1 && return 0
  fi
  return 1
}

ensure_pkg_installed_interactive() {
  # Installe un paquet s'il n'est pas présent + propose enable/start du service.
  local pkg="$1" service_name="${2:-}"
  local pm; pm="$(pkg_mgr_detect)"

  if [[ "$pm" == "none" ]]; then
    say "Gestionnaire de paquets non détecté : installation impossible pour $pkg."
    return 1
  fi

  if is_pkg_installed "$pkg"; then
    say "$pkg : déjà installé."
    return 0
  fi

  say "$pkg : non installé."
  if ! pkg_available "$pm" "$pkg"; then
    say "Paquet $pkg non disponible dans le cache actuel -> refresh index/caches…"
    pkg_update "$pm"
  fi

  if ! pkg_available "$pm" "$pkg"; then
    say "Paquet $pkg toujours indisponible après refresh."
    if [[ "$pm" == "apt" ]]; then
      run_show "Diagnostic APT: apt-cache policy $pkg" apt-cache policy "$pkg"
      run_show "Sources APT (extrait)" bash -lc 'grep -R "^[^#]" -n /etc/apt/sources.list /etc/apt/sources.list.d/* 2>/dev/null | head -n 200 || true'
    fi
    return 1
  fi

  if ask_yn "Installer $pkg maintenant ?" "Y"; then
    pkg_install "$pm" "$pkg" || return 1

    if [[ -n "$service_name" ]] && have_cmd systemctl; then
      if ask_yn "Activer et démarrer le service $service_name ?" "Y"; then
        run_show "Enable+start $service_name" systemctl enable --now "$service_name"
        systemctl --no-pager --full status "$service_name" 2>/dev/null || true
      fi
    fi
  fi
  return 0
}

# -------------------------------
# SSH: lecture config effective + modifications visibles
# -------------------------------
sshd_effective_get() {
  have_cmd sshd && sshd -T 2>/dev/null || true
}

sshd_effective_value() {
  local key="$1"
  sshd_effective_get | awk -v k="$key" '$1==k {print $2; exit}'
}

sshd_config_current_line() {
  # Première ligne NON commentée correspondant à la directive (si existe)
  local key="$1" cfg="$2"
  grep -E "^[[:space:]]*$key[[:space:]]+" "$cfg" 2>/dev/null | head -n 1 || true
}

show_change_and_confirm() {
  local key="$1" proposed_value="$2" cfg="$3"
  local current_line proposed_line
  current_line="$(sshd_config_current_line "$key" "$cfg")"
  proposed_line="$key $proposed_value"

  hr
  say "Changement proposé dans $cfg"
  say "  Directive : $key"
  if [[ -n "$current_line" ]]; then
    say "  Actuel    : $current_line"
  else
    say "  Actuel    : (absent) -> sera ajouté"
  fi
  say "  Proposé   : $proposed_line"
  hr
  ask_yn "Appliquer ce changement ?" "N"
}

apply_sshd_change() {
  local key="$1" value="$2" cfg="$3"
  if grep -Eq "^[[:space:]]*$key[[:space:]]+" "$cfg"; then
    sed -i -E "s|^[[:space:]]*$key[[:space:]]+.*|$key $value|g" "$cfg" 2>/dev/null || true
  else
    printf "\n%s %s\n" "$key" "$value" >> "$cfg"
  fi
}

sshd_restart_safe() {
  local svc="$1"
  say "Validation sshd_config (sshd -t)…"
  if have_cmd sshd && ! sshd -t 2>/dev/null; then
    say "ERREUR: sshd -t a échoué. Redémarrage annulé."
    return 1
  fi
  say "Redémarrage service: $svc"
  systemctl restart "$svc" 2>/dev/null || true
  systemctl --no-pager --full status "$svc" 2>/dev/null || true
  return 0
}

# -------------------------------
# Checks (audit)
# -------------------------------
check_01_ssh_status_and_recent_logs() {
  local svc="$1"
  run_show "SSH: statut service ($svc)" systemctl --no-pager --full status "$svc"
  run_show "SSH: journald (50 dernières lignes)" journalctl -u "$svc" -n 50 --no-pager
}

check_02_logs_files_and_lastb() {
  run_show "Logs: auth.log/secure + btmp/wtmp" bash -lc '
    ls -lh /var/log/auth.log* 2>/dev/null || true
    ls -lh /var/log/secure* 2>/dev/null || true
    ls -lh /var/log/btmp /var/log/wtmp 2>/dev/null || true
  '
  run_show "lastb (échecs) - top 20" bash -lc 'lastb 2>/dev/null | head -n 20 || true'
}

check_03_journald_persistence_offer_fix() {
  run_show "journald: /var/log/journal" bash -lc 'ls -ld /var/log/journal 2>/dev/null || echo "Absent: journald probablement non persistant (perte au reboot)"'
  if [[ -d /var/log/journal ]]; then
    say "journald persistant: OK"
    return
  fi
  say "journald persistant: NON (logs perdus après reboot)."
  if ask_yn "Activer persistance journald (mkdir /var/log/journal + restart journald) ?" "Y"; then
    mkdir -p /var/log/journal
    systemctl restart systemd-journald 2>/dev/null || true
    run_show "Re-check /var/log/journal" ls -ld /var/log/journal
  fi
}

check_04_rsyslog_offer_install_enable() {
  if have_cmd systemctl && systemctl list-unit-files 2>/dev/null | grep -q '^rsyslog\.service'; then
    run_show "rsyslog: statut" systemctl --no-pager --full status rsyslog
    if ask_yn "S’assurer que rsyslog est enabled+running ?" "N"; then
      run_show "Enable+start rsyslog" systemctl enable --now rsyslog
    fi
  else
    say "rsyslog: non installé (ou service non détecté)."
    ensure_pkg_installed_interactive "rsyslog" "rsyslog" || true
  fi
}

check_05_effective_sshd_settings_and_recos() {
  run_show "sshd -T (paramètres clés)" bash -lc '
    if command -v sshd >/dev/null 2>&1; then
      sshd -T 2>/dev/null | egrep -i "^(port|listenaddress|permitrootlogin|passwordauthentication|pubkeyauthentication|kbdinteractiveauthentication|authenticationmethods|maxauthtries|maxstartups|loglevel|allowusers|allowgroups|denyusers|denygroups|x11forwarding|permitemptyPasswords|usepam|logingracetime)" || true
    else
      echo "sshd non trouvé."
    fi
  '

  local prl pa kia x11 mat mss ll lgt
  prl="$(sshd_effective_value permitrootlogin)"
  pa="$(sshd_effective_value passwordauthentication)"
  kia="$(sshd_effective_value kbdinteractiveauthentication)"
  x11="$(sshd_effective_value x11forwarding)"
  mat="$(sshd_effective_value maxauthtries)"
  mss="$(sshd_effective_value maxstartups)"
  ll="$(sshd_effective_value loglevel)"
  lgt="$(sshd_effective_value logingracetime)"

  hr
  say "Préconisations (basées sur sshd -T) :"
  [[ -n "$prl" ]] && say "- PermitRootLogin: $prl -> recommandé: no (sauf besoin spécifique)"
  [[ -n "$pa"  ]] && say "- PasswordAuthentication: $pa -> recommandé: no (auth par clé) si possible"
  [[ -n "$kia" ]] && say "- KbdInteractiveAuthentication: $kia -> recommandé: no si password désactivé"
  [[ -n "$x11" ]] && say "- X11Forwarding: $x11 -> recommandé: no (sauf besoin)"
  [[ -n "$mat" ]] && say "- MaxAuthTries: $mat -> recommandé: 3"
  [[ -n "$mss" ]] && say "- MaxStartups: $mss -> recommandé: 10:30:60 (limite preauth)"
  [[ -n "$ll"  ]] && say "- LogLevel: $ll -> recommandé: INFO"
  [[ -n "$lgt" ]] && say "- LoginGraceTime: $lgt -> recommandé: 20"
  hr
}

check_06_hardening_interactif_show_diff() {
  local svc="$1"
  local cfg; cfg="$(sshd_config_path)"
  if [[ -z "$cfg" ]]; then
    say "sshd_config introuvable, hardening ignoré."
    return
  fi

  run_show "sshd_config (lignes clés actuelles)" bash -lc "
    egrep -i '^(Port|PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|KbdInteractiveAuthentication|AuthenticationMethods|MaxAuthTries|MaxStartups|LoginGraceTime|AllowUsers|AllowGroups|DenyUsers|DenyGroups|X11Forwarding|PermitEmptyPasswords|UsePAM|LogLevel)\\b' \"$cfg\" 2>/dev/null || true
  "

  say "Sauvegarde avant modifs -> $BACKUP_DIR"
  backup_file "$cfg"

  local applied_any=0

  # Aide sécurité: si tu n'as pas de clé, désactiver password peut te bloquer.
  # On garde la question "PasswordAuthentication no" sur défaut N.
  if show_change_and_confirm "PermitRootLogin" "no" "$cfg"; then
    apply_sshd_change "PermitRootLogin" "no" "$cfg"
    applied_any=1
  fi

  if show_change_and_confirm "PasswordAuthentication" "no" "$cfg"; then
    say "ATTENTION: si tu n'as pas une clé SSH fonctionnelle, tu peux te verrouiller."
    if ask_yn "Confirmer vraiment PasswordAuthentication no ?" "N"; then
      apply_sshd_change "PasswordAuthentication" "no" "$cfg"
      applied_any=1

      # Souvent recommandé aussi si password off:
      if show_change_and_confirm "KbdInteractiveAuthentication" "no" "$cfg"; then
        apply_sshd_change "KbdInteractiveAuthentication" "no" "$cfg"
        applied_any=1
      fi
    fi
  fi

  if show_change_and_confirm "MaxAuthTries" "3" "$cfg"; then
    apply_sshd_change "MaxAuthTries" "3" "$cfg"
    applied_any=1
  fi

  if show_change_and_confirm "LoginGraceTime" "20" "$cfg"; then
    apply_sshd_change "LoginGraceTime" "20" "$cfg"
    applied_any=1
  fi

  if show_change_and_confirm "MaxStartups" "10:30:60" "$cfg"; then
    apply_sshd_change "MaxStartups" "10:30:60" "$cfg"
    applied_any=1
  fi

  if show_change_and_confirm "X11Forwarding" "no" "$cfg"; then
    apply_sshd_change "X11Forwarding" "no" "$cfg"
    applied_any=1
  fi

  if show_change_and_confirm "LogLevel" "INFO" "$cfg"; then
    apply_sshd_change "LogLevel" "INFO" "$cfg"
    applied_any=1
  fi

  run_show "sshd_config (après changements)" bash -lc "
    egrep -i '^(Port|PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|KbdInteractiveAuthentication|AuthenticationMethods|MaxAuthTries|MaxStartups|LoginGraceTime|AllowUsers|AllowGroups|DenyUsers|DenyGroups|X11Forwarding|PermitEmptyPasswords|UsePAM|LogLevel)\\b' \"$cfg\" 2>/dev/null || true
  "

  if [[ "$applied_any" -eq 1 ]]; then
    if ask_yn "Valider (sshd -t) et redémarrer SSH ($svc) ?" "N"; then
      sshd_restart_safe "$svc" || true
    else
      say "SSH non redémarré. Les changements s’appliqueront au prochain restart."
    fi
  else
    say "Aucune modification appliquée."
  fi
}

check_07_fail2ban_offer_install_config() {
  if have_cmd systemctl && systemctl list-unit-files 2>/dev/null | grep -q '^fail2ban\.service'; then
    run_show "fail2ban: statut" systemctl --no-pager --full status fail2ban
  else
    say "fail2ban: non installé (ou service non détecté)."
    ensure_pkg_installed_interactive "fail2ban" "fail2ban" || true
  fi

  if have_cmd fail2ban-client; then
    run_show "fail2ban: jails" fail2ban-client status
    run_show "fail2ban: sshd jail (si présent)" bash -lc 'fail2ban-client status sshd 2>/dev/null || true'

    if ask_yn "Créer/mettre à jour /etc/fail2ban/jail.local (sshd mode=aggressive) ?" "N"; then
      local jail="/etc/fail2ban/jail.local"
      backup_file "$jail"
      cat > "$jail" <<'EOF'
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 5

[sshd]
enabled = true
mode = aggressive
EOF
      run_show "Restart fail2ban" systemctl restart fail2ban
      run_show "fail2ban: sshd jail" bash -lc 'fail2ban-client status sshd 2>/dev/null || true'
    fi
  fi
}

check_08_ports_and_firewall() {
  run_show "Ports en écoute (ss/netstat)" bash -lc '
    if command -v ss >/dev/null 2>&1; then
      ss -lntup || true
    elif command -v netstat >/dev/null 2>&1; then
      netstat -lntup || true
    else
      echo "Ni ss ni netstat disponibles."
    fi
  '

  run_show "Firewall (ufw/nft/iptables)" bash -lc '
    if command -v ufw >/dev/null 2>&1; then
      ufw status verbose || true
    elif command -v nft >/dev/null 2>&1; then
      nft list ruleset || true
    elif command -v iptables >/dev/null 2>&1; then
      iptables -S || true
      iptables -L -n -v || true
    else
      echo "Aucun ufw/nft/iptables détecté."
    fi
  '
}

check_09_bruteforce_summary() {
  local svc; svc="$(detect_ssh_service_name)"

  hr
  say "Résumé brute-force (best effort)"
  hr

  if [[ -f /var/log/auth.log ]]; then
    say "Top IP (Failed/Invalid) via /var/log/auth.log:"
    grep -E "sshd.*(Failed password|Invalid user)" /var/log/auth.log 2>/dev/null \
      | awk '{print $(NF-3)}' | sort | uniq -c | sort -nr | head -n 15 || true
    echo
    say "Top users ciblés via /var/log/auth.log:"
    grep -E "sshd.*Failed password" /var/log/auth.log 2>/dev/null \
      | awk '{print $(NF-5)}' | sort | uniq -c | sort -nr | head -n 15 || true
  else
    say "Pas de /var/log/auth.log -> journald sur 7 jours:"
    journalctl -u "$svc" --since "7 days ago" --no-pager 2>/dev/null \
      | grep -E "Failed password|Invalid user" \
      | awk '{print $(NF-3)}' | sort | uniq -c | sort -nr | head -n 15 || true
  fi

  echo
  say "Connexions SSH réussies récentes:"
  if [[ -f /var/log/auth.log ]]; then
    grep -E "sshd.*Accepted" /var/log/auth.log 2>/dev/null | tail -n 10 || true
  else
    journalctl -u "$svc" -n 300 --no-pager 2>/dev/null | grep -E "Accepted" | tail -n 10 || true
  fi
}

check_10_logrotate_hints() {
  run_show "logrotate: présence configs (auth/secure)" bash -lc '
    ls -lh /etc/logrotate.d/* 2>/dev/null | head -n 60 || true
    echo
    grep -R "auth.log\|/var/log/secure" -n /etc/logrotate.d 2>/dev/null | head -n 80 || true
  '
}

check_11_updates_quick_view() {
  local pm; pm="$(pkg_mgr_detect)"
  case "$pm" in
    apt)
      run_show "Apt: upgrades disponibles (simulation)" bash -lc 'apt-get update -y >/dev/null 2>&1 || true; apt-get -s upgrade 2>/dev/null | egrep "^(Inst|Conf)" | head -n 80 || true'
      if ask_yn "Appliquer les upgrades maintenant (apt-get upgrade) ?" "N"; then
        run_show "apt-get update" apt-get update -y
        run_show "apt-get upgrade" apt-get upgrade -y
      fi
      ;;
    dnf)
      run_show "dnf: check-update" dnf -q check-update || true
      if ask_yn "Appliquer les upgrades maintenant (dnf upgrade) ?" "N"; then
        run_show "dnf upgrade" dnf -y upgrade
      fi
      ;;
    yum)
      run_show "yum: check-update" yum -q check-update || true
      if ask_yn "Appliquer les upgrades maintenant (yum update) ?" "N"; then
        run_show "yum update" yum -y update
      fi
      ;;
    apk)
      run_show "apk: update" apk update
      run_show "apk: upgrade (info)" apk upgrade --available || true
      if ask_yn "Appliquer les upgrades maintenant (apk upgrade) ?" "N"; then
        run_show "apk upgrade" apk upgrade
      fi
      ;;
    pacman)
      run_show "pacman: upgrades (pacman -Qu)" bash -lc 'pacman -Sy --noconfirm >/dev/null 2>&1 || true; pacman -Qu || true'
      if ask_yn "Appliquer les upgrades maintenant (pacman -Syu) ?" "N"; then
        run_show "pacman -Syu" pacman -Syu --noconfirm
      fi
      ;;
    *)
      say "Gestionnaire non supporté: skip updates."
      ;;
  esac
}

# -------------------------------
# Main
# -------------------------------
main() {
  need_root

  local svc; svc="$(detect_ssh_service_name)"
  say "Audit interactif SSH / VPS"
  say "Service SSH détecté : $svc"
  say "Backups (si modifications) : $BACKUP_DIR"
  say

  if ask_yn "Check 1: Statut SSH + logs récents ?" "Y"; then check_01_ssh_status_and_recent_logs "$svc"; fi
  if ask_yn "Check 2: Fichiers logs (auth/secure) + lastb ?" "Y"; then check_02_logs_files_and_lastb; fi
  if ask_yn "Check 3: Persistance journald (+ correctif) ?" "Y"; then check_03_journald_persistence_offer_fix; fi
  if ask_yn "Check 4: rsyslog (+ installation/enable si besoin) ?" "Y"; then check_04_rsyslog_offer_install_enable; fi

  # Préconisations d'abord (lecture seule)
  if ask_yn "Check 5: sshd -T + préconisations ?" "Y"; then check_05_effective_sshd_settings_and_recos; fi

  # Puis hardening (modifications)
  if ask_yn "Check 6: Hardening SSH (montre chaque changement AVANT validation) ?" "N"; then
    check_06_hardening_interactif_show_diff "$svc"
  fi

  if ask_yn "Check 7: fail2ban (+ installation/config si besoin) ?" "Y"; then check_07_fail2ban_offer_install_config; fi
  if ask_yn "Check 8: Ports en écoute + firewall ?" "Y"; then check_08_ports_and_firewall; fi
  if ask_yn "Check 9: Résumé brute-force (IPs/users + succès) ?" "Y"; then check_09_bruteforce_summary; fi

  # Extras optionnels
  if ask_yn "Check 10: logrotate (rotation des logs) ?" "N"; then check_10_logrotate_hints; fi
  if ask_yn "Check 11: mises à jour système (+ upgrade optionnel) ?" "N"; then check_11_updates_quick_view; fi

  say
  hr
  say "Terminé."
  if [[ -d "$BACKUP_DIR" ]]; then
    say "Backups : $BACKUP_DIR"
  else
    say "Aucune modification appliquée."
  fi
  hr
}

main "$@"
