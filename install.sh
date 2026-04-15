#!/usr/bin/env bash
# =============================================================================
# install.sh — Instala o linux-audit-json
#
# Uso: sudo bash install.sh
#
# O que faz:
#   1. Cria usuário e grupo dedicados (sem shell, sem home)
#   2. Copia os arquivos do agente para /opt/linux-audit-json
#   3. Cria diretórios de conf e log com permissões corretas
#   4. Instala o .conf de exemplo (sem sobrescrever se já existir)
#   5. Instala o .service (desabilitado — não é necessário no modo plugin)
#   6. Cria os wrappers CLI
#   7. Copia o plugin do audispd para /etc/audit/plugins.d/
#   8. Ajusta q_depth no auditd.conf para evitar drop de eventos no boot
#   9. Reinicia o auditd
# =============================================================================

set -euo pipefail

AGENT_USER="audit-agent"
AGENT_GROUP="audit-agent"
INSTALL_DIR="/opt/linux-audit-json"
CONF_DIR="/etc/linux-audit-json"
LOG_DIR="/var/log/linux-audit-json"
SERVICE_FILE="/etc/systemd/system/linux-audit-json.service"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---------------------------------------------------------------------------
# Verificações
# ---------------------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
    echo "ERRO: execute como root (sudo bash install.sh)" >&2
    exit 1
fi

if ! command -v python3.11 &>/dev/null; then
    echo "ERRO: python3.11 não encontrado." >&2
    exit 1
fi

PYTHON_VERSION=$(python3.11 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PYTHON_MAJOR=$(echo "$PYTHON_VERSION" | cut -d. -f1)
PYTHON_MINOR=$(echo "$PYTHON_VERSION" | cut -d. -f2)

if [[ $PYTHON_MAJOR -lt 3 ]] || [[ $PYTHON_MAJOR -eq 3 && $PYTHON_MINOR -lt 11 ]]; then
    echo "ERRO: Python 3.11+ necessário (encontrado: $PYTHON_VERSION)" >&2
    exit 1
fi

echo "==> Python $PYTHON_VERSION encontrado."

# ---------------------------------------------------------------------------
# Usuário e grupo
# ---------------------------------------------------------------------------
if ! getent group "$AGENT_GROUP" &>/dev/null; then
    groupadd --system "$AGENT_GROUP"
    echo "==> Grupo '$AGENT_GROUP' criado."
else
    echo "==> Grupo '$AGENT_GROUP' já existe."
fi

if ! id "$AGENT_USER" &>/dev/null; then
    useradd \
        --system \
        --no-create-home \
        --shell /usr/sbin/nologin \
        --gid "$AGENT_GROUP" \
        "$AGENT_USER"
    echo "==> Usuário '$AGENT_USER' criado."
else
    echo "==> Usuário '$AGENT_USER' já existe."
fi

# Configura ACL para leitura de /var/log/audit sem adicionar ao grupo adm
# Requer: apt install acl  /  yum install acl
if command -v setfacl &>/dev/null && [[ -d /var/log/audit ]]; then
    setfacl -R -m u:"$AGENT_USER":r-x /var/log/audit 2>/dev/null || true
    setfacl -d -m u:"$AGENT_USER":r-x /var/log/audit 2>/dev/null || true
    echo "==> ACL configurada para $AGENT_USER em /var/log/audit."
elif [[ -d /var/log/audit ]]; then
    echo "AVISO: setfacl não encontrado. Instale acl para permissão granular."
    echo "       Alternativa: adicione $AGENT_USER ao grupo adm manualmente se necessário."
fi

# ---------------------------------------------------------------------------
# Diretórios
# ---------------------------------------------------------------------------
install -d -m 755 -o root      -g root         "$INSTALL_DIR"
install -d -m 755 -o root      -g "$AGENT_GROUP" "$CONF_DIR"
install -d -m 755 -o "$AGENT_USER" -g "$AGENT_GROUP" "$LOG_DIR"
echo "==> Diretórios criados."

# ---------------------------------------------------------------------------
# Arquivos do agente
# ---------------------------------------------------------------------------
cp -r "$SCRIPT_DIR/agent" "$INSTALL_DIR/"
# Copia também o conf do audispd para que o admin possa localizá-lo
cp -r "$SCRIPT_DIR/conf"  "$INSTALL_DIR/"
chmod -R 644 "$INSTALL_DIR/agent/"*.py
chmod -R 644 "$INSTALL_DIR/agent/outputs/"*.py
chmod 755 "$INSTALL_DIR/agent/main.py"
chmod 755 "$INSTALL_DIR/agent/plugin.py"
echo "==> Arquivos do agente copiados para $INSTALL_DIR."

# ---------------------------------------------------------------------------
# Configuração (não sobrescreve se já existir)
# ---------------------------------------------------------------------------
# Instala agent.conf.example sempre (referência imutável)
install -m 644 -o root -g "$AGENT_GROUP" \
    "$SCRIPT_DIR/conf/agent.conf.example" \
    "$CONF_DIR/agent.conf.example"
echo "==> Referência instalada em $CONF_DIR/agent.conf.example (nunca sobrescrito em updates)."

# Instala agent.conf apenas se não existir
if [[ ! -f "$CONF_DIR/agent.conf" ]]; then
    install -m 644 -o root -g "$AGENT_GROUP" \
        "$SCRIPT_DIR/conf/agent.conf" \
        "$CONF_DIR/agent.conf"
    echo "==> Configuração instalada em $CONF_DIR/agent.conf — revise antes de usar."
else
    echo "==> $CONF_DIR/agent.conf já existe — não sobrescrito."
fi

# ---------------------------------------------------------------------------
# Serviço systemd — instalado mas DESABILITADO
# (necessário apenas no modo source=file, não no modo plugin)
# ---------------------------------------------------------------------------
install -m 644 -o root -g root \
    "$SCRIPT_DIR/systemd/linux-audit-json.service" \
    "$SERVICE_FILE"
systemctl daemon-reload
systemctl disable linux-audit-json.service 2>/dev/null || true
echo "==> Serviço systemd instalado (desabilitado — não necessário no modo plugin)."

# ---------------------------------------------------------------------------
# Wrappers CLI
# ---------------------------------------------------------------------------
cat > /usr/local/bin/linux-audit-json << 'WEOF'
#!/usr/bin/env bash
# CLI principal: validate / test / run (modo file)
exec python3.11 /opt/linux-audit-json/agent/main.py "$@"
WEOF
chmod 755 /usr/local/bin/linux-audit-json

cat > /usr/local/bin/linux-audit-json-plugin << 'WEOF'
#!/usr/bin/env bash
# Processo filho do audispd — lê stdin, NÃO é um serviço systemd
exec python3.11 /opt/linux-audit-json/agent/plugin.py "$@"
WEOF
chmod 755 /usr/local/bin/linux-audit-json-plugin

echo "==> Wrappers criados: linux-audit-json  e  linux-audit-json-plugin"

# ---------------------------------------------------------------------------
# Plugin do audispd
# ---------------------------------------------------------------------------
if [[ -d /etc/audit/plugins.d ]]; then
    install -m 640 -o root -g root \
        "$SCRIPT_DIR/conf/linux-audit-json.conf.audispd" \
        /etc/audit/plugins.d/linux-audit-json.conf
    echo "==> Plugin audispd instalado em /etc/audit/plugins.d/linux-audit-json.conf"
else
    echo "AVISO: /etc/audit/plugins.d não encontrado — instale o plugin manualmente."
fi

# ---------------------------------------------------------------------------
# q_depth no auditd.conf (evita drop de eventos na inicialização)
# ---------------------------------------------------------------------------
AUDITD_CONF="/etc/audit/auditd.conf"
if [[ -f "$AUDITD_CONF" ]]; then
    if grep -qi "^q_depth" "$AUDITD_CONF"; then
        sed -i 's/^q_depth\s*=.*/q_depth = 10500/' "$AUDITD_CONF"
    else
        echo "" >> "$AUDITD_CONF"
        echo "# linux-audit-json: fila para plugins aumentada" >> "$AUDITD_CONF"
        echo "q_depth = 10500" >> "$AUDITD_CONF"
    fi
    # disp_qos foi removido em versões recentes do auditd — removemos se existir
    # para evitar o aviso "disp_qos option is deprecated"
    if grep -qi "^disp_qos" "$AUDITD_CONF"; then
        sed -i '/^disp_qos/d' "$AUDITD_CONF"
        echo "==> disp_qos removido do auditd.conf (opção deprecated nas versões recentes)."
    fi
    echo "==> auditd.conf atualizado (q_depth=10500)."
fi

# ---------------------------------------------------------------------------
# Logrotate
# ---------------------------------------------------------------------------
if [[ -d /etc/logrotate.d ]]; then
    install -m 644 -o root -g root \
        "$SCRIPT_DIR/conf/linux-audit-json.logrotate" \
        /etc/logrotate.d/linux-audit-json
    echo "==> Logrotate configurado em /etc/logrotate.d/linux-audit-json (7 dias)."
fi

# ---------------------------------------------------------------------------
# Reinicia o auditd para ativar o plugin
# ---------------------------------------------------------------------------
if systemctl is-active --quiet auditd; then
    if command -v service &>/dev/null; then
        service auditd restart
    else
        systemctl restart auditd
    fi
    sleep 1
    echo "==> auditd reiniciado."
    if systemctl status auditd --no-pager 2>/dev/null | grep -q "plugin.py"; then
        echo "==> Plugin python3.11 plugin.py detectado como processo filho do auditd. OK."
    else
        echo "AVISO: plugin.py não detectado ainda — verifique: systemctl status auditd"
    fi
else
    echo "AVISO: auditd não está rodando. Inicie manualmente: systemctl start auditd"
fi

# ---------------------------------------------------------------------------
# Instruções finais
# ---------------------------------------------------------------------------
cat << 'FINALEOF'

=============================================================================
Instalação concluída.

MODO DE OPERAÇÃO: plugin do audispd
  O agente roda como processo filho do auditd — NÃO como serviço systemd.
  O auditd gerencia o ciclo de vida do plugin automaticamente.

GERENCIAMENTO:
  Parar coleta:       sudo systemctl stop auditd
  Reiniciar plugin:   sudo systemctl restart auditd
  Ver status:         sudo systemctl status auditd
  Ver eventos:        sudo tail -f /var/log/linux-audit-json/events.ndjson
  Ver log do agente:  sudo tail -f /var/log/linux-audit-json/agent.log

CONFIGURAÇÃO:
  Edite /etc/linux-audit-json/agent.conf e reinicie o auditd.

VALIDAR CONFIGURAÇÃO:
  sudo linux-audit-json validate

DESINSTALAR:
  sudo bash uninstall.sh
=============================================================================
FINALEOF
