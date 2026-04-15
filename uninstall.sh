#!/usr/bin/env bash
# =============================================================================
# uninstall.sh — Remove completamente o linux-audit-json do sistema
#
# Uso: sudo bash uninstall.sh
#
# O que remove:
#   - Plugin do audispd (/etc/audit/plugins.d/linux-audit-json.conf)
#   - Arquivos do agente (/opt/linux-audit-json)
#   - Configuração (/etc/linux-audit-json)          ← pergunta antes
#   - Logs (/var/log/linux-audit-json)              ← pergunta antes
#   - Serviço systemd
#   - Wrappers CLI
#   - Usuário e grupo audit-agent                  ← pergunta antes
#   - Linhas adicionadas ao auditd.conf (q_depth, disp_qos)
# =============================================================================

set -euo pipefail

RED='\033[0;31m'
YLW='\033[1;33m'
GRN='\033[0;32m'
NC='\033[0m'

if [[ $EUID -ne 0 ]]; then
    echo "ERRO: execute como root (sudo bash uninstall.sh)" >&2
    exit 1
fi

echo -e "${YLW}=== Desinstalação do linux-audit-json ===${NC}"
echo ""

# ---------------------------------------------------------------------------
# Confirmações
# ---------------------------------------------------------------------------
read -rp "Remover configuração em /etc/linux-audit-json? [s/N] " REMOVE_CONF
read -rp "Remover logs em /var/log/linux-audit-json? [s/N] " REMOVE_LOGS
read -rp "Remover usuário e grupo 'audit-agent'? [s/N] " REMOVE_USER

echo ""

# ---------------------------------------------------------------------------
# 1. Para e desabilita o plugin (reinicia auditd sem ele)
# ---------------------------------------------------------------------------
echo "==> 1. Desativando plugin do audispd..."
if [[ -f /etc/audit/plugins.d/linux-audit-json.conf ]]; then
    # Desativa antes de remover para o auditd encerrar o plugin limpo
    sed -i 's/^active\s*=.*/active = no/' /etc/audit/plugins.d/linux-audit-json.conf
    systemctl restart auditd 2>/dev/null || true
    sleep 1
    rm -f /etc/audit/plugins.d/linux-audit-json.conf
    echo "     Plugin removido de /etc/audit/plugins.d/"
else
    echo "     Plugin não encontrado — ignorando."
fi

# ---------------------------------------------------------------------------
# 2. Remove serviço systemd
# ---------------------------------------------------------------------------
echo "==> 2. Removendo serviço systemd..."
systemctl stop    linux-audit-json.service 2>/dev/null || true
systemctl disable linux-audit-json.service 2>/dev/null || true
if [[ -f /etc/systemd/system/linux-audit-json.service ]]; then
    rm -f /etc/systemd/system/linux-audit-json.service
    systemctl daemon-reload
    echo "     Serviço removido."
else
    echo "     Serviço não encontrado — ignorando."
fi

# ---------------------------------------------------------------------------
# 3. Remove wrappers CLI
# ---------------------------------------------------------------------------
echo "==> 3. Removendo wrappers CLI..."
rm -f /usr/local/bin/linux-audit-json
rm -f /usr/local/bin/linux-audit-json-plugin
echo "     Wrappers removidos."

# ---------------------------------------------------------------------------
# 4. Remove arquivos do agente
# ---------------------------------------------------------------------------
echo "==> 4. Removendo arquivos do agente em /opt/linux-audit-json..."
if [[ -d /opt/linux-audit-json ]]; then
    rm -rf /opt/linux-audit-json
    echo "     Removido."
else
    echo "     Não encontrado — ignorando."
fi

# ---------------------------------------------------------------------------
# 5. Configuração
# ---------------------------------------------------------------------------
echo "==> 5. Configuração..."
if [[ "${REMOVE_CONF,,}" == "s" ]]; then
    rm -rf /etc/linux-audit-json
    echo "     /etc/linux-audit-json removido."
else
    echo "     Mantido em /etc/linux-audit-json (remova manualmente se quiser)."
fi

# ---------------------------------------------------------------------------
# 6. Logs
# ---------------------------------------------------------------------------
echo "==> 6. Logs..."
if [[ "${REMOVE_LOGS,,}" == "s" ]]; then
    rm -rf /var/log/linux-audit-json
    echo "     /var/log/linux-audit-json removido."
else
    echo "     Mantido em /var/log/linux-audit-json (remova manualmente se quiser)."
fi

# ---------------------------------------------------------------------------
# 7. Usuário e grupo
# ---------------------------------------------------------------------------
echo "==> 7. Usuário e grupo..."
if [[ "${REMOVE_USER,,}" == "s" ]]; then
    if id audit-agent &>/dev/null; then
        userdel audit-agent
        echo "     Usuário 'audit-agent' removido."
    fi
    if getent group audit-agent &>/dev/null; then
        groupdel audit-agent 2>/dev/null || true
        echo "     Grupo 'audit-agent' removido."
    fi
else
    echo "     Mantidos (remova manualmente com: userdel audit-agent && groupdel audit-agent)."
fi

# ---------------------------------------------------------------------------
# 8. Reverte auditd.conf (remove linhas adicionadas pelo install.sh)
# ---------------------------------------------------------------------------
echo "==> 8. Revertendo auditd.conf..."
AUDITD_CONF="/etc/audit/auditd.conf"
if [[ -f "$AUDITD_CONF" ]]; then
    # Remove linhas adicionadas pelo instalador
    sed -i '/^# linux-audit-json:/d' "$AUDITD_CONF"
    sed -i '/^q_depth = 10500/d' "$AUDITD_CONF"
    sed -i '/^disp_qos = lossy/d' "$AUDITD_CONF"
    # Remove linhas em branco extras no final
    sed -i -e '/^[[:space:]]*$/{ /./!d }' "$AUDITD_CONF"
    echo "     auditd.conf revertido."
    systemctl restart auditd 2>/dev/null || true
else
    echo "     auditd.conf não encontrado — ignorando."
fi

# ---------------------------------------------------------------------------
# Resultado
# ---------------------------------------------------------------------------
echo ""
echo -e "${GRN}==============================================================================${NC}"
echo -e "${GRN}Desinstalação concluída.${NC}"
echo ""
echo "auditd continua rodando normalmente (sem o plugin)."
echo "Verifique: sudo systemctl status auditd"
echo -e "${GRN}==============================================================================${NC}"
