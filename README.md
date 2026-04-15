# 🛡️ linux-audit-json

<p align="center">
  <img src="docs/logo.png" alt="linux-audit-json logo" width="420"/>
</p>

<p align="center">
  <strong>Coleta • Correlaciona • Filtra • Entrega</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.11+-blue.svg">
  <img src="https://img.shields.io/badge/platform-linux-important">
  <img src="https://img.shields.io/badge/status-active-success">
  <img src="https://img.shields.io/badge/license-MIT-green">
</p>

---

Coletor de eventos do **Linux Audit (auditd)** que transforma logs brutos em **JSON estruturado**, com suporte a **correlação, filtragem e envio para múltiplos destinos**.

Projetado para integração com **SIEMs**, pipelines de segurança e análises forenses.

---

## ✨ O que ele resolve

O `auditd` puro é difícil de trabalhar:

* Eventos fragmentados
* Muito ruído
* Difícil integração com SIEM
* Pouco estruturado

O `linux-audit-json` resolve isso.

---

## ⚙️ Como funciona

```text
auditd → audispd → plugin → parser → correlator → filters → router → outputs
```

---

## 🚀 Instalação

```bash
sudo bash install.sh
```

---

## 🧠 Pipeline interno

| Etapa      | Função                    |
| ---------- | ------------------------- |
| Parser     | Converte linhas brutas    |
| Correlator | Junta múltiplos registros |
| Filters    | Decide o que fica         |
| Router     | Define destino            |
| Outputs    | Envia dados               |

---

## 📤 Saídas suportadas

| Tipo   | Descrição                 |
| ------ | ------------------------- |
| file   | NDJSON local              |
| tcp    | Confiável + retry + spool |
| udp    | Alta performance          |
| stdout | Debug                     |

---

## 🔐 Segurança

* Execução com usuário dedicado
* Restrição de caminhos
* Proteção contra symlink
* Permissões seguras
* Hash de configuração (`config_hash`)

---

## 📊 Exemplo de saída

```json
{
  "event_id": "37837",
  "timestamp": 1776258346.065,
  "host": "rocky9.linuxvmimages.local",
  "record_types": [
    "SYSCALL",
    "EXECVE",
    "CWD",
    "PATH",
    "PROCTITLE"
  ],
  "summary": {
    "syscall": "59",
    "success": "yes",
    "pid": "67832",
    "uid": "1000",
    "auid": "1000",
    "comm": "whoami",
    "exe": "/usr/bin/whoami",
    "key": "recon",
    "cmdline": "whoami",
    "cwd": "/home/rockylinux/pasta-de-origem",
    "filepath": "/usr/bin/whoami",
    "proctitle": "whoami"
  },
  "tags": [],
  "route_name": "critical-to-siem",
  "filter_name": "",
  "collector_version": "1.1.0",
  "config_hash": "6a563a5193e885edee2fa161defa0177830e64af9a45520f24796e75b9e91a15",
  "agent_id": "rocky9.linuxvmimages.local@1.1.0"
}
```

---

## 🧹 Desinstalação

```bash
sudo bash uninstall.sh
```

---

# 📜 Licença

**MIT**

---

# 🤝 Contribuição

Pull requests são bem-vindos.

Se quiser melhorar performance, parsing ou integração com SIEM — manda.