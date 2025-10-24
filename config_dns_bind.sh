#!/bin/bash
# =========================================================================================#
#
# Projeto: Instalação e Configuração de Servidor DNS (BIND) - Classe C
# Autor: Sérgio Correia
# Data: 24 10 2025
#
# Descrição:
# Script para automatizar a instalação e configuração do servidor DNS BIND em CentOS Stream 10.
# Suporta apenas redes de Classe C (/24).
#
# =========================================================================================#

set -e

# Definir permissões do script
# O que faz o chmod 775: Define permissões de leitura, escrita e execução para o proprietário e grupo, e leitura e execução para outros.

chmod 775 config_dns_bind

echo ""
echo "=========================================="
echo "   INSTALAÇÃO: DNS (BIND)"
echo "=========================================="
echo ""

# 1 - Instalação do BIND
# O que faz: Instala o servidor DNS BIND e suas ferramentas (bind-utils) usando o gestor de pacotes DNF.
# O que faz o -y: Responde "sim" automaticamente a todas as perguntas durante a instalação.
# O que faz o bind: Pacote principal do servidor DNS BIND.
# O que faz o bind-utils: Ferramentas úteis como dig, nslookup, host para testar DNS.

echo "A instalar BIND..."
sudo dnf install -y bind bind-utils

# 2 - Solicitar informações do domínio
# O que faz: Pede ao utilizador o nome do domínio e o IP do servidor DNS.
# O que faz o read -p: Exibe uma mensagem e aguarda entrada do utilizador.

echo ""
read -p "Introduza o domínio (ex: empresa.local): " DOMINIO
read -p "Introduza o IP do servidor de Classe C (ex: 192.168.1.5): " IP_SERVIDOR_DNS

# 3 - Extrair octetos do IP para criar zona reversa
# O que faz: Divide o IP em 4 partes (octetos) para formar o nome da zona reversa.
# O que faz o cut -d. -fN: Extrai o N-ésimo octeto do IP usando o ponto como delimitador.
# O que faz o REVERSE_ZONE_ID: Cria o identificador da zona reversa no formato padrão DNS (in-addr.arpa).
# O que faz o date +%s: Gera um número de série baseado em segundos desde 1970 (Unix timestamp).

OCTETO_1=$(echo "$IP_SERVIDOR_DNS" | cut -d'.' -f1)
OCTETO_2=$(echo "$IP_SERVIDOR_DNS" | cut -d'.' -f2)
OCTETO_3=$(echo "$IP_SERVIDOR_DNS" | cut -d'.' -f3)
OCTETO_4=$(echo "$IP_SERVIDOR_DNS" | cut -d'.' -f4)
REVERSE_ZONE_ID="${OCTETO_3}.${OCTETO_2}.${OCTETO_1}.in-addr.arpa"

# Gerar número de série para o SOA
# O que faz: Gera um número de série único baseado na data atual para o SO

# Como funciona o Serial DATE: Utiliza o timestamp atual em segundos como número de série.

# O que faz o date +%s: Gera um número de série baseado em segundos desde 1970 (Unix timestamp).
# O que faz o +%s: Formata a data como segundos desde 1970.

SERIAL_DATE=$(date +%s)

echo ""
echo "Domínio: $DOMINIO"
echo "IP Servidor DNS: $IP_SERVIDOR_DNS"
echo "Zona Reversa: $REVERSE_ZONE_ID"
echo ""

# 4 - Criar ficheiro de zona direta (Forward Zone)
# O que faz: Cria o ficheiro de zona DNS que resolve nomes para IPs (ex: empresa.local ->

# O que faz o SOA: Start of Authority - define o servidor autoritativo para a zona.
# O que faz o NS: Name Server - define o servidor de nomes para a zona.

echo "A criar zona direta (Forward Zone)..."
sudo tee /var/named/${DOMINIO}.db >/dev/null << EOF
\$TTL 86400
@   IN  SOA     ${DOMINIO}. root.${DOMINIO}. (
        ${SERIAL_DATE}  ; Serial
        3600            ; Refresh
        1800            ; Retry
        604800          ; Expire
        86400 )         ; Minimum TTL
    IN  NS      ns.${DOMINIO}.
ns  IN  A       ${IP_SERVIDOR_DNS}
@   IN  A       ${IP_SERVIDOR_DNS}
EOF

# 5 - Criar ficheiro de zona inversa (Reverse Zone)
# O que faz: Cria o ficheiro de zona DNS que resolve IPs para nomes (ex: 192.168.1.10 -> empresa.local).

# O que faz o PTR: Pointer - aponta um IP para um nome de domínio (resolução inversa).

echo "A criar zona inversa (Reverse Zone)..."
sudo tee /var/named/${OCTETO_3}.${OCTETO_2}.${OCTETO_1}.db >/dev/null << EOF
\$TTL 86400
@   IN  SOA     ${DOMINIO}. root.${DOMINIO}. (
        ${SERIAL_DATE}  ; Serial
        3600            ; Refresh
        1800            ; Retry
        604800          ; Expire
        86400 )         ; Minimum TTL
    IN  NS      ns.${DOMINIO}.
${OCTETO_4} IN  PTR   ns.${DOMINIO}.
EOF

# 6 - Configurar named.conf
# O que faz: Adiciona as zonas criadas ao ficheiro de configuração principal do BIND.

# O que faz o sudo tee -a: Anexa conteúdo ao ficheiro (não sobrescreve) com privilégios de superusuário.
# O que faz o type master: Indica que este servidor é autoritativo para esta zona.
# O que faz o file: Caminho para o ficheiro de zona.
# O que faz o allow-update { none; }: Não permite atualizações dinâmicas (mais seguro).

echo "A configurar named.conf..."
sudo tee -a /etc/named.conf >/dev/null << EOF

zone "${DOMINIO}" IN {
    type master;
    file "${DOMINIO}.db";
    allow-update { none; };
};

zone "${REVERSE_ZONE_ID}" IN {
    type master;
    file "${OCTETO_3}.${OCTETO_2}.${OCTETO_1}.db";
    allow-update { none; };
};
EOF

# Criar diretório para logs do BIND
# O que faz: Cria o diretório /var/log/named para armazenar logs do BIND.

# O que faz o mkdir -p: Cria o diretório, incluindo pais se não
# existirem.
# O que faz o chown: Change owner - muda o proprietário e grupo do diretório
# O que faz o chmod 755: Define permissões de leitura, escrita e execução para o proprietário, e leitura e execução para grupo e outros.

sudo mkdir -p /var/log/named
sudo chown named:named /var/log/named
sudo chmod 755 /var/log/named

# 7 - Definir permissões dos ficheiros de zona
# O que faz: Altera o proprietário dos ficheiros de zona para o utilizador "named" (user do BIND).
# O que faz o chown: Change owner - muda o proprietário e grupo de um ficheiro.
# O que faz o named:named: Define utilizador "named" e grupo "named" como proprietários.

echo "A definir permissões dos ficheiros de zona..."
sudo chown named:named /var/named/${DOMINIO}.db
sudo chown named:named /var/named/${OCTETO_3}.${OCTETO_2}.${OCTETO_1}.db

# 8 - Validar configurações do BIND
# O que faz: Verifica se o ficheiro named.conf tem erros de sintaxe.
# O que faz o named-checkconf: Ferramenta do BIND que valida a configuração principal.
# O que faz o named-checkzone: Ferramenta do BIND que valida ficheiros de zona.
# O que faz o if ... then ... else: Estrutura condicional que executa código baseado no sucesso/falha do comando.

echo "A validar configurações..."
if sudo named-checkconf; then
    echo "named.conf está OK!"
else
    echo "ERRO no named.conf! Verifique a configuração."
    exit 1
fi

# 9 - Validar zona direta
# O que faz: Verifica se o ficheiro de zona direta tem erros de sintaxe.

# O que faz o if ... then ... else: Estrutura condicional que executa código baseado no sucesso/falha do comando.
# O que faz o sudo named-checkzone: Ferramenta do BIND que valida ficheiros de zona.

if sudo named-checkzone ${DOMINIO} /var/named/${DOMINIO}.db; then
    echo "Zona direta está OK!"
else
    echo "ERRO na zona direta! Verifique o ficheiro."
    exit 1
fi

# 10 - Validar zona inversa
# O que faz: Verifica se o ficheiro de zona inversa tem erros de sintaxe.

if sudo named-checkzone ${REVERSE_ZONE_ID} /var/named/${OCTETO_3}.${OCTETO_2}.${OCTETO_1}.db; then
    echo "Zona inversa está OK!"
else
    echo "ERRO na zona inversa! Verifique o ficheiro."
    exit 1
fi

# 11 - Configurar firewall
# O que faz: Adiciona permanentemente o serviço DNS às regras do firewall.

# O que faz o firewall-cmd --permanent: Torna a regra permanente (persiste após reboot).
# O que faz o --add-service=dns: Permite tráfego na porta 53 (TCP e UDP).
# O que faz o --reload: Recarrega as regras do firewall para aplicar as mudanças.

echo "A configurar firewall..."
sudo firewall-cmd --permanent --add-service=dns
sudo firewall-cmd --reload

# 12 - Iniciar e habilitar serviço BIND
# O que faz: Inicia o serviço named (BIND) e configura para iniciar automaticamente no boot.
# O que faz o systemctl enable --now: Habilita o serviço e inicia-o imediatamente.
# O que faz o systemctl status: Mostra o estado atual do serviço.

echo "A iniciar serviço BIND..."
sudo systemctl enable --now named
sudo systemctl status named

echo ""
echo "DNS configurado com sucesso!"
echo ""

# 13 - Menu de verificações para DNS
# O que faz: Apresenta um menu simples ao utilizador com opções para verificar o DNS.

# O que faz o case: Estrutura de controlo que compara uma variável com vários padrões.
# O que faz o dig: Ferramenta de query DNS que testa resolução de nomes.
# O que faz o -x: Realiza uma query de resolução inversa (IP para nome).
# O que faz o systemctl status: Mostra o estado atual do serviço.
# O que faz o @: Especifica que a query deve ser feita ao servidor DNS local, ou localhost.

echo "Deseja executar verificações? (opcional)"
echo "1) Testar resolução direta (nome -> IP);"
echo "2) Testar resolução inversa (IP -> nome);"
echo "3) Ver status do serviço;"
echo "4) Sair."
echo ""
read -p "Escolha uma opção (1-4): " OPCAO_VERIFICACAO_DNS

case $OPCAO_VERIFICACAO_DNS in
    1)
        echo ""
        echo "--- Teste de Resolução Direta ---"
        dig ${DOMINIO}
        ;;
    2)
        echo ""
        echo "--- Teste de Resolução Inversa ---"
        dig -x ${IP_SERVIDOR_DNS}
        ;;
    3)
        echo ""
        echo "--- Status do Serviço BIND ---"
        sudo systemctl status named
        ;;
    4)
        echo ""
        echo "A sair sem verificações."
        ;;
    *)
        echo ""
        echo "Opção inválida. A sair sem verificações."
        ;;

# O que faz o esac: Finaliza a estrutura case.

esac

echo ""
echo "Comandos úteis para o futuro:"
echo "- Testar DNS: dig ${DOMINIO}"
echo "- Ver logs: tail -f /var/log/messages"
echo "- Status: systemctl status named"
echo ""

echo "Fim do script."