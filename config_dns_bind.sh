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

dos2unix *.sh

set -e

echo ""
echo "=========================================="
echo "   DNS (BIND) - MENU PRINCIPAL"
echo "=========================================="
echo ""
echo "1) Instalação do BIND"
echo "2) Criar Forward e Reverse Zones"
echo "3) Sair"
echo ""
read -p "Escolha uma opção (1-3): " OPCAO_MENU

case $OPCAO_MENU in
    1)
        echo ""
        echo "=========================================="
        echo "   INSTALAÇÃO: DNS (BIND)"
        echo "=========================================="
        echo ""

        # 1 - Definir permissões do script
        # O que faz: Garante que o script tem permissões corretas para ser executado.
        
        # O que faz o chmod 775: Define permissões de leitura, escrita e execução para o proprietário e grupo, e leitura e execução para outros.

        chmod 775 config_dns_bind.sh

        # 2 - Recolha de informações do utilizador
        # O que faz: Solicita ao utilizador os dados necessários para configurar o servidor DNS.
        
        # O que faz o read -p: Lê a entrada do utilizador com um prompt personalizado.

        echo ""
        read -p "Introduza o domínio (ex: empresa.local): " DOMINIO
        read -p "Introduza o IP do servidor de Classe C (ex: 192.168.0.10): " IP_SERVIDOR_DNS
        read -p "Introduza o IP do Servidor DHCP/NAT: " IP_FORWARDER
        sleep 0.5

        nmcli device status | grep ethernet

        read -p "Indique a interface PRINCIPAL ÚNICA (ex: ens224): " LAN_INTERFACE # INTERFACE ÚNICA
        sleep 0.5

        echo ""
        echo "Informações recolhidas com sucesso!"
        sleep 0.5

        # 3 - Configuração da interface LAN com IP estático
        # O que faz: Configura a interface LAN principal com o IP estático fornecido.

        echo ""
        echo "=========================================="
        echo "   CONFIGURAÇÃO DE REDE"
        echo "=========================================="
        echo ""

        echo "A configurar IP estático $IP_SERVIDOR_DNS na interface $LAN_INTERFACE..."
        sleep 0.5

        # O que faz o ipv4.addresses: Define o endereço IP e máscara de rede (/24 = 255.255.255.0).

        sudo nmcli connection modify "$LAN_INTERFACE" ipv4.addresses "$IP_SERVIDOR_DNS/24"
        echo "Alterar a LAN_INTERFACE para IP $IP_SERVIDOR_DNS/24"
        sleep 0.5

        # O que faz o ipv4.method manual: Desativa DHCP e força configuração manual de IP.

        sudo nmcli connection modify "$LAN_INTERFACE" ipv4.method manual
        echo "Definir método de IP para manual"
        sleep 0.5

        # O que faz o ipv4.gateway: Define o gateway padrão (router) para acesso à rede externa.

        sudo nmcli connection modify "$LAN_INTERFACE" ipv4.gateway "$IP_FORWARDER"
        echo "Definir gateway para $IP_FORWARDER"
        sleep 0.5
        
        # O que faz o connection up: Reload da interface LAN com as novas configurações aplicadas.

        sudo nmcli connection up "$LAN_INTERFACE"
        echo "Aplicar configurações na interface $LAN_INTERFACE"
        sleep 0.5

        echo "Configuração da interface LAN concluída."
        sleep 0.5

        echo -n "A carregar: "
        for i in {1..50}; do
            printf "\rA carregar: [ %-50s ]" "$(printf '=%.0s' $(seq 1 $i))"
            sleep 0.05
        done

        # 5 - Teste de conectividade à Internet
        # O que faz: Verifica se o servidor consegue aceder à Internet antes de instalar pacotes.
        
        # O que faz o ping -c 3: Envia 3 pacotes ICMP para o servidor DNS público do Google (8.8.8.8).
        # O que faz o 8.8.8.8: Endereço IP do servidor DNS público do Google, usado para testar conectividade.
        
        echo ""
        echo "Teste de conectividade antes da instalação."

        nmcli con mod ens224 ipv4.dns "8.8.8.8"
        nmcli con up ens224 

        ping -c 3 8.8.8.8

        echo "Conectividade confirmada!"
        sleep 0.5
        echo ""

        # 6 - Instalação do BIND
        # O que faz: Instala o servidor DNS BIND e as suas ferramentas de diagnóstico.

        echo ""
        echo "=========================================="
        echo "   INSTALAÇÃO DO BIND"
        echo "=========================================="
        echo ""

        echo "A instalar BIND..."

        sudo dnf install -y bind bind-utils

        echo "BIND instalado com sucesso!"
        sleep 0.5

        localhost="127.0.0.1"
        sudo nmcli con mod ens224 ipv4.dns "$localhost"

        # 7 - Instalação e configuração do Fail2Ban para proteger o BIND
        # O que faz: Instala o Fail2Ban e configura uma jail específica para proteger o servidor DNS contra ataques.

        # O que faz o Fail2Ban: Ferramenta que monitora logs e bloqueia IPs que mostram comportamento malicioso.
        # O que faz a jail: Conjunto de regras que definem como o Fail2Ban deve agir para um serviço específico (neste caso, o BIND).
        # O que faz o filter named-refused: Filtro pré-definido que detecta tentativas de acesso recusadas no BIND.
        # O que faz o logpath: Caminho para o ficheiro de log que o Fail2Ban irá monitorizar.
        # O que faz o maxretry: Número máximo de tentativas falhadas antes de banir o IP.
        # O que faz o findtime: Período de tempo (em segundos) durante o qual as tentativas são contadas.
        # O que faz o bantime: Duração (em segundos) do banimento do IP.
        # O que faz o ignoreip: Lista de IPs que nunca serão banidos (ex: localhost e IP do servidor DNS).
        # O que faz o action firewallcmd-ipset: Ação que usa o firewalld para bloquear IPs maliciosos.
        # O que faz o systemctl enable --now: Habilita o serviço (auto-start) e inicia-o imediatamente.
        # O que faz o systemctl restart named: Reinicia o serviço BIND para aplicar novas configurações de log.
        # O que faz o systemctl status: Mostra o estado atual do serviço (ativo, inativo, erros).
        # O que faz o sleep 0.5: Pausa a execução por 0.5 segundos para melhor legibilidade.
        # O que faz o tee: Escreve o conteúdo para um ficheiro (similar ao cat > ficheiro).
        # O que faz o >/dev/null: Redireciona a saída para "nada" (não mostra no terminal).
        # O que faz o grep -q: Verifica silenciosamente se uma string existe num ficheiro (sem produzir saída).
        # O que faz o -a: Anexa (append) conteúdo ao ficheiro sem sobrescrever o que já existe.
        # O que faz o if ... then ... fi: Estrutura condicional para verificar se a inclusão já existe.
        # O que faz o exit 1: Sai do script com código de erro 1 em caso de falha. Juntamente com o set -e no início, isso interrompe o script.

        echo ""
        echo "=========================================="
        echo "   INSTALAÇÃO E CONFIGURAÇÃO DO FAIL2BAN"
        echo "=========================================="
        echo ""

        # 7.1 - Instalar EPEL e Fail2Ban (Comandos Separados para Robustez)

        echo "A instalar EPEL..."
        sudo dnf install -y epel-release 

        echo "A instalar Fail2Ban e firewalld integration..."

        # Fail2Ban e fail2ban-firewalld estão agora no EPEL

        sudo dnf install -y fail2ban fail2ban-firewalld

        echo "Fail2Ban instalado com sucesso!"
        sleep 0.5

        # 7.4 - Criar Jail (Regra) para o BIND DNS
        # O que faz: Define os parâmetros de banimento para o serviço DNS.

        echo "A criar jail 'bind-dns' em /etc/fail2ban/jail.d/bind-dns.conf..."

        IP_TO_IGNORE="127.0.0.1/8 $IP_SERVIDOR_DNS"

        sudo tee /etc/fail2ban/jail.d/bind-dns.conf >/dev/null << EOF
[bind-dns]
enabled  = true
port     = domain
protocol = udp,tcp
filter   = named-refused
logpath  = /var/log/named/security.log
maxretry = 10
findtime = 60
bantime  = 3600
ignoreip = $IP_TO_IGNORE
action   = firewallcmd-ipset
EOF

        # 7.5 - Iniciar e habilitar o serviço Fail2Ban

        echo "A iniciar e habilitar o serviço Fail2Ban..."

        # Reiniciar named para garantir que as novas configs de log são carregadas

        sudo systemctl restart named

        sudo systemctl enable --now fail2ban

        echo "Fail2Ban configurado para proteger o BIND/DNS."
        sleep 0.5

        # 8 - Configurar DNS da interface LAN para localhost
        # O que faz: Define o servidor DNS da interface LAN para o próprio servidor (localhost).
        
        # O que faz o ipv4.dns: Define o servidor DNS que a interface irá usar.
        # O que faz o 127.0.0.1: Endereço de loopback (localhost) - faz o servidor usar o seu próprio BIND.
        # O que faz o connection up: Recarrega a interface para aplicar a nova configuração de DNS.

        echo ""
        echo "A definir DNS da interface principal ($LAN_INTERFACE) para 127.0.0.1 (Loopback)..."
        sleep 0.5

        sudo nmcli connection modify "$LAN_INTERFACE" ipv4.dns "127.0.0.1"
        echo "Aplicar configuração de DNS na interface $LAN_INTERFACE..."
        sleep 0.5

        sudo nmcli connection up "$LAN_INTERFACE"
        echo "DNS da interface $LAN_INTERFACE definido para localhost."
        sleep 0.5

        echo "Limpeza de rede concluída."
        sleep 0.5
        echo ""

        # 9 - Extrair octetos do IP para criar zona reversa
        # O que faz: Divide o endereço IP em 4 partes (octetos) para poder criar a zona de resolução inversa.
        
        # O que é zona reversa: Permite descobrir o nome de domínio a partir de um endereço IP (IP → nome).
        # O que faz o REVERSE_ZONE_ID: Cria o nome da zona reversa no formato DNS padrão (in-addr.arpa).
        # O que faz o cut -d. -fN: Extrai o N-ésimo octeto do IP usando o ponto (.) como separador.
        # O que faz o date +%s: Gera um número de série baseado no timestamp Unix (segundos desde 1 janeiro 1970).

        echo ""
        echo "=========================================="
        echo "   PREPARAÇÃO DAS ZONAS DNS"
        echo "=========================================="
        echo ""

        OCTETO_1=$(echo "$IP_SERVIDOR_DNS" | cut -d'.' -f1)
        OCTETO_2=$(echo "$IP_SERVIDOR_DNS" | cut -d'.' -f2)
        OCTETO_3=$(echo "$IP_SERVIDOR_DNS" | cut -d'.' -f3)
        OCTETO_4=$(echo "$IP_SERVIDOR_DNS" | cut -d'.' -f4)

        REVERSE_ZONE_ID="${OCTETO_3}.${OCTETO_2}.${OCTETO_1}.in-addr.arpa"

        SERIAL_DATE=$(date +%s)

        echo "Domínio: $DOMINIO"
        echo "IP Servidor DNS: $IP_SERVIDOR_DNS"
        echo "Zona Reversa: $REVERSE_ZONE_ID"
        echo "Serial Date: $SERIAL_DATE"
        sleep 0.5
        echo ""

        echo "A criar diretório e ficheiros de logs..."

        sudo mkdir -p /var/log/named
        sudo chown named:named /var/log/named
        sudo chmod 755 /var/log/named
        sudo touch /var/log/named/bind_queries.log
        sudo touch /var/log/named/security.log
        sudo chown named:named /var/log/named/bind_queries.log
        sudo chown named:named /var/log/named/security.log
        echo "Ajustando contexto SELinux para os logs do BIND..."
        sudo restorecon -Rv /var/log/named

        echo "Diretório e ficheiros de logs criados e permissões/SELinux ajustados."
        sleep 0.5
        echo ""

        # 9.5 - VALIDAÇÃO CRÍTICA: Verificar se as variáveis estão definidas
        # O que faz: Garante que todas as variáveis necessárias existem antes de criar os ficheiros de zona.

        echo ""
        echo "=========================================="
        echo "   VALIDAÇÃO DE VARIÁVEIS"
        echo "=========================================="
        echo ""

        echo "A validar variáveis necessárias..."

        if [ -z "$DOMINIO" ]; then
            echo "ERRO CRÍTICO: Variável DOMINIO não está definida!"
            exit 1
        fi

        if [ -z "$IP_SERVIDOR_DNS" ]; then
            echo "ERRO CRÍTICO: Variável IP_SERVIDOR_DNS não está definida!"
            exit 1
        fi

        if [ -z "$OCTETO_1" ] || [ -z "$OCTETO_2" ] || [ -z "$OCTETO_3" ] || [ -z "$OCTETO_4" ]; then
            echo "ERRO CRÍTICO: Octetos não estão definidos!"
            exit 1
        fi

        if [ -z "$SERIAL_DATE" ]; then
            echo "ERRO CRÍTICO: Variável SERIAL_DATE não está definida!"
            exit 1
        fi

        echo "DOMINIO: $DOMINIO"
        echo "IP_SERVIDOR_DNS: $IP_SERVIDOR_DNS"
        echo "OCTETOS: $OCTETO_1.$OCTETO_2.$OCTETO_3.$OCTETO_4"
        echo "SERIAL_DATE: $SERIAL_DATE"
        echo "REVERSE_ZONE_ID: $REVERSE_ZONE_ID"

        echo ""
        echo "Todas as variáveis validadas com sucesso!"
        sleep 0.5
        echo ""

        # 10 - Criar ficheiro de zona direta (Forward Zone)
        # O que faz: Cria o ficheiro que resolve nomes de domínio para endereços IP (nome → IP).
        # O que faz o tee: Escreve o conteúdo para um ficheiro (similar ao cat > ficheiro).
        # O que faz o >/dev/null: Redireciona a saída para "nada" (não mostra no terminal).

        echo "A criar Forward Zone..."

        sudo tee /var/named/${DOMINIO}.db >/dev/null << EOF
\$TTL 86400
@ IN SOA ${DOMINIO}. root.${DOMINIO}. (
        ${SERIAL_DATE}  ; Serial
        3600            ; Refresh
        1800            ; Retry
        604800          ; Expire
        86400 )         ; Minimum TTL
    IN NS     ns.${DOMINIO}.
ns IN A       ${IP_SERVIDOR_DNS}
@ IN A       ${IP_SERVIDOR_DNS}
EOF

        # Explicação dos registos DNS:
        # - \$TTL 86400: Time To Live - tempo (em segundos) que os registos são guardados em cache (24 horas).
        # - SOA: Start of Authority - define o servidor autoritativo para esta zona.
        # - Serial: Número de versão da zona (incrementa a cada alteração).
        # - Refresh: Tempo que servidores secundários esperam antes de verificar atualizações.
        # - Retry: Tempo de espera se o refresh falhar.
        # - Expire: Tempo após o qual a zona expira se não houver contacto com o servidor primário.
        # - NS: Name Server - define qual o servidor de nomes para este domínio.
        # - A: Address Record - associa um nome a um endereço IPv4.
        # - @: Representa o próprio domínio (empresa.local).

        echo "Forward zone criada: /var/named/${DOMINIO}.db"
        sleep 0.5

        # 11 - Criar ficheiro de zona inversa (Reverse Zone)
        # O que faz: Cria o ficheiro que resolve endereços IP para nomes de domínio (IP -> nome).

        echo "A criar zona inversa (Reverse Zone)..."

        sudo tee /var/named/${OCTETO_3}.${OCTETO_2}.${OCTETO_1}.db >/dev/null << EOF
\$TTL 86400
@ IN SOA ${DOMINIO}. root.${DOMINIO}. (
        ${SERIAL_DATE}  ; Serial
        3600            ; Refresh
        1800            ; Retry
        604800          ; Expire
        86400 )         ; Minimum TTL
    IN NS     ns.${DOMINIO}.
${OCTETO_4} IN  PTR   ns.${DOMINIO}.
EOF

        # Explicação adicional dos registos PTR:
        # - PTR: Pointer Record - associa um endereço IP a um nome de domínio.
        # - ${OCTETO_4}: Último octeto do IP do servidor DNS.

        echo "Zona inversa criada: /var/named/${OCTETO_3}.${OCTETO_2}.${OCTETO_1}.db"
        sleep 0.5
        echo ""

        # 12 - Configurar named.conf (ficheiro principal do BIND)
        # O que faz: Cria o ficheiro de configuração principal do servidor BIND com todas as opções necessárias.

        echo ""
        echo "CONFIGURAÇÃO DO BIND"
        echo ""

        # UTILIZAÇÃO de << EOF para evitar problemas com identação.
        sudo tee /etc/named.conf >/dev/null << EOF
// named.conf do servidor autoritativo e de caching
options {
    listen-on port 53 { any; };
    listen-on-v6 port 53 { none; };
    directory "/var/named";
    dump-file "/var/named/data/cache_dump.db";
    statistics-file "/var/named/data/named_stats.txt";
    memstatistics-file "/var/named/data/named_mem_stats.txt";
    allow-query { any; };
    
    forwarders { 
        8.8.8.8;
    };
    forward only;
    
    recursion yes;
    
    managed-keys-directory "/var/named/dynamic";
    pid-file "/run/named/named.pid";
    session-keyfile "/run/named/session.key";
};

logging {
    channel default_log {
        file "/var/log/named/bind_queries.log" versions 3 size 5m;
        severity info;
        print-time yes;
    };
    channel security_log {
        file "/var/log/named/security.log" versions 3 size 5m;
        severity info;
        print-time yes;
    };
    category queries { default_log; };
    category security { security_log; };
    category client { security_log; };
};

zone "." IN {
    type hint;
    file "named.ca";
};

include "/etc/named.rfc1912.zones";
include "/etc/named.root.key";
EOF

        # Explicação das opções do named.conf:
        # - listen-on port 53 { any; }: Escuta pedidos DNS em todas as interfaces na porta 53.
        # - listen-on-v6 port 53 { none; }: Desativa IPv6.
        # - directory "/var/named": Diretório onde ficam os ficheiros de zona.
        # - allow-query { any; }: Permite consultas DNS de qualquer cliente.
        # - forwarders { 8.8.8.8; }: DNS externo usado para consultas que este servidor não conhece.
        # - forward only: Força o uso do forwarder (não tenta resolver sozinho domínios externos).
        # - recursion yes: Permite que o servidor faça consultas recursivas (essencial para clientes).
        # - logging: Configuração de logs para registar todas as consultas DNS.

        echo "Configuração básica do named.conf concluída."
        sleep 0.5

        # 13 - Adicionar zonas personalizadas ao named.conf
        # O que faz: Adiciona as definições das zonas direta e inversa ao ficheiro de configuração.
        # O que faz o -a: Anexa (append) conteúdo ao ficheiro sem sobrescrever o que já existe.

        echo "A adicionar zonas personalizadas ao named.conf..."

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

        # Explicação das opções de zona:
        # - type master: Indica que este servidor é o autoritativo (mestre) para esta zona.
        # - file: Caminho para o ficheiro de zona (relativo a /var/named).
        # - allow-update { none; }: Não permite atualizações dinâmicas (mais seguro).

        echo "Zonas adicionadas com sucesso."
        sleep 0.5

        # 15 - Definir permissões dos ficheiros de zona
        # O que faz: Altera o proprietário dos ficheiros de zona para o utilizador "named".

        # O que faz o sudo chown: Change owner - muda o proprietário dos ficheiros de zona para o utilizador e grupo "named".

        echo "A definir permissões dos ficheiros de zona..."

        sudo chown named:named /var/named/${DOMINIO}.db
        sudo chown named:named /var/named/${OCTETO_3}.${OCTETO_2}.${OCTETO_1}.db

        echo "Permissões definidas."
        sleep 0.5
        echo ""

        # 16 - Validar configuração do BIND (named.conf)
        # O que faz: Verifica se o ficheiro de configuração principal tem erros de sintaxe.

        # O que faz o named-checkconf: Ferramenta que valida a sintaxe do ficheiro named.conf.
        # O que faz o if ... then ... else: Estrutura condicional baseada no sucesso/falha do comando.
        # O que faz o exit 1: Sai do script com código de erro 1 em caso de falha. Juntamente com o set -e no início, isso interrompe o script.

        echo ""
        echo "=========================================="
        echo "   VALIDAÇÃO DE CONFIGURAÇÕES"
        echo "=========================================="
        echo ""

        echo "A validar named.conf..."

        if sudo named-checkconf; then
            echo "named.conf está OK!"
        else
            echo "Erro 16 no named.conf! Verifique a configuração."
            exit 1
        fi

        sleep 0.5

        # 17 - Validar zona direta
        # O que faz: Verifica se o ficheiro de zona direta tem erros de sintaxe ou inconsistências.

        # O que faz o named-checkzone: Ferramenta que valida a sintaxe e integridade de ficheiros de zona.
        # O que faz o ${DOMINIO}: Nome da zona direta a validar.
        # O que faz o /var/named/${DOMINIO}.db: Caminho para o ficheiro de zona direta.
        # O que faz o if ... then ... else: Estrutura condicional baseada no sucesso/falha do comando.

        echo "A validar forward zone..."

        if sudo named-checkzone ${DOMINIO} /var/named/${DOMINIO}.db; then
            echo "Forward zone está OK!"
        else
            echo "Erro 17 na forward zone! Verifique o ficheiro."
            exit 1
        fi

        sleep 0.5

        # 18 - Validar zona inversa
        # O que faz: Verifica se o ficheiro de zona inversa tem erros de sintaxe ou inconsistências.

        # O que faz o ${REVERSE_ZONE_ID}: Nome da zona inversa a validar.
        # O que faz o /var/named/${OCTETO_3}.${OCTETO_2}.${OCTETO_1}.db: Caminho para o ficheiro de zona inversa.
        # O que faz o if ... then ... else: Estrutura condicional baseada no sucesso/falha do comando.

        echo "A validar reverse zone..."

        if sudo named-checkzone ${REVERSE_ZONE_ID} /var/named/${OCTETO_3}.${OCTETO_2}.${OCTETO_1}.db; then
            echo "Zona inversa está OK!"
        else
            echo "Erro 18 na zona inversa! Verifique o ficheiro."
            exit 1
        fi

        sleep 0.5
        echo ""

        # 19 - Configurar firewall
        # O que faz: Adiciona regras à firewall para permitir tráfego DNS (porta 53 TCP/UDP).

        # O que faz o firewall-cmd: Ferramenta de gestão da firewall (firewalld) no CentOS/RHEL.
        # O que faz o --permanent: Torna a regra permanente (persiste após reboot).
        # O que faz o --add-service=dns: Permite tráfego para o serviço DNS (porta 53 TCP e UDP).
        # O que faz o --reload: Recarrega as regras da firewall para aplicar as mudanças imediatamente.

        echo ""
        echo "=========================================="
        echo "   CONFIGURAÇÃO DA FIREWALL"
        echo "=========================================="
        echo ""

        echo "A configurar firewall..."

        sudo firewall-cmd --permanent --add-service=dns

        sudo firewall-cmd --reload

        echo "Firewall configurada com sucesso!"
        sleep 0.5
        echo ""

        # 20 - Iniciar e habilitar o serviço BIND
        # O que faz: Inicia o servidor DNS BIND e configura-o para arrancar automaticamente no boot.
        # O que faz o systemctl enable --now: Habilita o serviço (auto-start) e inicia-o imediatamente.
        # O que faz o named: Nome do serviço BIND no systemd.
        # O que faz o systemctl status: Mostra o estado atual do serviço (ativo, inativo, erros).

        echo ""
        echo "=========================================="
        echo "   INICIALIZAÇÃO DO SERVIÇO BIND"
        echo "=========================================="
        echo ""

        echo -n "A iniciar o Serviço BIND..."
        for i in {1..50}; do
            printf "\rA carregar: [%-50s]" "$(printf '=%.0s' $(seq 1 $i))"
            sleep 0.1
        done

        sudo systemctl enable --now named

        sleep 0.5

        sudo systemctl status named

        echo ""
        echo "DNS CONFIGURADO COM SUCESSO!"
        echo ""
        sleep 0.5
        ;;

    2)

        # 21 - Menu de gestão de registos DNS
        # O que faz: Permite ao utilizador adicionar ou consultar registos DNS após a configuração inicial.

        # O que faz o while true; do ... done: Cria um loop infinito para o menu.
        # O que faz o case ... in ... esac: Estrutura de seleção múltipla para escolher ações baseadas na opção do utilizador.
        # O que faz o read -p: Lê a entrada do utilizador com um prompt personalizado.
        # O que faz o sudo tee -a: Anexa (append) conteúdo ao ficheiro com privilégios de superutilizador.
        # O que faz o rndc reload: Recarrega as zonas DNS sem reiniciar o serviço BIND.
        # O que faz o sleep 0.5: Pausa a execução por 0.5 segundos para melhor legibilidade.
        # O que faz o sed -i '$ d': Remove a última linha do ficheiro (em caso de erro).
        # O que faz o $: Representa a última linha do ficheiro.
        # O que faz o d: Comando do sed para deletar a linha selecionada.
        # O que faz o exit 0: Sai do script com código de sucesso (0).
        # O que faz o continue: Retorna ao início do loop, permitindo nova escolha no menu.
        # O que faz o break: Sai do loop, terminando o menu.

        echo ""
        echo "=========================================="
        echo "   PREPARAÇÃO DA GESTÃO DE ZONAS"
        echo "=========================================="
        echo ""

        # O que faz: Solicita o IP do servidor DNS (necessário para todas as validações de sub-rede e zonas)

        read -p "Introduza o IP do Servidor DNS (ex: 192.168.0.10): " IP_SERVIDOR_DNS
        read -p "Introduza o domínio (ex: empresa.local): " DOMINIO

        # O que faz: Re-extrair octetos e rede para uso nos passos 21 e 22

        OCTETO_1=$(echo "$IP_SERVIDOR_DNS" | cut -d'.' -f1)
        OCTETO_2=$(echo "$IP_SERVIDOR_DNS" | cut -d'.' -f2)
        OCTETO_3=$(echo "$IP_SERVIDOR_DNS" | cut -d'.' -f3)
        OCTETO_4=$(echo "$IP_SERVIDOR_DNS" | cut -d'.' -f4)
        
        REVERSE_ZONE_ID="${OCTETO_3}.${OCTETO_2}.${OCTETO_1}.in-addr.arpa"

        # O que faz: Define a sub-rede para validação da rede

        IP_REDE_SERVIDOR="${OCTETO_1}.${OCTETO_2}.${OCTETO_3}" 
        
        # O que faz: Tenta obter o serial date para gestão (Se o ficheiro existir, senão usa o timestamp atual)

        if [ -f /var/named/${DOMINIO}.db ]; then
            SERIAL_DATE=$(grep -m 1 '; Serial' /var/named/${DOMINIO}.db 2>/dev/null | awk '{print $1}')
            if [ -z "$SERIAL_DATE" ]; then
                SERIAL_DATE=$(date +%s)
            fi
        else
            echo "Aviso: O ficheiro de zona direta não foi encontrado. Usando Serial Date atual."
            SERIAL_DATE=$(date +%s)
        fi
        
        echo ""
        echo "IP DNS para validações: $IP_SERVIDOR_DNS (Sub-rede: $IP_REDE_SERVIDOR.0)"
        sleep 0.5
        echo ""
        echo "Deseja adicionar ou consultar registos no DNS? (y/n): "
        read -p "Resposta: " GERIR_REGISTOS

        if [[ "$GERIR_REGISTOS" == "y" || "$GERIR_REGISTOS" == "Y" ]]; then
            
            # 21.1 - Loop do menu principal
            # O que faz: Mantém o menu ativo até o utilizador escolher sair.

            while true; do
                echo ""
                echo "=========================================="
                echo "   GESTÃO DE REGISTOS DNS"
                echo "=========================================="
                echo ""
                echo "Escolha o tipo de operação:"
                echo "1 - Adicionar Nome para IP (zona direta)"
                echo "2 - Adicionar IP para Nome (zona inversa)"
                echo "3 - Ver registos existentes"
                echo "4 - Sair"
                echo ""
                read -p "Opção: " OPCAO_GESTAO
                
                case $OPCAO_GESTAO in
                    1)
                        # 21.1.1 - Adicionar registo à zona direta (A Record)
                        # O que faz: Adiciona um novo nome de host que aponta para um IP.
                        
                        echo ""
                        echo "--- Adicionar Nome para IP (zona direta) ---"
                        echo ""
                        read -p "Nome do host (ex: pc1, servidor, router): " NOME_HOST
                        read -p "Endereço IP (ex: 192.168.1.20): " IP_HOST
                        
                        # 21.1.2 - Validar se o IP está na mesma rede
                        # O que faz: Extrai os primeiros 3 octetos do IP fornecido e compara com o IP do servidor.

                        IP_REDE_HOST=$(echo "$IP_HOST" | cut -d'.' -f1-3)
                        IP_REDE_SERVIDOR=$(echo "$IP_SERVIDOR_DNS" | cut -d'.' -f1-3)
                        
                        if [[ "$IP_REDE_HOST" != "$IP_REDE_SERVIDOR" ]]; then
                            echo ""
                            echo "AVISO: O IP $IP_HOST não está na mesma rede que o servidor ($IP_REDE_SERVIDOR.0/24)!"
                            read -p "Deseja continuar mesmo assim? (y/n): " CONTINUAR
                            if [[ "$CONTINUAR" != "y" && "$CONTINUAR" != "Y" ]]; then
                                echo "Operação cancelada."
                                continue
                            fi
                        fi
                        
                        # 21.1.3 - Incrementar o serial da zona
                        # O que faz: Atualiza o número de série para que outros servidores DNS saibam que a zona mudou.

                        # O que faz o sed: Stream editor - ferramenta para procurar e substituir texto em ficheiros.
                        # O que faz o -i: Edita o ficheiro diretamente (in-place).
                        # O que faz o "s/ANTIGO/NOVO/": Substitui a primeira ocorrência de ANTIGO por NOVO.

                        NOVO_SERIAL=$(date +%s)

                        sudo sed -i "s/${SERIAL_DATE}/${NOVO_SERIAL}/" /var/named/${DOMINIO}.db
                        SERIAL_DATE=$NOVO_SERIAL
                        
                        # 21.1.4 - Adicionar o registo A ao ficheiro de zona
                        # O que faz: Anexa uma nova linha ao ficheiro com o registo DNS tipo A.

                        echo "${NOME_HOST}  IN  A       ${IP_HOST}" | sudo tee -a /var/named/${DOMINIO}.db >/dev/null
                        
                        echo ""
                        echo "Registo adicionado com sucesso!"
                        echo "${NOME_HOST}.${DOMINIO} → ${IP_HOST}"
                        
                        # 21.1.5 - Validar a zona após alteração
                        # O que faz: Verifica se o ficheiro de zona está correto após a adição do novo registo.

                        # O que faz o rndc reload: Recarrega as zonas DNS sem reiniciar o serviço BIND.
                        # O que faz o if ... then ... else: Estrutura condicional baseada no sucesso/falha do comando.
                        # O que faz o sed -i '$ d': Remove a última linha do ficheiro (em caso de erro).
                        # O que faz o $: Representa a última linha do ficheiro.
                        # O que faz o d: Comando do sed para deletar a linha selecionada.
                        # O que faz o sleep 0.5: Pausa a execução por 1 segundo para melhor legibilidade.

                        if sudo named-checkzone ${DOMINIO} /var/named/${DOMINIO}.db >/dev/null 2>&1; then

                            sudo rndc reload
                            echo "Zona recarregada com sucesso!"

                        else

                            echo "Erro 21.1.5! Zona direta inválida após alteração!"
                            echo "A reverter alterações..."

                            # Remover a última linha adicionada em caso de erro

                            sudo sed -i '$ d' /var/named/${DOMINIO}.db
                        fi
                        
                        sleep 0.5
                        ;;
                        
                    2)
                        # 21.1.6 - Adicionar registo à zona inversa (PTR Record)
                        # O que faz: Adiciona um registo que permite resolver IP para nome.
                        
                        echo ""
                        echo "--- Adicionar IP para Nome (zona inversa) ---"
                        echo ""
                        read -p "Último octeto do IP (ex: para 192.168.0.20, digite 20): " ULTIMO_OCTETO
                        read -p "Nome completo do host (ex: pc1.${DOMINIO}): " NOME_COMPLETO
                        
                        # 21.1.6 - Adição do ponto final caso não exista.
                        # O que faz: Garante que o FQDN (Fully Qualified Domain Name) termina com ponto.

                        # O que faz o =~ \.$: Verifica se a string termina com um ponto.
                        # O que faz o ${NOME_COMPLETO}.: Adiciona um ponto ao final do nome se necessário.

                        if [[ ! "$NOME_COMPLETO" =~ \.$ ]]; then
                            NOME_COMPLETO="${NOME_COMPLETO}."
                        fi
                        
                        # 21.1.7 - Incrementação da serial da zona inversa (reverse zone)
                        # O que faz: Atualiza o número de série para que outros servidores DNS saibam que a zona mudou.

                        # O que faz o sed: Stream editor - ferramenta para procurar e substituir texto em ficheiros.
                        # O que faz o -i: Edita o ficheiro diretamente (in-place).
                        # O que faz o "s/ANTIGO/NOVO/": Substitui a primeira ocorrência de ANTIGO por NOVO.
                        # O que faz o date +%s: Gera um número de série baseado no timestamp Unix (segundos desde 1 janeiro 1970).

                        NOVO_SERIAL=$(date +%s)
                        sudo sed -i "s/${SERIAL_DATE}/${NOVO_SERIAL}/" /var/named/${OCTETO_3}.${OCTETO_2}.${OCTETO_1}.db
                        SERIAL_DATE=$NOVO_SERIAL
                        
                        # 21.1.8 - Adicionar o registo PTR ao ficheiro de zona inversa

                        echo "${ULTIMO_OCTETO}  IN  PTR   ${NOME_COMPLETO}" | sudo tee -a /var/named/${OCTETO_3}.${OCTETO_2}.${OCTETO_1}.db >/dev/null
                        
                        echo ""
                        echo "Registo inverso adicionado com sucesso!"
                        echo "  ${OCTETO_1}.${OCTETO_2}.${OCTETO_3}.${ULTIMO_OCTETO} -> ${NOME_COMPLETO}"
                        
                        # 21.1.9 - Validar a zona inversa após alteração
                        # O que faz: Verifica se o ficheiro de zona inversa está correto após a adição do novo registo.

                        # O que faz o rndc reload: Recarrega as zonas DNS sem reiniciar o serviço BIND.
                        # O que faz o if ... then ... else: Estrutura condicional baseada no sucesso/falha do comando.
                        # O que faz o sed -i '$ d': Remove a última linha do ficheiro (em caso de erro).
                        # O que faz o $: Representa a última linha do ficheiro.
                        # O que faz o d: Comando do sed para deletar a linha selecionada.
                        # O que faz o sleep 0.5: Pausa a execução por meio segundo para melhor legibilidade.

                        if sudo named-checkzone ${REVERSE_ZONE_ID} /var/named/${OCTETO_3}.${OCTETO_2}.${OCTETO_1}.db >/dev/null 2>&1; then
                            sudo rndc reload
                            echo "Reverse zone recarregada com sucesso!"

                        else
                            echo "Erro 21.1.9! Reverse zone inválida após alteração!"
                            echo "  A reverter alterações..."
                            sudo sed -i '$ d' /var/named/${OCTETO_3}.${OCTETO_2}.${OCTETO_1}.db
                        fi
                        
                        sleep 0.5
                        ;;
                        
                    3)
                        # 21.1.10 - Ver registos existentes
                        # O que faz: Mostra os registos DNS atualmente configurados nas zonas.

                        # O que faz o grep -v "^;": Filtra linhas que começam com ; (comentários).
                        # O que faz o grep -v "^$": Filtra linhas vazias.
                        # O que faz o grep -E "IN\s+(A|NS|CNAME|MX)": Filtra registos A, NS, CNAME e MX.
                        # O que faz o grep "PTR": Filtra registos PTR na zona inversa.
                        # O que faz o sudo cat: Mostra o conteúdo dos ficheiros de zona com permissões elevadas.

                        echo ""
                        echo "=========================================="
                        echo "   REGISTOS EXISTENTES"
                        echo "=========================================="
                        echo ""
                        echo "--- Forward Zone (${DOMINIO}) ---"

                        sudo cat /var/named/${DOMINIO}.db | grep -v "^;" | grep -v "^$" | grep -E "IN\s+(A|NS|CNAME|MX)"
                        
                        echo ""
                        echo "--- Zona Inversa (${REVERSE_ZONE_ID}) ---"
                        sudo cat /var/named/${OCTETO_3}.${OCTETO_2}.${OCTETO_1}.db | grep -v "^;" | grep -v "^$" | grep "PTR"
                        
                        echo ""
                        read -p "Prima ENTER para continuar..."
                        ;;
                        
                    4)
                        echo ""
                        echo "A sair da gestão de registos..."
                        break
                        ;;
                        
                    *)
                        echo ""
                        echo "Opção inválida! Tente novamente."
                        sleep 0.5
                        ;;
                esac
            done
        fi

        # 22 - Menu de verificações opcionais
        # O que faz: Oferece ao utilizador opções para testar o servidor DNS configurado.

        # O que faz o while True; do ... done: Loop infinito que mantém o menu ativo até o utilizador decidir sair.
        # O que faz o read -p: Lê a entrada do utilizador com um prompt personalizado.

        echo ""
        echo "Deseja executar verificações finais? (y/n): "
        read -p "Resposta: " FAZER_VERIFICACOES

        while true; do

            # 22.1 - Menu de verificações DNS
            # O que faz: Apresenta várias opções de teste para o servidor DNS.

            if [[ "$FAZER_VERIFICACOES" == "y" || "$FAZER_VERIFICACOES" == "Y" ]]; then
                echo ""
                echo "1) Testar resolução direta (nome -> IP);"
                echo "2) Testar resolução inversa (IP -> nome);"
                echo "3) Ver status do serviço;"
                echo "4) Testar conectividade Internet;"
                echo "5) Sair."
                echo ""
                read -p "Escolha uma opção (1-5): " OPCAO_VERIFICACAO_DNS

                # 22.1.1 - Estrutura case para opções de verificação
                # O que faz: Executa diferentes comandos de teste baseados na escolha do utilizador.

                # O que faz o case: Estrutura de controlo que compara uma variável com vários padrões e executa código correspondente.
                # O que faz o dig: Ferramenta de query DNS que consulta registos DNS.
                # O que faz o -x: Opção do dig que realiza uma query de resolução inversa (IP para nome).
                # O que faz o systemctl status: Mostra o estado atual do serviço (ativo, inativo, erros).
                # O que faz o google.com: Domínio usado para testar se o forwarder está a funcionar corretamente.
                # O que faz o break: Sai do loop atual (neste caso, sai do menu de verificações).
                # O que faz o *: Padrão "catch-all" que captura qualquer entrada não prevista.
                # O que faz o echo: Exibe mensagens no terminal.
                # O que faz o ;;: Termina cada bloco de código dentro do case.
                # O que faz o esac: Finaliza a estrutura case (é "case" escrito ao contrário).

                case $OPCAO_VERIFICACAO_DNS in
                    1)
                        echo ""
                        echo "--- Teste de Resolução Direta ---"

                        # 22.1.2 - Teste de resolução direta
                        # O que faz: Consulta o servidor DNS para resolver nomes de domínio para endereços IP.
                        # O que faz o dig: Ferramenta de query DNS que consulta registos DNS.

                        dig ${DOMINIO}
                        dig ns.${DOMINIO}
                        ;;
                    2)
                        echo ""
                        echo "--- Teste de Resolução Inversa ---"

                        # 22.1.3 - Teste de resolução inversa
                        # O que faz: Consulta o servidor DNS para resolver endereços IP para nomes de domínio.
                        # O que faz o -x: Opção do dig que realiza uma query de resolução inversa (IP para nome).

                        dig -x ${IP_SERVIDOR_DNS}
                        ;;
                    3)
                        echo ""
                        echo "--- Status do Serviço BIND ---"
                        sudo systemctl status named
                        ;;
                    4)
                        echo ""
                        echo "--- Teste de Conectividade Internet ---"

                        # 22.1.4 - Teste de conectividade à Internet via DNS
                        # O que faz: Testa se o forwarder 8.8.8.8 está a funcionar corretamente.

                        dig google.com
                        ;;
                    5)
                        echo ""
                        echo "A sair sem verificações."

                        # 22.1.5 - Sair do menu de verificações
                        # O que faz: Encerra o loop do menu de verificações.

                        break
                        ;;
                    *)
                        echo ""
                        echo "Opção inválida. A sair sem verificações."

                        # 22.1.6 - Opção inválida
                        # O que faz: Encerra o loop do menu de verificações em caso de entrada inválida.

                        break
                        ;;
                esac
            fi
        done

        # O que faz o esac: Finaliza a estrutura case (é "case" escrito ao contrário).

        ;;

    3)
        echo ""
        echo "A sair do script. Adeus!"
        exit 0
        ;;
    
    *)
        echo ""
        echo "Opção inválida. A sair do script."
        exit 1
        ;;

esac

# O que faz o esac: Finaliza a estrutura case (é "case" escrito ao contrário).

# 23 - Mensagens finais e comandos úteis
# O que faz: Exibe comandos úteis para o utilizador após a conclusão do script.

echo ""
echo "=========================================="
echo "   COMANDOS ÚTEIS PARA O FUTURO"
echo "=========================================="
echo ""
echo "- Testar DNS interno: dig ${DOMINIO}"
echo "- Testar Internet: dig google.com"
echo "- Ver logs: tail -f /var/log/named/bind_queries.log"
echo "- Status: systemctl status named"
echo "- Reiniciar BIND: sudo systemctl restart named"
echo ""
echo "Recomenda-se um reboot do sistema para garantir que todas as alterações tenham efeito."
echo "Para reiniciar o sistema, execute: reboot"

#reboot - Caso queira reiniciar automaticamente após a configuração, descomente esta linha.

# O que faz o exit 0: Finaliza o script em caso de sucesso (se não houver falhas com set -e)
exit 0