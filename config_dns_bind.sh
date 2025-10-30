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

echo ""
echo "=========================================="
echo "   INSTALAÇÃO: DNS (BIND)"
echo "=========================================="
echo ""

# 1 - Definir permissões do script
# O que faz: Garante que o script tem permissões corretas para ser executado.
# O que faz o chmod 775: Define permissões de leitura, escrita e execução para o proprietário e grupo, e leitura e execução para outros.

chmod 775 config_dns_bindV2.sh

# 2 - Recolha de informações do utilizador
# O que faz: Solicita ao utilizador os dados necessários para configurar o servidor DNS.

echo ""
read -p "Introduza o domínio (ex: empresa.local): " DOMINIO
read -p "Introduza o IP do servidor de Classe C (ex: 192.168.0.10): " IP_SERVIDOR_DNS
read -p "Introduza o IP do Servidor DHCP/NAT: " IP_FORWARDER
sleep 0.5

read -p "Indique a interface LAN principal (ex: ens224): " LAN_INTERFACE
read -p "Indique a interface WAN temporária para acesso à Internet (ex: ens160): " INTERFACE_WAN_TEMP
sleep 0.5

echo ""
echo "Informações recolhidas com sucesso!"
sleep 1

# 2 - Configuração da interface LAN com IP estático
# O que faz: Define o endereço IP fixo do servidor DNS na interface de rede local.

echo ""
echo "=========================================="
echo "   CONFIGURAÇÃO DE REDE"
echo "=========================================="
echo ""

# O que faz: Cria uma nova conexão para a interface WAN temporária (se não existir).

sudo nmcli connection add type ethernet ifname "$INTERFACE_WAN_TEMP" con-name "$INTERFACE_WAN_TEMP"
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

# 3 - Ativação da interface WAN temporária
# O que faz: Liga a interface WAN temporária para permitir acesso à Internet durante a instalação.
# O que faz o ||: Operador lógico OR - tenta o primeiro comando (device connect), se falhar executa o segundo (connection up).

echo ""
echo "A ativar interface $INTERFACE_WAN_TEMP para acesso temporário à Internet..."

sudo nmcli device connect "$INTERFACE_WAN_TEMP" || sudo nmcli connection up "$INTERFACE_WAN_TEMP"
echo "Interface $INTERFACE_WAN_TEMP ativada."

echo -n "A carregar: "
for i in {1..50}; do
    printf "\rA carregar: [%-50s]" "$(printf '#%.0s' $(seq 1 $i))"
    sleep 0.1
done

# 4 - Teste de conectividade à Internet
# O que faz: Verifica se o servidor consegue aceder à Internet antes de instalar pacotes.

# O que faz o ping -c 3: Envia 3 pacotes ICMP para o servidor DNS público do Google (8.8.8.8).
# O que faz o 8.8.8.8: Endereço IP do servidor DNS público do Google, usado para testar conectividade.

echo "Teste de conectividade antes da instalação."

ping -c 3 8.8.8.8

echo "Conectividade confirmada!"
sleep 1
echo ""

# 5 - Instalação do BIND
# O que faz: Instala o servidor DNS BIND e as suas ferramentas de diagnóstico.

# O que faz o dnf install: Gestor de pacotes do CentOS/RHEL que instala software.
# O que faz o -y: Responde automaticamente "sim" a todas as perguntas durante a instalação.
# O que faz o bind: Pacote principal do servidor DNS BIND.
# O que faz o bind-utils: Ferramentas úteis como dig, nslookup, host para testar DNS.
# O que faz o nmcli con mod: Modifica a configuração da conexão de rede.
# O que faz o ipv4.dns: Define o servidor DNS para a interface de rede.
# O que faz o ens224: Nome da interface de rede principal (LAN).

# O que é localhost: Endereço IP de loopback.

echo ""
echo "=========================================="
echo "   INSTALAÇÃO DO BIND"
echo "=========================================="
echo ""

echo "A instalar BIND..."

sudo nmcli con mod ens224 ipv4.dns "8.8.8.8"
sudo nmcli con up ens224

sudo dnf install -y bind bind-utils

echo "BIND instalado com sucesso!"
sleep 1

localhost="127.0.0.1"
sudo nmcli con mod ens224 ipv4.dns "$localhost"

# 6 - Desativação da interface WAN temporária
# O que faz: Desliga a interface WAN temporária após a instalação para segurança.

sudo nmcli device disconnect "$INTERFACE_WAN_TEMP"

# 7 - Configurar DNS da interface LAN para localhost
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

# 8 - Extrair octetos do IP para criar zona reversa
# O que faz: Divide o endereço IP em 4 partes (octetos) para poder criar a zona de resolução inversa.

# O que é zona reversa: Permite descobrir o nome de domínio a partir de um endereço IP (IP → nome).
# O que faz o REVERSE_ZONE_ID: Cria o nome da zona reversa no formato DNS padrão (in-addr.arpa).

# O que faz o cut -d. -fN: Extrai o N-ésimo octeto do IP usando o ponto (.) como separador.

# O que faz o date +%s: Gera um número de série baseado no timestamp Unix (segundos desde 1 janeiro 1970).

echo ""
echo "=========================================="
echo "   PREPARAÇÃO DAS ZONAS DNS"
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
sleep 1
echo ""

# 9 - Criar ficheiro de zona direta (Forward Zone)
# O que faz: Cria o ficheiro que resolve nomes de domínio para endereços IP (nome → IP).
# O que faz o tee: Escreve o conteúdo para um ficheiro (similar ao cat > ficheiro).
# O que faz o >/dev/null: Redireciona a saída para "nada" (não mostra no terminal).

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

echo "Zona direta criada: /var/named/${DOMINIO}.db"
sleep 0.5

# 10 - Criar ficheiro de zona inversa (Reverse Zone)
# O que faz: Cria o ficheiro que resolve endereços IP para nomes de domínio (IP -> nome).

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

# Explicação adicional dos registos PTR:
# - PTR: Pointer Record - associa um endereço IP a um nome de domínio.
# - ${OCTETO_4}: Último octeto do IP do servidor DNS.

echo "Zona inversa criada: /var/named/${OCTETO_3}.${OCTETO_2}.${OCTETO_1}.db"
sleep 0.5
echo ""

# ----------------------------------------------------
# 11 - Configurar named.conf (ficheiro principal do BIND)
# O que faz: Cria o ficheiro de configuração principal do servidor BIND com todas as opções necessárias.
# ----------------------------------------------------

echo ""
echo "CONFIGURAÇÃO DO BIND"
echo ""

sudo tee /etc/named.conf >/dev/null << EOF
// named.conf do servidor autoritativo e de caching
options {
    listen-on port 53 { any; };
    listen-on-v6 port 53 { none; };
    directory   "/var/named";
    dump-file   "/var/named/data/cache_dump.db";
    statistics-file "/var/named/data/named_stats.txt";
    memstatistics-file "/var/named/data/named_mem_stats.txt";
    allow-query     { any; };

    // ------------------------------------------------------------------
    // CONFIGURAÇÃO DO FORWARDER (Usamos 8.8.8.8 para garantir conectividade)
    // ------------------------------------------------------------------
    forwarders { 
        8.8.8.8;
    };
    forward only; // Garante que o BIND só usa o forwarder para consultas externas
    // ------------------------------------------------------------------

    recursion yes; // Permite a recursão de clientes

    /* CORREÇÃO: Removido DNSSEC obsoleto */

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
    category queries { default_log; }; // Logging de consultas ativado
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
sleep 1

# ----------------------------------------------------
# 12 - Adicionar zonas personalizadas ao named.conf
# O que faz: Adiciona as definições das zonas direta e inversa ao ficheiro de configuração.
# ----------------------------------------------------

echo "A adicionar zonas personalizadas ao named.conf..."

# O que faz o -a: Anexa (append) conteúdo ao ficheiro sem sobrescrever o que já existe.
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
sleep 1

# ----------------------------------------------------
# 13 - Criar diretório para logs do BIND
# O que faz: Cria a estrutura de diretórios para armazenar os logs de consultas DNS.
# ----------------------------------------------------

echo "A criar diretório de logs..."

# O que faz o mkdir -p: Cria o diretório (e diretórios pais se não existirem).
sudo mkdir -p /var/log/named

# O que faz o chown: Change owner - muda o proprietário do diretório.
# O que faz o named:named: Define o utilizador "named" e grupo "named" como proprietários.
# Porquê: O serviço BIND corre com o utilizador "named", que precisa de escrever nos logs.
sudo chown named:named /var/log/named

# O que faz o chmod 755: Define permissões - dono pode ler/escrever/executar, outros podem ler/executar.
sudo chmod 755 /var/log/named

echo "Diretório de logs criado."
sleep 1
echo ""

# ----------------------------------------------------
# 14 - Definir permissões dos ficheiros de zona
# O que faz: Altera o proprietário dos ficheiros de zona para o utilizador "named".
# Porquê: O BIND precisa de ter acesso de leitura a estes ficheiros para funcionar.
# ----------------------------------------------------

echo "A definir permissões dos ficheiros de zona..."

sudo chown named:named /var/named/${DOMINIO}.db
sudo chown named:named /var/named/${OCTETO_3}.${OCTETO_2}.${OCTETO_1}.db

echo "Permissões definidas."
sleep 1
echo ""

# ----------------------------------------------------
# 15 - Validar configuração do BIND (named.conf)
# O que faz: Verifica se o ficheiro de configuração principal tem erros de sintaxe.
# Porquê: Evita que o BIND falhe ao arrancar devido a erros de configuração.
# ----------------------------------------------------

echo ""
echo "=========================================="
echo "   VALIDAÇÃO DE CONFIGURAÇÕES"
echo "=========================================="
echo ""

echo "A validar named.conf..."

# O que faz o named-checkconf: Ferramenta que valida a sintaxe do ficheiro named.conf.
# O que faz o if ... then ... else: Estrutura condicional baseada no sucesso/falha do comando.
if sudo named-checkconf; then
    echo "named.conf está OK!"
else
    echo "ERRO no named.conf! Verifique a configuração."
    exit 1
fi

sleep 1

# ----------------------------------------------------
# 16 - Validar zona direta
# O que faz: Verifica se o ficheiro de zona direta tem erros de sintaxe ou inconsistências.
# ----------------------------------------------------

echo "A validar zona direta..."

# O que faz o named-checkzone: Ferramenta que valida a sintaxe e integridade de ficheiros de zona.
if sudo named-checkzone ${DOMINIO} /var/named/${DOMINIO}.db; then
    echo "Zona direta está OK!"
else
    echo "ERRO na zona direta! Verifique o ficheiro."
    exit 1
fi

sleep 1

# ----------------------------------------------------
# 17 - Validar zona inversa
# O que faz: Verifica se o ficheiro de zona inversa tem erros de sintaxe ou inconsistências.
# ----------------------------------------------------

echo "A validar zona inversa..."

if sudo named-checkzone ${REVERSE_ZONE_ID} /var/named/${OCTETO_3}.${OCTETO_2}.${OCTETO_1}.db; then
    echo "Zona inversa está OK!"
else
    echo "ERRO na zona inversa! Verifique o ficheiro."
    exit 1
fi

sleep 1
echo ""

# ----------------------------------------------------
# 18 - Configurar firewall
# O que faz: Adiciona regras à firewall para permitir tráfego DNS (porta 53 TCP/UDP).
# Porquê: Sem esta regra, os clientes não conseguem fazer consultas DNS ao servidor.
# ----------------------------------------------------

echo ""
echo "=========================================="
echo "   CONFIGURAÇÃO DA FIREWALL"
echo "=========================================="
echo ""

echo "A configurar firewall..."

# O que faz o firewall-cmd: Ferramenta de gestão da firewall (firewalld) no CentOS/RHEL.
# O que faz o --permanent: Torna a regra permanente (persiste após reboot).
# O que faz o --add-service=dns: Permite tráfego para o serviço DNS (porta 53 TCP e UDP).
sudo firewall-cmd --permanent --add-service=dns

# O que faz o --reload: Recarrega as regras da firewall para aplicar as mudanças imediatamente.
sudo firewall-cmd --reload

echo "Firewall configurada com sucesso!"
sleep 1
echo ""

# ----------------------------------------------------
# 19 - Iniciar e habilitar o serviço BIND
# O que faz: Inicia o servidor DNS BIND e configura-o para arrancar automaticamente no boot.
# ----------------------------------------------------

echo ""
echo "INICIALIZAÇÃO DO SERVIÇO"
echo ""

echo "A iniciar serviço BIND..."

# O que faz o systemctl enable --now: Habilita o serviço (auto-start) e inicia-o imediatamente.
# O que faz o named: Nome do serviço BIND no systemd.
sudo systemctl enable --now named

sleep 1

# O que faz o systemctl status: Mostra o estado atual do serviço (ativo, inativo, erros).
sudo systemctl status named

echo ""
echo "DNS CONFIGURADO COM SUCESSO!"
echo ""
sleep 1

# ----------------------------------------------------
# 21 - Menu de gestão de registos DNS
# O que faz: Permite adicionar ou consultar registos DNS após a instalação inicial.
# ----------------------------------------------------

echo ""
echo "Deseja adicionar ou consultar registos no DNS? (s/n): "
read -p "Resposta: " GERIR_REGISTOS

if [[ "$GERIR_REGISTOS" == "s" || "$GERIR_REGISTOS" == "S" ]]; then
    
    # Loop do menu principal
    # O que faz: Mantém o menu ativo até o utilizador escolher sair.
    while true; do
        echo ""
        echo "=========================================="
        echo "   GESTÃO DE REGISTOS DNS"
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
                # ----------------------------------------------------
                # Adicionar registo à zona direta (A Record)
                # O que faz: Adiciona um novo nome de host que aponta para um IP.
                # ----------------------------------------------------
                
                echo ""
                echo "--- Adicionar Nome para IP (zona direta) ---"
                echo ""
                read -p "Nome do host (ex: pc1, servidor, router): " NOME_HOST
                read -p "Endereço IP (ex: 192.168.1.20): " IP_HOST
                
                # Validar se o IP está na mesma rede
                # O que faz: Extrai os primeiros 3 octetos do IP fornecido e compara com o IP do servidor.
                IP_REDE_HOST=$(echo "$IP_HOST" | cut -d'.' -f1-3)
                IP_REDE_SERVIDOR=$(echo "$IP_SERVIDOR_DNS" | cut -d'.' -f1-3)
                
                if [[ "$IP_REDE_HOST" != "$IP_REDE_SERVIDOR" ]]; then
                    echo ""
                    echo "AVISO: O IP $IP_HOST não está na mesma rede que o servidor ($IP_REDE_SERVIDOR.0/24)!"
                    read -p "Deseja continuar mesmo assim? (s/n): " CONTINUAR
                    if [[ "$CONTINUAR" != "s" && "$CONTINUAR" != "S" ]]; then
                        echo "Operação cancelada."
                        continue
                    fi
                fi
                
                # Incrementar o serial da zona
                # O que faz: Atualiza o número de série para que outros servidores DNS saibam que a zona mudou.
                NOVO_SERIAL=$(date +%s)
                
                # O que faz o sed: Stream editor - ferramenta para procurar e substituir texto em ficheiros.
                # O que faz o -i: Edita o ficheiro diretamente (in-place).
                # O que faz o "s/ANTIGO/NOVO/": Substitui a primeira ocorrência de ANTIGO por NOVO.
                sudo sed -i "s/${SERIAL_DATE}/${NOVO_SERIAL}/" /var/named/${DOMINIO}.db
                SERIAL_DATE=$NOVO_SERIAL
                
                # Adicionar o registo A ao ficheiro de zona
                # O que faz: Anexa uma nova linha ao ficheiro com o registo DNS tipo A.
                echo "${NOME_HOST}  IN  A       ${IP_HOST}" | sudo tee -a /var/named/${DOMINIO}.db >/dev/null
                
                echo ""
                echo "Registo adicionado com sucesso!"
                echo "${NOME_HOST}.${DOMINIO} → ${IP_HOST}"
                
                # Validar a zona após alteração
                if sudo named-checkzone ${DOMINIO} /var/named/${DOMINIO}.db >/dev/null 2>&1; then
                    # O que faz o rndc reload: Recarrega as zonas DNS sem reiniciar o serviço BIND.
                    sudo rndc reload
                    echo "Zona recarregada com sucesso!"
                else
                    echo "ERRO: Zona direta inválida após alteração!"
                    echo "A reverter alterações..."
                    # Remover a última linha adicionada em caso de erro
                    sudo sed -i '$ d' /var/named/${DOMINIO}.db
                fi
                
                sleep 1
                ;;
                
            2)
                # ----------------------------------------------------
                # Adicionar registo à zona inversa (PTR Record)
                # O que faz: Adiciona um registo que permite resolver IP para nome.
                # ----------------------------------------------------
                
                echo ""
                echo "--- Adicionar IP para Nome (zona inversa) ---"
                echo ""
                read -p "Último octeto do IP (ex: para 192.168.1.20, digite 20): " ULTIMO_OCTETO
                read -p "Nome completo do host (ex: pc1.${DOMINIO}): " NOME_COMPLETO
                
                # Adicionar ponto final se não existir
                # O que faz: Garante que o FQDN (Fully Qualified Domain Name) termina com ponto.
                # Porquê: No DNS, um ponto final indica um nome absoluto.
                if [[ ! "$NOME_COMPLETO" =~ \.$ ]]; then
                    NOME_COMPLETO="${NOME_COMPLETO}."
                fi
                
                # Incrementar o serial da zona inversa
                NOVO_SERIAL=$(date +%s)
                sudo sed -i "s/${SERIAL_DATE}/${NOVO_SERIAL}/" /var/named/${OCTETO_3}.${OCTETO_2}.${OCTETO_1}.db
                SERIAL_DATE=$NOVO_SERIAL
                
                # Adicionar o registo PTR ao ficheiro de zona inversa
                echo "${ULTIMO_OCTETO}  IN  PTR   ${NOME_COMPLETO}" | sudo tee -a /var/named/${OCTETO_3}.${OCTETO_2}.${OCTETO_1}.db >/dev/null
                
                echo ""
                echo "Registo inverso adicionado com sucesso!"
                echo "  ${OCTETO_1}.${OCTETO_2}.${OCTETO_3}.${ULTIMO_OCTETO} → ${NOME_COMPLETO}"
                
                # Validar a zona inversa após alteração
                if sudo named-checkzone ${REVERSE_ZONE_ID} /var/named/${OCTETO_3}.${OCTETO_2}.${OCTETO_1}.db >/dev/null 2>&1; then
                    sudo rndc reload
                    echo "Zona inversa recarregada com sucesso!"
                else
                    echo "ERRO: Zona inversa inválida após alteração!"
                    echo "  A reverter alterações..."
                    sudo sed -i '$ d' /var/named/${OCTETO_3}.${OCTETO_2}.${OCTETO_1}.db
                fi
                
                sleep 1
                ;;
                
            3)
                # ----------------------------------------------------
                # Ver registos existentes
                # O que faz: Mostra os registos DNS atualmente configurados nas zonas.
                # ----------------------------------------------------
                
                echo ""
                echo "=========================================="
                echo "   REGISTOS EXISTENTES"
                echo "=========================================="
                echo ""
                echo "--- Zona Direta (${DOMINIO}) ---"
                # O que faz o grep -v "^;": Filtra linhas que começam com ; (comentários).
                # O que faz o grep -v "^$": Filtra linhas vazias.
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
                sleep 1
                ;;
        esac
    done
fi

# ----------------------------------------------------
# 22 - Menu de verificações opcionais
# O que faz: Oferece ao utilizador opções para testar o servidor DNS configurado.
# ----------------------------------------------------

echo ""
echo "Deseja executar verificações finais? (y/n): "
read -p "Resposta: " FAZER_VERIFICACOES

if [[ "$FAZER_VERIFICACOES" == "y" || "$FAZER_VERIFICACOES" == "Y" ]]; then
    echo ""
    echo "1) Testar resolução direta (nome -> IP);"
    echo "2) Testar resolução inversa (IP -> nome);"
    echo "3) Ver status do serviço;"
    echo "4) Testar conectividade Internet;"
    echo "5) Sair."
    echo ""
    read -p "Escolha uma opção (1-5): " OPCAO_VERIFICACAO_DNS

    # O que faz o case: Estrutura de controlo que compara uma variável com vários padrões e executa código correspondente.
    case $OPCAO_VERIFICACAO_DNS in
        1)
            echo ""
            echo "--- Teste de Resolução Direta ---"
            # O que faz o dig: Ferramenta de query DNS que consulta registos DNS.
            dig ${DOMINIO}
            dig ns.${DOMINIO}
            ;;
        2)
            echo ""
            echo "--- Teste de Resolução Inversa ---"
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
            # O que faz: Testa se o forwarder 8.8.8.8 está a funcionar corretamente.
            dig google.com
            ;;
        5)
            echo ""
            echo "A sair sem verificações."
            ;;
        *)
            echo ""
            echo "Opção inválida. A sair sem verificações."
            ;;
    esac
fi

# O que faz o esac: Finaliza a estrutura case (é "case" escrito ao contrário).

echo ""
echo "=========================================="
echo "   COMANDOS ÚTEIS PARA O FUTURO"
echo "=========================================="
echo ""
echo "- Testar DNS interno: dig ${DOMINIO}"
echo "- Testar Internet: dig google.com"
echo "- Ver logs: tail -f /var/log/named/bind_queries.log"
echo "- Status: systemctl status named"
echo "- Reiniciar BIND: sudo systemctl restart named"
echo ""
echo "Script concluído. O servidor DNS está pronto a usar!"