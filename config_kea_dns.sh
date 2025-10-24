#!/bin/bash
# Devido a limitações de conhecimento, este programa vai operar unicamente sobre um CIDR /24. Esperamos, no futuro, alargar a escolha.

#
# =========================================================================================#
#
# Projeto: Automatização da Configuração de um Servidor DHCP (KEA) / DNS (BIND) (Classe C)
# Autor: Sérgio Correia
# Data: 24 10 2025
#
# Descrição:
# Este script automatiza a instalação e configuração de serviços de rede essenciais, tais como 
# DHCP (usando KEA) e DNS (usando BIND) em sistemas baseados em CentOS Stream 10. 
#
# O que é DHCP KEA:
# O KEA DHCP é um servidor DHCP moderno e flexível desenvolvido pela Internet Systems Consortium (ISC).
# Ele oferece funcionalidades avançadas, como suporte a IPv4 e IPv6, alta performance, e uma arquitetura modular.
#
# O que é BIND: 
# BIND (Berkeley Internet Name Domain) é um dos servidores DNS mais utilizados no mundo. 
# Serve para traduzir nomes de domínio em endereços IP, permitindo que os utilizadores acedam a recursos
# usando nomes amigáveis em vez de números.
#
# =========================================================================================#
#

# ======================================================
# 0 - Menu Principal
# ======================================================

# O que faz: Apresenta um menu ao utilizador para escolher entre instalar apenas DNS, apenas DHCP, ambos ou sair.
# O que faz o read -p: Exibe uma mensagem ao utilizador e lê a entrada fornecida, armazenando-a na variável OPCAO.
# O que faz o case: Estrutura de controle que executa diferentes blocos de código com base na escolha do utilizador.

echo ""
echo "1) Instalar apenas DNS (BIND);"
echo "2) Instalar apenas DHCP (KEA);"
echo "3) Instalar ambos (DNS + DHCP integrados);"
echo "4) Sair."
echo "-----------------------------------------------"
read -p "Escolha uma opção (1-4): " OPCAO

# O que faz: Usa uma estrutura case para executar diferentes blocos de código com base na escolha do utilizador.
# O que faz o ;;: Termina cada caso do switch case (equivalente ao break em outras linguagens).
# O que faz o *): Caso padrão que captura qualquer entrada inválida.
# O que faz o esac: Fecha a estrutura case (é "case" ao contrário).

case $OPCAO in

# ======================================================
# 1 - OPÇÃO 1 - Apenas DNS (BIND)
# ======================================================

1)
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
    read -p "Introduza o IP do servidor de Classe C (ex: 192.168.1.10): " IP_SERVIDOR_DNS

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
    SERIAL_DATE=$(date +%s)

    echo ""
    echo "Domínio: $DOMINIO"
    echo "IP Servidor DNS: $IP_SERVIDOR_DNS"
    echo "Zona Reversa: $REVERSE_ZONE_ID"
    echo ""

    # 4 - Criar ficheiro de zona direta (Forward Zone)
    # O que faz: Cria o ficheiro de zona DNS que resolve nomes para IPs (ex: empresa.local -> 192.168.1.10).

    # O que faz o sudo tee: Permite escrever múltiplas linhas em ficheiros que requerem privilégios de superutilizador.
    # O que faz o >/dev/null: Redireciona a saída para "nada" (não mostra conteúdo duplicado no terminal).
    # O que faz o << EOF: Inicia um "here document" que permite escrever múltiplas linhas até encontrar EOF.
    # O que faz o \$TTL: Time To Live - tempo em segundos que o registo pode ser guardado em cache.
    # O que faz o SOA: Start of Authority - registo que define a autoridade da zona.
    # O que faz o NS: Name Server - indica qual é o servidor DNS autoritativo.
    # O que faz o A: Address - mapeia um nome para um endereço IPv4.

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
    # O que faz o @127.0.0.1: Especifica que a query deve ser feita ao servidor DNS local, ou localhost.

    echo "Deseja executar verificações? (opcional)"
    echo "1) Testar resolução direta (nome -> IP);"
    echo "2) Testar resolução inversa (IP -> nome);"
    echo "3) Ver status do serviço;"
    echo "4) Sair."
    echo ""
    read -p "Escolha uma opção (1-4): " OPCAO_VERIFICACAO_DNS

    case $OPCAO_VERIFICACAO_DNS in
        1)
            # O que faz: Testa se o DNS consegue resolver o domínio para o IP.
            # O que faz o dig: Ferramenta de query DNS que testa resolução de nomes.

            echo ""
            echo "--- Teste de Resolução Direta ---"
            dig ${DOMINIO}
            ;;
        2)
            # O que faz: Testa se o DNS consegue resolver o IP para o nome (reverse lookup).
            # O que faz o -x: Opção do dig que faz resolução inversa.

            echo ""
            echo "--- Teste de Resolução Inversa ---"
            dig -x ${IP_SERVIDOR_DNS}
            ;;
        3)
            # O que faz: Mostra o estado atual do serviço BIND.
            echo ""
            echo "--- Status do Serviço BIND ---"

            # O que faz o sudo systemctl status named: Comando que exibe o status do serviço named (BIND).

            sudo systemctl status named
            ;;
        4)
            # O que faz: Sai do menu sem executar verificações.

            echo ""
            echo "A sair sem verificações."
            ;;
        *)
            # O que faz: Caso padrão para entradas inválidas.

            echo ""
            echo "Opção inválida. A sair sem verificações."
            ;;
    
    # O que faz o esac: Fecha a estrutura case (é "case" ao contrário).

    esac

    echo ""
    echo "Comandos úteis para o futuro:"
    echo "- Testar DNS: dig ${DOMINIO}"
    echo "- Ver logs: tail -f /var/log/messages"
    echo "- Status: systemctl status named"
    echo ""
    ;;

# ======================================================
# 2 - OPÇÃO 2 - Apenas DHCP (KEA)
# ======================================================

2)
    echo ""
    echo "=========================================="
    echo "   INSTALAÇÃO: DHCP (KEA)"
    echo "=========================================="
    echo ""

    # 1 - Perguntar pelo IP de DNS
    # O que faz: Solicita ao utilizador o IP do servidor DNS a ser usado pelos clientes DHCP.
    # O que faz o read -p: Exibe uma mensagem e aguarda entrada do utilizador.

    read -p "Inserir o IP de DNS (8.8.8.8 ou 1.1.1.1): " IP_DNS

    # 2 Instalação do KEA DHCP4
    # O que faz: Instala o servidor DHCP KEA usando o gestor de pacotes DNF.
    # O que faz o -y: Responde "sim" automaticamente a todas as perguntas durante a instalação.

    echo "A instalar KEA DHCP4..."
    sudo dnf install -y kea-dhcp4

    # 3 - Criação do backup config
    # O que faz: Cria uma cópia de segurança do ficheiro de configuração original do KEA DHCP4.
    # O que faz o -f: Verifica se o ficheiro especificado existe.
    # O que faz o -e: Verifica se o ficheiro ou diretório especificado existe.
    # O que faz o !: Operador de negação (verifica se NÃO existe).

    if [ -f /etc/kea/kea-dhcp4.conf ] && [ ! -e /etc/kea/kea-dhcp4.conf.backup ]; then
        sudo cp /etc/kea/kea-dhcp4.conf /etc/kea/kea-dhcp4.conf.backup
    fi

    # 4 - Validação do IP da Máquina
    # O que faz: Solicita ao utilizador o IP do servidor DHCP e valida se está no formato correto.

    # O que faz o while true: Loop infinito que só termina com break.
    # O que faz o =~: Operador de correspondência regex em bash.
    # O que faz o ^: Indica o início da string na regex.
    # O que faz o $: Indica o fim da string na regex.
    # O que faz o \.: Escapa o ponto na regex para que seja interpretado literalmente.
    # O que faz o [0-9]{1,3}: Corresponde a 1-3 dígitos.
    # O que faz o (( ... )): Permite operações aritméticas e comparações numéricas.
    # O que faz o break: Sai do loop quando um IP válido é inserido.
    # O que faz o continue: Retorna ao início do loop para solicitar nova entrada.

    while true; do
        read -p "Digite o IP desejado para o Servidor (Inserir unicamente IPs de Classe C): " IP_SERVIDOR

        TERCEIRO_OCTETO=$(echo "$IP_SERVIDOR" | cut -d'.' -f3)
        QUARTO_OCTETO=$(echo "$IP_SERVIDOR" | cut -d'.' -f4)

        if [[ ! $IP_SERVIDOR =~ ^192\.168\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
            echo "Erro 1! IP deve começar com 192.168.x.x."
        elif (( TERCEIRO_OCTETO < 1 || TERCEIRO_OCTETO > 254 )); then
            echo "Erro 2! O 3º octeto deve estar entre 1 e 254."
        elif (( QUARTO_OCTETO < 2 || QUARTO_OCTETO >= 254 )); then
            echo "Erro 3! O 4º octeto deve estar entre 2 e 253."
        else
            echo "IP válido!"
            break
        fi
    done

    # 5 - Inserção e validação de IPs
    # O que faz: Solicita ao utilizador os IPs necessários (Range DHCP, Gateway e DNS) e valida-os.

    # O que faz o VERIFICACAO="": Inicializa a variável de verificação vazia.
    # O que faz o [ "$VERIFICACAO" != "y" ]: Verifica se a resposta não é "y" ou "Y".
    # O que faz o &&: Operador lógico "E" que combina condições.

    VERIFICACAO=""
    while [ "$VERIFICACAO" != "y" ] && [ "$VERIFICACAO" != "Y" ]; do

        # 5.1 - Solicitar o escopo de IPs
        # O que faz: Pede ao utilizador apenas o 4º octeto do range e gateway.

        read -p "Qual vai ser o início do range DHCP (4º octeto)? " OCTETO_INICIO_RANGE
        read -p "Qual vai ser o fim do range DHCP (4º octeto)? " OCTETO_FIM_RANGE
        read -p "Inserir o 4º octeto do IP de Gateway (1 ou 254): " OCTETO_IP_GATEWAY

        # 5.2 - Extrair a subrede do servidor
        # O que faz: Usa o cut para extrair os primeiros três octetos do IP do servidor.
        # O que faz o cut -d'.' -f1-3: Extrai campos 1 a 3 usando ponto como delimitador.

        IP_SUBNET_SERVIDOR_C=$(echo "$IP_SERVIDOR" | cut -d'.' -f1-3)

        # 5.3 - Criar IPs completos
        # O que faz: Concatena a sub-rede com os octetos fornecidos para formar IPs completos.
        # O que faz o ${VARIAVEL}: Sintaxe de expansão de variável em bash.

        IP_RANGE_INICIO="${IP_SUBNET_SERVIDOR_C}.${OCTETO_INICIO_RANGE}"
        IP_RANGE_FIM="${IP_SUBNET_SERVIDOR_C}.${OCTETO_FIM_RANGE}"
        IP_GATEWAY="${IP_SUBNET_SERVIDOR_C}.${OCTETO_IP_GATEWAY}"
        IP_REDE="${IP_SUBNET_SERVIDOR_C}.0"
        IP_BROADCAST="${IP_SUBNET_SERVIDOR_C}.255"

        # 5.4 - Validação do IP da Gateway
        # O que faz: Verifica se o 4º octeto do gateway é 1 ou 254.
        # O que faz o [[ ... ]]: Testa expressões condicionais (forma moderna).
        # O que faz o !=: Operador de desigualdade.
        # O que faz o continue: Volta ao início do loop se houver erro.

        if [[ "$OCTETO_IP_GATEWAY" != "1" && "$OCTETO_IP_GATEWAY" != "254" ]]; then
            echo "Erro 4! O IP do Gateway só deve ser 1 ou 254."
            continue
        fi

        # 5.5 - Validação do IP de DNS
        # O que faz: Verifica se o DNS é um dos endereços públicos aceites.

        if [[ "$IP_DNS" != "8.8.8.8" && "$IP_DNS" != "1.1.1.1" ]]; then
            echo "Erro 5! O IP de DNS só pode ser 8.8.8.8 (Google) ou 1.1.1.1 (Cloudflare)."
            continue
        fi

        # 5.6 - Validação do Range DHCP
        # O que faz: Verifica se o início do range é menor que o fim.
        # O que faz o >=: Operador "maior ou igual".

        if (( OCTETO_INICIO_RANGE >= OCTETO_FIM_RANGE )); then
            echo "Erro 6! Início do range deve ser menor que o fim."
            continue
        fi

        # 5.7 - Validação do IP do Servidor vs Range
        # O que faz: Verifica se o IP do servidor não está dentro do range DHCP.

        QUARTO_OCTETO_SERVIDOR=$(echo "$IP_SERVIDOR" | cut -d'.' -f4)
        if (( QUARTO_OCTETO_SERVIDOR >= OCTETO_INICIO_RANGE && QUARTO_OCTETO_SERVIDOR <= OCTETO_FIM_RANGE )); then
            echo "Erro 7! O IP do Servidor não pode estar dentro do range DHCP."
            continue
        fi

        # 5.8 - Barra de progresso
        # O que faz: Exibe uma barra de progresso visual antes do resumo.
        # O que faz o echo -n: Imprime sem adicionar nova linha.
        # O que faz o {1..40}: Expansão de sequência que gera números de 1 a 40.
        # O que faz o sleep: Pausa a execução por um tempo especificado em segundos.

        echo -n "[ "
        for i in {1..40}; do
            echo -n "="
            sleep 0.05
        done
        echo " ]"

        # 5.9 - Mostrar resumo
        # O que faz: Exibe um resumo dos IPs configurados para confirmação.

        echo "Resumo dos IPs configurados:"
        echo "IP Servidor: $IP_SERVIDOR"
        echo "Range DHCP: $IP_RANGE_INICIO - $IP_RANGE_FIM"
        echo "IP Gateway: $IP_GATEWAY"
        echo "IP DNS: $IP_DNS"
        echo "IP Broadcast: $IP_BROADCAST"
        echo "IP de Rede: $IP_REDE"

        # 5.10 - Confirmação final
        # O que faz: Pede confirmação ao utilizador sobre os IPs inseridos.

        read -p "Validação básica concluída! Está tudo correto? (y/n): " VERIFICACAO
    done

    echo "Verificação concluída!"
    echo "Aguarde enquanto aplicamos as definições!"

    # 6 - Barra de progresso final
    # O que faz: Exibe uma barra de progresso antes de aplicar as configurações.

    echo -n "[ "
    for i in {1..40}; do
        echo -n "="
        sleep 0.05
    done
    echo " ]"
    echo " Feito!"

    # 7 - Deteção e Configuração da Placa de Rede
    # O que faz: Deteta automaticamente a interface de rede ativa.

    # O que faz o nmcli: NetworkManager Command Line Interface.
    # O que faz o -t: Formato tabular (sem cabeçalhos).
    # O que faz o -f DEVICE: Mostra apenas a coluna DEVICE.
    # O que faz o --active: Lista apenas conexões ativas.
    # O que faz o head -n1: Pega a primeira linha da saída.
    # O que faz o [ -z "$INTERFACE" ]: Verifica se a variável está vazia.

    INTERFACE=$(nmcli -t -f DEVICE connection show --active | head -n1)

    if [ -z "$INTERFACE" ]; then
        echo "Aviso: Nenhuma interface ativa detetada automaticamente!"
        read -p "Insira o nome da interface manualmente (ex: enp0s3, eth0): " INTERFACE
    else
        echo "Interface de rede detetada: $INTERFACE"
        read -p "Esta é a interface correta? (y/n): " CONFIRMA_INTERFACE
        
        if [[ "$CONFIRMA_INTERFACE" != "y" && "$CONFIRMA_INTERFACE" != "Y" ]]; then
            read -p "Insira o nome da interface manualmente: " INTERFACE
            echo "Interface alterada para: $INTERFACE"
        fi
    fi

    # 8 - Validação final da interface
    # O que faz: Verifica se a interface especificada existe no sistema.
    # O que faz o &>/dev/null: Redireciona stdout e stderr para /dev/null.
    # O que faz o exit 1: Sai do script com código de erro 1.

    if ! nmcli connection show "$INTERFACE" &>/dev/null; then
        echo "Erro: A interface '$INTERFACE' não existe no sistema!"
        echo "Interfaces disponíveis:"
        nmcli connection show
        exit 1
    fi

    echo "A usar interface: $INTERFACE"

    # 9 - Configurar interface de rede
    # O que faz: Define a interface para IP manual e atribui o IP do servidor.
    # O que faz o nmcli connection modify: Modifica configurações da conexão.
    # O que faz o ipv4.method manual: Define método de IP como manual (estático).
    # O que faz o ipv4.addresses: Define o endereço IP e máscara.
    # O que faz o nmcli connection down/up: Desativa e reativa a conexão.

    sudo nmcli connection modify "$INTERFACE" ipv4.method manual
    echo "Placa de rede $INTERFACE alterada para manual."

    sudo nmcli connection modify "$INTERFACE" ipv4.addresses "$IP_SERVIDOR/24"
    echo "IP alterado para $IP_SERVIDOR/24."

    sudo nmcli connection down "$INTERFACE"
    sudo nmcli connection up "$INTERFACE"
    echo "Restart da interface $INTERFACE concluído."

    # 10 - Edição do Config do DHCP (Kea)
    # O que faz: Escreve o ficheiro de configuração JSON do Kea DHCPv4.
    # O que faz o sudo tee: Permite escrever em ficheiros que requerem privilégios.
    # O que faz o >/dev/null: Suprime a saída duplicada no terminal.
    # O que faz o << DHCP: Inicia here document até encontrar DHCP.
    # O que faz o interfaces-config: Define interfaces que o Kea irá escutar.
    # O que faz o lease-database: Configura armazenamento de leases.
    # O que faz o valid-lifetime: Tempo de vida dos leases em segundos.
    # O que faz o option-data: Define opções DHCP para os clientes.
    # O que faz o subnet4: Define a sub-rede e pools de IPs.
    # O que faz o loggers: Configura o sistema de logging.

    sudo tee /etc/kea/kea-dhcp4.conf >/dev/null << DHCP
{
  "Dhcp4": {
    "interfaces-config": { "interfaces": [ "0.0.0.0" ] },
    "lease-database": {
      "type": "memfile",
      "lfc-interval": 3600
    },
    "valid-lifetime": 7200,
    "renew-timer": 1800,
    "rebind-timer": 3600,
    "option-data": [
      { "name": "domain-name-servers", "data": "${IP_DNS}" },
      { "name": "domain-name", "data": "${DOMINIO}" },
      { "name": "routers", "data": "${IP_GATEWAY}" },
      { "name": "subnet-mask", "data": "255.255.255.0" },
      { "name": "broadcast-address", "data": "${IP_BROADCAST}" }
    ],
    "subnet4": [
      {
        "subnet": "${IP_REDE}/24",
        "pools": [ { "pool": "${IP_RANGE_INICIO} - ${IP_RANGE_FIM}" } ],
        "reservations": [
          {
            "hw-address": "$(ip link show ${INTERFACE} | grep -i ether | awk '{print $2}')",
            "ip-address": "${IP_SERVIDOR}",
            "hostname": "server.${DOMINIO}"
          }
        ]
      }
    ],
    "loggers": [
      {
        "name": "kea-dhcp4",
        "output_options": [
          {
            "output": "/var/log/kea-dhcp4.log",
            "pattern": "%D{%Y-%m-%d %H:%M:%S.%q} %-5p [%c] %m\n",
            "flush": true,
            "maxsize": 10240000,
            "maxver": 3
          }
        ],
        "severity": "INFO",
        "debuglevel": 0
      }
    ]
  }
}
DHCP

    # 11 - Configurar firewall
    # O que faz: Adiciona permanentemente o serviço DHCP às regras do firewall.
    # O que faz o --permanent: Torna a regra permanente (persiste após reboot).
    # O que faz o --add-service=dhcp: Permite tráfego DHCP (porta 67/68 UDP).
    # O que faz o systemctl restart: Reinicia o serviço para aplicar mudanças.

    echo "A configurar firewall..."
    sudo firewall-cmd --permanent --add-service=dhcp
    sudo systemctl restart firewalld

    # 12 - Validar e iniciar serviço KEA
    # O que faz: Testa a configuração do KEA antes de iniciar o serviço.
    # O que faz o kea-dhcp4 -t: Testa o ficheiro de configuração sem iniciar o serviço.
    # O que faz o systemctl enable --now: Habilita e inicia o serviço imediatamente.
    # O que faz o systemctl restart: Reinicia o serviço.
    # O que faz o systemctl status: Mostra o estado atual do serviço.

    echo "A validar e iniciar KEA DHCP4..."
    sudo kea-dhcp4 -t /etc/kea/kea-dhcp4.conf
    sudo systemctl enable --now kea-dhcp4
    sudo systemctl restart kea-dhcp4
    sudo systemctl status kea-dhcp4

    echo ""
    echo "DHCP configurado com sucesso!"
    echo ""

    # 13 - Menu de verificações para DHCP
    # O que faz: Apresenta um menu ao utilizador com opções para verificar o DHCP.

    echo "Deseja executar verificações finais?"
    echo "1) Verificar status do serviço;"
    echo "2) Ver leases atribuídos;"
    echo "3) Ver últimas linhas do log;"
    echo "4) Sair."
    echo ""
    read -p "Escolha uma opção (1-4): " OPCAO_VERIFICACAO

    # O que faz o case: Estrutura de controlo que compara uma variável com vários padrões.
    # O que faz cada opção do menu:
    # Opção 1: Mostra o status do serviço KEA DHCP4.
    # Opção 2: Lista os leases atribuídos pelo servidor DHCP.
    # Opção 3: Mostra as últimas 10 linhas do ficheiro de log.
    # Opção 4: Sai do menu sem executar verificações.

    case $OPCAO_VERIFICACAO in
        1)
            # O que faz: Mostra o estado atual do serviço KEA DHCP4.

            echo ""
            echo "--- Status do Serviço Kea DHCP4 ---"
            sudo systemctl status kea-dhcp4
            ;;
        2)
            # O que faz: Lista os leases atribuídos pelo servidor DHCP.

            # O que faz o [ -f ... ]: Verifica se o ficheiro existe.
            # O que faz o cat: Mostra o conteúdo do ficheiro.

            echo ""
            echo "--- Leases Atribuídos ---"
            if [ -f /var/lib/kea/kea-leases4.csv ]; then
                cat /var/lib/kea/kea-leases4.csv
            else
                echo "Ainda não existem leases atribuídos."
            fi
            ;;
        3)
            # O que faz: Mostra as últimas 10 linhas do ficheiro de log.

            # O que faz o tail -n 10: Mostra as últimas 10 linhas de um ficheiro.

            echo ""
            echo "--- Últimas 10 linhas do Log ---"
            if [ -f /var/log/kea-dhcp4.log ]; then
                tail -n 10 /var/log/kea-dhcp4.log
            else
                echo "Ficheiro de log ainda não existe."
            fi
            ;;
        4)
            # O que faz: Sai do menu sem executar verificações.

            echo ""
            echo "A sair sem verificações."
            ;;
        *)
            # O que faz: Caso padrão para entradas inválidas.

            echo ""
            echo "Opção inválida. A sair sem verificações."
            ;;

    # O que faz o esac: Fecha a estrutura case (é "case" ao contrário).

    esac

    echo ""
    echo "Comandos úteis para o futuro:"
    echo "- Ver leases: cat /var/lib/kea/kea-leases4.csv"
    echo "- Ver logs: tail -f /var/log/kea-dhcp4.log"
    echo "- Status: systemctl status kea-dhcp4"
    echo ""
    echo "Recomenda-se um reboot do sistema para garantir que todas as alterações tenham efeito."
    echo "Para reiniciar o sistema, execute: reboot"
    ;;

# ======================================================
# 3 - OPÇÃO 3 - DNS + DHCP
# ======================================================

3)
    echo ""
    echo "=========================================="
    echo "   INSTALAÇÃO: DNS + DHCP"
    echo "=========================================="
    echo ""

    # 1 - Instalação do BIND
    # O que faz: Instala o servidor DNS BIND primeiro.

    # O que faz o dnf install -y: Instala pacotes sem pedir confirmação.
    # O que faz o yum: Gestor de pacotes para distribuições baseadas em Red Hat (substituído pelo dnf em versões mais recentes).
    # O que faz o -y: Responde "sim" automaticamente a todas as perguntas durante a instalação. - YES

    echo "A instalar BIND..."
    sudo dnf install -y bind bind-utils

    # 2 - Solicitar informações do domínio e IP
    # O que faz: Pede ao utilizador o domínio e IP que será usado tanto para DNS como DHCP.

    echo ""
    read -p "Introduza o domínio (ex: empresa.local): " DOMINIO
    read -p "Introduza o IP do servidor (ex: 192.168.1.10): " IP_SERVIDOR

    # 3 - Extrair octetos do IP
    # O que faz: Divide o IP em octetos para criar zonas DNS e configurar DHCP.

    OCTETO_1=$(echo "$IP_SERVIDOR" | cut -d'.' -f1)
    OCTETO_2=$(echo "$IP_SERVIDOR" | cut -d'.' -f2)
    OCTETO_3=$(echo "$IP_SERVIDOR" | cut -d'.' -f3)
    OCTETO_4=$(echo "$IP_SERVIDOR" | cut -d'.' -f4)
    REVERSE_ZONE_ID="${OCTETO_3}.${OCTETO_2}.${OCTETO_1}.in-addr.arpa"
    SERIAL_DATE=$(date +%s)

    echo ""
    echo "Domínio: $DOMINIO"
    echo "IP Servidor: $IP_SERVIDOR"
    echo "Zona Reversa: $REVERSE_ZONE_ID"
    echo ""

    # 4 - Criar zona direta
    # O que faz: Cria o ficheiro de zona DNS direta.

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
ns  IN  A       ${IP_SERVIDOR}
@   IN  A       ${IP_SERVIDOR}
EOF

    # 5 - Criar zona inversa
    # O que faz: Cria o ficheiro de zona DNS inversa.

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
    # O que faz: Adiciona as zonas ao ficheiro de configuração do BIND.

    echo "A configurar named.conf..."
    sudo tee -a /etc/named.conf >/dev/null << EOF
options {
    directory "/var/named";
    dump-file "/var/named/data/cache_dump.db";
    statistics-file "/var/named/data/named_stats.txt";
    memstatistics-file "/var/named/data/named_mem_stats.txt";
    
    // Forwarders para resolução externa
    forwarders {
        8.8.8.8;
        1.1.1.1;
    };
    forward only;

    // Configurações básicas de segurança
    allow-query { any; };
    recursion yes;
    dnssec-enable yes;
    dnssec-validation yes;
};

// Configuração de logging
logging {
    channel query_log {
        file "/var/log/named/query.log" versions 3 size 5m;
        severity dynamic;
        print-time yes;
    };
    channel default_debug {
        file "data/named.run";
        severity dynamic;
    };
    category queries { query_log; };
    category default { default_debug; };
};

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
    sudo mkdir -p /var/log/named
    sudo chown named:named /var/log/named
    sudo chmod 755 /var/log/named

    # 7 - Definir permissões
    # O que faz: Altera proprietário dos ficheiros de zona para o utilizador "named".

    echo "A definir permissões..."
    sudo chown named:named /var/named/${DOMINIO}.db
    sudo chown named:named /var/named/${OCTETO_3}.${OCTETO_2}.${OCTETO_1}.db

    # 8 - Validar configurações DNS
    # O que faz: Verifica se as configurações do BIND estão corretas.

    echo "A validar configurações DNS..."
    if sudo named-checkconf; then
        echo "named.conf está OK!"
    else
        echo "ERRO no named.conf!"
        exit 1
    fi

    if sudo named-checkzone ${DOMINIO} /var/named/${DOMINIO}.db; then
        echo "Zona direta está OK!"
    else
        echo "ERRO na zona direta!"
        exit 1
    fi

    if sudo named-checkzone ${REVERSE_ZONE_ID} /var/named/${OCTETO_3}.${OCTETO_2}.${OCTETO_1}.db; then
        echo "Zona inversa está OK!"
    else
        echo "ERRO na zona inversa!"
        exit 1
    fi

    # 9 - Configurar firewall para DNS
    # O que faz: Permite tráfego DNS através do firewall.

    echo "A configurar firewall para DNS..."
    sudo firewall-cmd --permanent --add-service=dns
    sudo firewall-cmd --reload

    # 10 - Iniciar serviço BIND
    # O que faz: Inicia e habilita o serviço BIND.

    echo "A iniciar serviço BIND..."
    sudo systemctl enable --now named

    echo ""
    echo "DNS configurado! IP do DNS: ${IP_SERVIDOR}"
    echo ""

    # 11 - Instalar KEA DHCP4
    # O que faz: Instala o servidor DHCP KEA.

    echo "A instalar KEA DHCP4..."
    sudo dnf install -y kea-dhcp4

    # 12 - Criar backup da configuração KEA
    # O que faz: Faz backup do ficheiro de configuração original.

    if [ -f /etc/kea/kea-dhcp4.conf ] && [ ! -e /etc/kea/kea-dhcp4.conf.backup ]; then
        sudo cp /etc/kea/kea-dhcp4.conf /etc/kea/kea-dhcp4.conf.backup
    fi

    # 13 - Definir IP_DNS como o servidor local
    # O que faz: Define que o DNS a ser distribuído pelo DHCP é o próprio servidor.

    IP_DNS="$IP_SERVIDOR"

    # 14 - Inserção e validação de IPs para DHCP
    # O que faz: Solicita range DHCP e gateway, valida os dados.

    VERIFICACAO=""
    while [ "$VERIFICACAO" != "y" ] && [ "$VERIFICACAO" != "Y" ]; do

        read -p "Qual vai ser o início do range DHCP (4º octeto)? " OCTETO_INICIO_RANGE
        read -p "Qual vai ser o fim do range DHCP (4º octeto)? " OCTETO_FIM_RANGE
        read -p "Inserir o 4º octeto do IP de Gateway (1 ou 254): " OCTETO_IP_GATEWAY

        # 14.1 - Extrair subrede
        # O que faz: Usa os primeiros 3 octetos do IP do servidor.

        IP_SUBNET_SERVIDOR_C=$(echo "$IP_SERVIDOR" | cut -d'.' -f1-3)

        # 14.2 - Criar IPs completos
        # O que faz: Forma os IPs completos para configuração DHCP.

        IP_RANGE_INICIO="${IP_SUBNET_SERVIDOR_C}.${OCTETO_INICIO_RANGE}"
        IP_RANGE_FIM="${IP_SUBNET_SERVIDOR_C}.${OCTETO_FIM_RANGE}"
        IP_GATEWAY="${IP_SUBNET_SERVIDOR_C}.${OCTETO_IP_GATEWAY}"
        IP_REDE="${IP_SUBNET_SERVIDOR_C}.0"
        IP_BROADCAST="${IP_SUBNET_SERVIDOR_C}.255"

        # 14.3 - Validação do Gateway
        # O que faz: Verifica se o gateway é 1 ou 254.

        if [[ "$OCTETO_IP_GATEWAY" != "1" && "$OCTETO_IP_GATEWAY" != "254" ]]; then
            echo "Erro! O IP do Gateway só deve ser 1 ou 254."
            continue
        fi

        # 14.4 - Validação do Range
        # O que faz: Verifica se o início é menor que o fim.

        if (( OCTETO_INICIO_RANGE >= OCTETO_FIM_RANGE )); then
            echo "Erro! Início do range deve ser menor que o fim."
            continue
        fi

        # 14.5 - Validação do IP do Servidor vs Range
        # O que faz: Garante que o IP do servidor não está no range DHCP.

        QUARTO_OCTETO_SERVIDOR=$(echo "$IP_SERVIDOR" | cut -d'.' -f4)
        if (( QUARTO_OCTETO_SERVIDOR >= OCTETO_INICIO_RANGE && QUARTO_OCTETO_SERVIDOR <= OCTETO_FIM_RANGE )); then
            echo "Erro! O IP do Servidor não pode estar dentro do range DHCP."
            continue
        fi

        # 14.6 - Barra de progresso
        # O que faz: Exibe progresso visual.

        echo -n "[ "
        for i in {1..40}; do
            echo -n "="
            sleep 0.05
        done
        echo " ]"

        # 14.7 - Mostrar resumo
        # O que faz: Exibe todos os parâmetros configurados.

        echo "Resumo dos IPs configurados:"
        echo "IP Servidor: $IP_SERVIDOR"
        echo "Range DHCP: $IP_RANGE_INICIO - $IP_RANGE_FIM"
        echo "IP Gateway: $IP_GATEWAY"
        echo "IP DNS (Local): $IP_DNS"
        echo "IP Broadcast: $IP_BROADCAST"
        echo "IP de Rede: $IP_REDE"
        echo "Domínio: $DOMINIO"

        # 14.8 - Confirmação final
        # O que faz: Pede confirmação dos dados inseridos.

        read -p "Está tudo correto? (y/n): " VERIFICACAO
    done

    echo "Verificação concluída!"
    echo "Aguarde enquanto aplicamos as definições!"

    # 15 - Barra de progresso final
    # O que faz: Mostra progresso antes de aplicar configurações.

    echo -n "[ "
    for i in {1..40}; do
        echo -n "="
        sleep 0.05
    done
    echo " ]"
    echo " Feito!"

    # 16 - Deteção da interface de rede
    # O que faz: Deteta automaticamente a interface ativa ou pede ao utilizador.

    INTERFACE=$(nmcli -t -f DEVICE connection show --active | head -n1)

    if [ -z "$INTERFACE" ]; then
        echo "Aviso: Nenhuma interface ativa detetada!"
        read -p "Insira o nome da interface manualmente (ex: enp0s3): " INTERFACE
    else
        echo "Interface detetada: $INTERFACE"
        read -p "Esta é a interface correta? (y/n): " CONFIRMA_INTERFACE
        
        if [[ "$CONFIRMA_INTERFACE" != "y" && "$CONFIRMA_INTERFACE" != "Y" ]]; then
            read -p "Insira o nome da interface manualmente: " INTERFACE
            echo "Interface alterada para: $INTERFACE"
        fi
    fi

    # 17 - Validação da interface
    # O que faz: Verifica se a interface existe no sistema.

    if ! nmcli connection show "$INTERFACE" &>/dev/null; then
        echo "Erro: A interface '$INTERFACE' não existe!"
        echo "Interfaces disponíveis:"
        nmcli connection show
        exit 1
    fi

    echo "A usar interface: $INTERFACE"

    # 18 - Configurar interface de rede
    # O que faz: Define IP estático na interface.

    sudo nmcli connection modify "$INTERFACE" ipv4.method manual
    echo "Interface $INTERFACE alterada para manual."

    sudo nmcli connection modify "$INTERFACE" ipv4.addresses "$IP_SERVIDOR/24"
    echo "IP alterado para $IP_SERVIDOR/24."

    sudo nmcli connection down "$INTERFACE"
    sudo nmcli connection up "$INTERFACE"
    echo "Restart da interface $INTERFACE concluído."

    # 19 - Criar configuração do KEA DHCP4
    # O que faz: Gera o ficheiro de configuração JSON do KEA com DNS local.

    # O que faz o domain-name: Define o domínio que será distribuído aos clientes.

    echo "A configurar KEA DHCP4 com DNS local..."
    sudo tee /etc/kea/kea-dhcp4.conf >/dev/null << DHCP
{
  "Dhcp4": {
    "interfaces-config": { "interfaces": [ "0.0.0.0" ] },
    "lease-database": {
      "type": "memfile",
      "lfc-interval": 3600
    },
    "valid-lifetime": 7200,
    "renew-timer": 1800,
    "rebind-timer": 3600,
    "option-data": [
      { "name": "domain-name-servers", "data": "${IP_DNS}" },
      { "name": "domain-name", "data": "${DOMINIO}" },
      { "name": "routers", "data": "${IP_GATEWAY}" },
      { "name": "subnet-mask", "data": "255.255.255.0" },
      { "name": "broadcast-address", "data": "${IP_BROADCAST}" }
    ],
    "subnet4": [
      {
        "subnet": "${IP_REDE}/24",
        "pools": [ { "pool": "${IP_RANGE_INICIO} - ${IP_RANGE_FIM}" } ],
        "reservations": [
          {
            "hw-address": "$(ip link show ${INTERFACE} | grep -i ether | awk '{print $2}')",
            "ip-address": "${IP_SERVIDOR}",
            "hostname": "server.${DOMINIO}"
          }
        ]
      }
    ],
    "loggers": [
      {
        "name": "kea-dhcp4",
        "output_options": [
          {
            "output": "/var/log/kea-dhcp4.log",
            "pattern": "%D{%Y-%m-%d %H:%M:%S.%q} %-5p [%c] %m\n",
            "flush": true,
            "maxsize": 10240000,
            "maxver": 3
          }
        ],
        "severity": "INFO",
        "debuglevel": 0
      }
    ]
  }
}
DHCP

    # 20 - Configurar firewall para DHCP
    # O que faz: Adiciona regra para permitir tráfego DHCP.

    # O que faz o --add-service=dhcp: Permite tráfego DHCP (porta 67/68 UDP).
    # O que faz o systemctl restart: Reinicia o serviço firewalld.
    # O que faz o firewall-cmd --reload: Recarrega as regras do firewall.
    # O que faz o --permanent: Torna a regra permanente.

    echo "A configurar firewall para DHCP..."
    sudo firewall-cmd --permanent --add-service=dhcp
    sudo systemctl restart firewalld

    # 21 - Validar e iniciar KEA DHCP4
    # O que faz: Testa configuração e inicia o serviço DHCP.

    # O que faz o kea-dhcp4 -t: Testa o ficheiro de configuração.
    # O que faz o systemctl enable --now: Habilita e inicia o serviço.
    # O que faz o systemctl restart: Reinicia o serviço.
    # O que faz o systemctl status: Mostra o estado do serviço.
    # O que faz o -t: Testa a configuração sem iniciar o serviço.

    echo "A validar e iniciar KEA DHCP4..."
    sudo kea-dhcp4 -t /etc/kea/kea-dhcp4.conf
    sudo systemctl enable --now kea-dhcp4
    sudo systemctl restart kea-dhcp4

    # 22 - Reiniciar BIND
    # O que faz: Reinicia o serviço DNS para garantir funcionamento correto.

    # O que faz o systemctl restart: Reinicia o serviço named (BIND).

    sudo systemctl restart named

    echo ""
    echo "=========================================="
    echo "  DNS + DHCP INTEGRADOS COM SUCESSO!"
    echo "=========================================="
    echo ""
    echo "Resumo da configuração:"
    echo "- DNS (BIND): $DOMINIO -> $IP_SERVIDOR"
    echo "- DHCP (KEA): Range $IP_RANGE_INICIO - $IP_RANGE_FIM"
    echo "- Gateway: $IP_GATEWAY"
    echo "- DNS distribuído aos clientes: $IP_DNS"
    echo "- Domínio: $DOMINIO"
    echo ""

    # 23 - Menu de verificações integrado
    # O que faz: Oferece opções para testar DNS e DHCP.

    # O que faz o case: Estrutura de controlo para múltiplas opções.
    # O que faz cada opção do menu:
    # Opção 1: Testa resolução DNS.
    # Opção 2: Mostra status dos serviços DNS e DHCP.
    # Opção 3: Lista leases DHCP atribuídos.
    # Opção 4: Sai do menu sem verificações.

    # O que faz o -p: Prompt para entrada do utilizador.

    echo "Deseja executar verificações?"
    echo "1) Testar resolução DNS (nome -> IP);"
    echo "2) Ver status dos serviços;"
    echo "3) Ver leases DHCP atribuídos;"
    echo "4) Sair."
    echo ""
    read -p "Escolha uma opção (1-4): " OPCAO_VERIFICACAO_INT

    case $OPCAO_VERIFICACAO_INT in
        1)
            # O que faz: Testa se o DNS resolve o domínio.
            echo ""
            echo "--- Teste de Resolução DNS ---"
            dig @127.0.0.1 ${DOMINIO} +short
            ;;
        2)
            # O que faz: Mostra o status de ambos os serviços.
            echo ""
            echo "--- Status BIND ---"
            sudo systemctl status named --no-pager
            echo ""
            echo "--- Status KEA DHCP4 ---"
            sudo systemctl status kea-dhcp4 --no-pager
            ;;
        3)
            # O que faz: Lista os leases DHCP atribuídos.
            echo ""
            echo "--- Leases DHCP ---"
            if [ -f /var/lib/kea/kea-leases4.csv ]; then
                cat /var/lib/kea/kea-leases4.csv
            else
                echo "Ainda não existem leases."
            fi
            ;;
        4)
            # O que faz: Sai sem verificações.
            echo ""
            echo "A sair sem verificações."
            ;;
        *)
            # O que faz: Trata entradas inválidas.
            echo ""
            echo "Opção inválida."
            ;;

    # O que faz o esac: Fecha a estrutura case.

    esac
    
    # 24 - Mensagem final
    # O que faz: Fornece comandos úteis e recomenda reboot.

    # O que faz o echo: Imprime mensagens no terminal.
    # O que faz o dig: Ferramenta para consultar servidores DNS.
    # O que faz o cat: Mostra conteúdo de ficheiros.
    # O que faz o systemctl status: Mostra estado de serviços.
    # O que faz o reboot: Comando para reiniciar o sistema.

    # O que faz o -f: Força o reboot sem perguntar.
    # O que faz o -h: Habilita reboot imediato.

    echo ""
    echo "Comandos úteis:"
    echo "- Testar DNS: dig @127.0.0.1 ${DOMINIO}"
    echo "- Ver leases: cat /var/lib/kea/kea-leases4.csv"
    echo "- Status DNS: systemctl status named"
    echo "- Status DHCP: systemctl status kea-dhcp4"
    echo ""
    echo "Recomenda-se um reboot do sistema."
    echo "Para reiniciar: reboot"
    ;;

# ======================================================
# 4 - OPÇÃO 4 - Sair
# ======================================================

4)
    # O que faz: Termina o script sem executar ações.
    # O que faz o exit 0: Sai do script com código de sucesso (0).
    
    echo ""
    echo "A sair..."
    exit 0
    ;;

# ======================================================
# Opção Inválida
# ======================================================

*)
    # O que faz: Trata qualquer entrada que não seja 1, 2, 3 ou 4.
    # O que faz o *): Captura todas as outras opções não listadas anteriormente.
    
    echo ""
    echo "Opção inválida! Por favor escolha entre 1-4."
    exit 1
    ;;

# O que faz o esac: Fecha a estrutura case iniciada no menu principal.

esac

echo "Acabou o script! Favor avaliar."