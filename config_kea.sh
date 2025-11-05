#!/bin/bash
# ========================================================================================= #
#
# Devido a limitações de conhecimento, este programa vai operar unicamente sobre um CIDR /24. Esperamos, no futuro, alargar a escolha.
#
# Projeto: Automatização da Configuração de um Servidor DHCP (KEA) (Classe C)
# Autor: Sérgio Correia
# Data: 17 10 2025
#
# Descrição:
# Este script foi concebido para simplificar a configuração de um servidor DHCP (KEA) em CentOS,
# operando em redes de Classe C com um CIDR /24. O programa valida os endereços IP
# inseridos pelo utilizador, configura automaticamente as interfaces de rede e os
# serviços necessários, e garante que a comunicação na rede é segura e funcional.
# O objetivo é fornecer uma solução robusta e de fácil utilização para administradores
# de sistema.
#
# ========================================================================================= #
#

# O que faz o dos2unix *.sh: Converte todos os ficheiros de script shell (.sh) no diretório atual do formato DOS/Windows para o formato Unix/Linux.

dos2unix *.sh

# 1 - Instalação do Service
# O que faz: Instala o servidor DHCP KEA usando o gestor de pacotes DNF. Ao contrário de DHCP tradicional (dhcpd), o KEA vai usar o dnf para instalação.

# O que faz o set -e: Configura o script para sair imediatamente se qualquer comando retornar um código de erro diferente de zero, garantindo que erros são tratados imediatamente.

set -e

# O que faz o chmod 775: Define as permissões do ficheiro para que o proprietário e o grupo possam ler, escrever e executar, enquanto outros utilizadores podem ler e executar.

chmod 775 config_kea.sh

# O que faz o dnf install -y kea: Instala o pacote KEA DHCP4 usando o gestor de pacotes DNF com a opção -y para automatizar a instalação.

echo ""
echo "=========================================="
echo "   INSTALAÇÃO: KEA (DHCP4) "
echo "=========================================="
echo ""

sudo dnf install -y kea

# 2 - Criação do backup config
# O que faz: Cria uma cópia de segurança do ficheiro de configuração original do KEA DHCP4, caso este exista e ainda não tenha sido feito um backup.

# O que faz o -f: Verifica se o ficheiro especificado existe. - file
# O que faz o -e: Verifica se o ficheiro ou diretório especificado existe (usado aqui para garantir que o backup não seja sobrescrito). - Exists

# O que difere de DHCP tradicional (dhcpd): O ficheiro de configuração do KEA DHCP4 é diferente do dhcpd, por isso o caminho do ficheiro também é diferente.

if [ -f /etc/kea/kea-dhcp4.conf ] && [ ! -e /etc/kea/kea-dhcp4.conf.backup ]; then
	sudo cp /etc/kea/kea-dhcp4.conf /etc/kea/kea-dhcp4.conf.backup
fi

# 3 - Validação do IP da Máquina
# O que faz: Verifica se o IP pertence à Classe C (192.168.x.x). Depois, garante que o terceiro octeto do IP não é 0 nem 255.

while true; do

	# 3.1 - Validação da Classe C
	# O que faz: Verifica se o IP do servidor pertence à Classe C (192.168.x.x) e se os octetos estão dentro dos intervalos válidos (1-254).
	
    # O que faz o =~: Operador de correspondência de expressão regular em bash, usado para validar o formato do IP. Como funciona: Verifica se a variável à esquerda corresponde ao padrão regex à direita.
	# O que faz o ^: Indica o início da string.
	# O que faz o $: Indica o fim da string.
	# O que faz o \.: Escapa o ponto, que é um caractere especial em regex, para que seja interpretado literalmente.
	# O que faz o [0-9]{1,3}: Corresponde a qualquer número entre 0 e 999, mas a validação adicional garante que os octetos estão entre 1 e 254.

    # O que difere de DHCP tradicional: Nada nesta secção difere do DHCP tradicional, pois a validação do IP é independente do serviço DHCP utilizado.

	read -p "Digite o IP desejado para o Servidor (Exemplo: 192.168.0.5): " IP_SERVIDOR

	TERCEIRO_OCTETO=$(echo "$IP_SERVIDOR" | cut -d'.' -f3)
	QUARTO_OCTETO=$(echo "$IP_SERVIDOR" | cut -d'.' -f4)

	if [[ ! $IP_SERVIDOR =~ ^192\.168\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
		echo "Erro 3.1! IP deve começar com 192.168.x.x."

	elif (( TERCEIRO_OCTETO < 0 || TERCEIRO_OCTETO > 254 )); then
		echo "Erro 3.2! O 3º octeto deve estar entre 1 e 254."

	elif (( QUARTO_OCTETO < 2 || QUARTO_OCTETO >= 254 )); then
		echo "Erro 3.3! O 4º octeto deve estar entre 2 e 253."

	else
		echo "IP válido!"
		break
	fi

done

# 4 - Inserção e validação de IPs
# O que faz: Solicita ao utilizador todos os IPs necessários (Servidor, Range DHCP, Gateway e DNS), valida-os em tempo real
# e permite que, caso a validação final não seja confirmada, o utilizador volte a inserir todos os valores novamente.

# O que difere de DHCP tradicional: Nada nesta secção difere do DHCP tradicional, pois a validação dos IPs é independente do serviço DHCP utilizado.

VERIFICACAO=""

while [ "$VERIFICACAO" != "y" ] && [ "$VERIFICACAO" != "Y" ]; do

    # 4.1 - Solicitar o escopo de IPs desejado e gateway/DNS
    # O que faz: Pede ao utilizador apenas o 4º octeto do range, gateway e DNS, para formar os IPs completos
	
    # O que faz o -p do read: Exibe uma mensagem para o utilizador antes de esperar pela entrada.

    read -p "Qual vai ser o início do range DHCP (4º octeto)? " OCTETO_INICIO_RANGE
    read -p "Qual vai ser o fim do range DHCP (4º octeto)? " OCTETO_FIM_RANGE
    read -p "Inserir o nome do domínio (ex: empresa.local): " DOMAIN_NAME
    read -p "Inserir o IP do Servidor DNS BIND (o IP estático na LAN Segment): " IP_DNS_BIND
    echo ""
    # 4.2 - Extrair a subrede do servidor
	# O que faz: Usa o cut para extrair os primeiros três octetos do IP do servidor, formando a sub-rede.
	
    # O que faz o cut: Divide uma string em partes com base em um delimitador especificado (neste caso, o ponto ".") e extrai as partes desejadas. - cut -d'.' -f1-3 ( Semelhante ao .split em Python)

    IP_SUBNET_SERVIDOR_C=$(echo "$IP_SERVIDOR" | cut -d'.' -f1-3)

    # 4.3 - Criar IPs completos
	# O que faz: Concatena a sub-rede com os octetos fornecidos pelo utilizador para formar os IPs completos necessários para a configuração do DHCP.

    IP_RANGE_INICIO="${IP_SUBNET_SERVIDOR_C}.${OCTETO_INICIO_RANGE}"
    IP_RANGE_FIM="${IP_SUBNET_SERVIDOR_C}.${OCTETO_FIM_RANGE}"
    IP_REDE="${IP_SUBNET_SERVIDOR_C}.0"

    # 4.4 - Octetos individuais para validações
	# O que faz: Extrai os octetos individuais do IP do servidor e do DNS para facilitar as validações subsequentes.

    IP_DNS="${IP_DNS_BIND}"
    OCTETO_IP_DNS=$(echo "$IP_DNS" | cut -d'.' -f4)

    # 4.5 - Cálculo do Broadcast
	# O que faz: Calcula o IP de broadcast com base no 4º octeto da gateway. Se a gateway for .1, o broadcast será .255, e vice-versa.

    IP_BROADCAST="${IP_SUBNET_SERVIDOR_C}.255"

    # 4.6 - Validação do Range DHCP
    # O que faz: Garante que o início do range DHCP é menor que o fim e que o IP do servidor não está dentro do range DHCP.
    
    # O que faz o >=: Operador de comparação em bash, usado para verificar se um valor é maior ou igual a outro.

    if (( OCTETO_INICIO_RANGE >= OCTETO_FIM_RANGE )); then
        echo "Erro 4.6! Início do range ($OCTETO_INICIO_RANGE) deve ser menor que o fim ($OCTETO_FIM_RANGE)."
        continue
    fi

    # 4.7 - Validação 2: IP do Servidor não pode estar dentro do range DHCP
    # O que faz: Garante que o 4º octeto do IP do servidor não esteja dentro do range DHCP definido.

    QUARTO_OCTETO_SERVIDOR=$(echo "$IP_SERVIDOR" | cut -d'.' -f4)

    if (( QUARTO_OCTETO_SERVIDOR >= OCTETO_INICIO_RANGE && QUARTO_OCTETO_SERVIDOR <= OCTETO_FIM_RANGE )); then
        echo "Erro 4.7! O 4º octeto do Servidor ($QUARTO_OCTETO_SERVIDOR) não pode estar dentro do range DHCP ($OCTETO_INICIO_RANGE - $OCTETO_FIM_RANGE)."
        continue
    fi

    # 4.9 - Mostrar resumo para confirmação

    echo -n "[ "

    for i in {1..40}; do
        echo -n "="
        sleep 0.05
    done

    echo " ]"

    echo ""

    echo "Resumo dos IPs configurados (Sub-rede: $IP_SUBNET_SERVIDOR_C):"
    echo "---------------------------------------------------------"
    echo "IP Servidor Estático: $IP_SERVIDOR (Fora do range DHCP)"
    echo "IP Gateway/Router:    $IP_GATEWAY"
    echo "IP DNS BIND:          $IP_DNS"
    echo "Range DHCP (Início): $IP_RANGE_INICIO"
    echo "Range DHCP (Fim):     $IP_RANGE_FIM"
    echo "IP Broadcast:         $IP_BROADCAST"
    echo "IP de Rede:           $IP_REDE"
    echo "Domain Name:         $DOMAIN_NAME"
    echo "---------------------------------------------------------"
    echo ""
    
    # 4.10 - Solicitar confirmação final
    # O que faz: Pede ao utilizador para confirmar se todos os valores estão corretos antes de prosseguir.

    read -p "Validação básica concluída! Está tudo correto? (y/n): " VERIFICACAO

done

echo "Verificação concluída!"

echo "Aguarde enquanto aplicamos as definições!"
echo ""

# Extra - Barra de Progresso para a espera da aplicação nova das configurações
# O que faz o -n do echo: Impede o echo de adicionar uma nova linha após a saída, permitindo que a barra de progresso seja exibida na mesma linha.

# O que difere de DHCP tradicional: Nada nesta secção difere do DHCP tradicional, pois a barra de progresso é apenas uma funcionalidade estética.

echo -n "[ "

for i in {1..40}; do
	echo -n "="
	sleep 0.05
done

echo " ]"
echo "Feito!"

# 5 - Configuração do Acesso à Internet
# O que faz: Pergunta ao utilizador se os clientes DHCP devem ter acesso à Internet. Se sim, configura o gateway e os servidores DNS apropriados.

# O que faz o ,,: Converte a entrada do utilizador para minúsculas, facilitando a comparação.
# O que faz o ==: Operador de comparação em bash, usado para verificar se duas strings são iguais.
# O que faz o if/else: Estrutura condicional que executa diferentes blocos de código com base na condição avaliada.
# O que faz o read -p: Pede ao utilizador para inserir uma resposta, exibindo uma mensagem antes da entrada.
# O que faz o &&: Operador lógico "E" em bash, usado para combinar múltiplas condições.
# O que faz o ||: Operador lógico "OU" em bash, usado para executar um comando se o anterior falhar.

# O que difere de DHCP tradicional: Nada nesta secção difere do DHCP tradicional, pois a configuração do gateway e DNS é independente do serviço DHCP utilizado.

read -p "Deseja que os clientes tenham acesso à Internet? (y/N): " ACESSO_INTERNET

if [ "$ACESSO_INTERNET" == "y" ] && [ "$ACESSO_INTERNET" == "Y" ]; then

    ACESSO=1
    # 5.1 - Definir o GATEWAY para a rede DHCP: É O PRÓPRIO SERVIDOR (DHCP/NAT)
    # O que faz: Define o gateway para os clientes DHCP como o IP do servidor, assumindo que este atuará como gateway para a rede LAN.

    GATEWAY="$IP_SERVIDOR"
    
    # 5.2 - Configurar o DNS do Servidor/Gateway (para ele ter acesso à Internet)
    # O que faz: Pede ao utilizador para inserir o IP de um servidor DNS externo (Google ou Cloudflare) para que o servidor/gateway possa resolver nomes de domínio na Internet.

    read -p "Insira o IP de DNS EXTERNO para o Servidor/Gateway (Ex: 8.8.8.8 ou 1.1.1.1): " IP_DNS_EXTERNO
    
    # 5.3 - Validação do DNS Externo
    # O que faz: Verifica se o IP inserido é um dos servidores DNS públicos válidos (Google ou Cloudflare).

    if [[ "$IP_DNS_EXTERNO" != "8.8.8.8" && "$IP_DNS_EXTERNO" != "1.1.1.1" ]]; then
        echo "Aviso! Valor inválido para DNS Externo. O Servidor/Gateway usará 1.1.1.1 por omissão."
        IP_DNS_EXTERNO="1.1.1.1"
    fi
    
    # 5.4 - Configurar o DNS Primário para os Clientes DHCP (Este é o seu Servidor BIND na LAN)
    # O que faz: Pede ao utilizador para inserir o IP do servidor BIND/DNS na LAN, que será usado como DNS primário pelos clientes DHCP.

    read -p "Insira o IP do seu Servidor BIND/DNS na LAN Segment (Será o DNS Primário dos clientes): " IP_DNS_BIND_PRIMARIO
    
    IP_DNS="$IP_DNS_BIND_PRIMARIO"
    
    echo "Acesso à Internet ativado."
    echo "Clientes DHCP receberão: Gateway ($GATEWAY) e DNS ($IP_DNS)."

else
    # 5.5 - Configuração para Operar sem Acesso à Internet
    # O que faz: Configura o servidor DHCP para operar sem acesso à Internet, apenas com DNS local (BIND).

    ACESSO=0
    GATEWAY=""
    IP_DNS_EXTERNO=""

    read -p "Insira o IP do seu Servidor BIND/DNS na LAN Segment (Será o único DNS para os clientes): " IP_DNS_BIND_PRIMARIO

    IP_DNS="$IP_DNS_BIND_PRIMARIO"
    echo "Apenas atribuição de IP local. Clientes DHCP receberão DNS ($IP_DNS)."
fi

# 6 - Deteção e Configuração da Placa de Rede
# O que faz: Deteta automaticamente a interface de rede ativa e pede confirmação ao utilizador.

# O que faz o nmcli -t -f DEVICE connection show --active: Usa o NetworkManager Command Line Interface (nmcli) para listar as conexões de rede ativas e extrair apenas os nomes dos dispositivos (interfaces de rede).
# O que faz o head -n1: Seleciona a primeira linha da saída, que corresponde à primeira interface de rede ativa detetada.
# O que faz o if [ -z "$INTERFACE" ]: Verifica se a variável INTERFACE está vazia, indicando que nenhuma interface ativa foi detetada automaticamente.
# O que faz o read -p: Pede ao utilizador para inserir o nome da interface manualmente, caso nenhuma tenha sido detetada.
# O que faz o nmcli connection modify: Modifica as configurações da conexão de rede especificada.
# O que faz o ipv4.method manual: Define o método de atribuição de IP para manual, permitindo a configuração estática do IP.
# O que faz o ipv4.addresses "$IP_SERVIDOR/24": Define o endereço IP estático para a interface de rede, usando o IP do servidor fornecido pelo utilizador com uma máscara de sub-rede /24.
# O que faz o nmcli connection down/up: Desativa e reativa a conexão de rede para aplicar as novas configurações.

# O que faz o -z: Verifica se a string está vazia.

# O que difere de DHCP tradicional: Nada nesta secção difere do DHCP tradicional, pois a configuração da interface de rede é independente do serviço DHCP utilizado.

echo ""
echo "Configuração de Interfaces"
echo ""

nmcli 

echo ""

read -p "Qual é a interface WAN (NAT)? " WAN_IF
read -p "Qual é a interface LAN (para DHCP)? " LAN_IF

echo ""
echo "A configurar interface WAN ($WAN_IF) para obter IP por DHCP..."
sleep 0.5

sudo nmcli connection add type ethernet ifname "$WAN_IF" con-name WAN ipv4.method auto || true
sudo nmcli connection up WAN || sudo nmcli connection up "$WAN_IF"

# 6.1 - Mostrar IP obtido pela WAN
# O que faz: Exibe o endereço IP obtido pela interface WAN após a configuração DHCP.

WAN_IP=$(ip -4 addr show "$WAN_IF" | grep inet | awk '{print $2}' | head -n1)
echo "Interface WAN configurada com IP: ${WAN_IP:-"A aguardar DHCP..."}"

# 6.2 - Configurar LAN com IP do utilizador (já definido anteriormente)
# O que faz: Configura a interface LAN com o IP estático fornecido pelo utilizador, juntamente com o gateway e o servidor DNS.

# O que faz o ip -4 addr show: Exibe os endereços IPv4 atribuídos às interfaces de rede.

echo ""
echo "A configurar interface LAN ($LAN_IF) com IP $IP_SERVIDOR/24..."
sleep 0.5
sudo nmcli connection add type ethernet ifname "$LAN_IF" con-name LAN ipv4.method manual ipv4.addresses "$IP_SERVIDOR/24" || true
sudo nmcli connection modify LAN ipv4.gateway "$IP_GATEWAY" ipv4.dns "$IP_DNS"
sudo nmcli connection up LAN || sudo nmcli connection up "$LAN_IF"

echo ""
echo "Interfaces configuradas:"
sleep 0.5
ip -4 addr show "$WAN_IF"
ip -4 addr show "$LAN_IF"

# 6.3 - Ativar IP Forwarding
# O que faz: Ativa o encaminhamento de IP no sistema, permitindo que o tráfego de rede seja roteado entre diferentes interfaces.

# O que faz o sysctl -w net.ipv4.ip_forward=1: Ativa o encaminhamento de IP temporariamente, até ao próximo reboot.
# O que faz o tee -a /etc/sysctl.conf: Adiciona a configuração de encaminhamento de IP ao ficheiro sysctl.conf para que a alteração seja persistente após reboot.

echo ""
echo "Ativando IP forwarding..."
sleep 0.5
sudo sysctl -w net.ipv4.ip_forward=1
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf > /dev/null

# 6.4 - Configurar NAT (masquerading)
# O que faz: Configura regras de NAT (Network Address Translation) usando iptables para permitir que os dispositivos na rede LAN acedam à Internet através da interface WAN.

# O que faz o iptables -t nat -A POSTROUTING -o "$WAN_IF" -j MASQUERADE: Adiciona uma regra à tabela NAT para mascarar os endereços IP de origem dos pacotes que saem pela interface WAN.
# O que faz o iptables -A FORWARD -i "$LAN_IF" -o "$WAN_IF" -j ACCEPT: Permite o encaminhamento de pacotes da interface LAN para a interface WAN.
# O que faz o iptables -A FORWARD -i "$WAN_IF" -o "$LAN_IF" -m state --state RELATED,ESTABLISHED -j ACCEPT: Permite o encaminhamento de pacotes da interface WAN para a interface LAN, mas apenas para conexões relacionadas ou estabelecidas.
# O que faz o -t nat: Especifica que a regra será adicionada à tabela NAT do iptables.
# O que faz o -A POSTROUTING: Adiciona uma regra à cadeia POSTROUTING, que é usada para modificar pacotes após a decisão de roteamento ter sido tomada.
# O que faz o -j MASQUERADE: Especifica a ação a ser tomada para os pacotes correspondentes à regra, neste caso, mascarar o endereço IP de origem.
# O que faz o -m state --state RELATED,ESTABLISHED: Usa o módulo de estado para corresponder apenas a pacotes que são parte de conexões já estabelecidas ou relacionadas.
# O que faz o -A FORWARD: Adiciona uma regra à cadeia FORWARD, que é usada para controlar o encaminhamento de pacotes entre interfaces de rede.
# O que faz o -i: Especifica a interface de entrada para a regra.
# O que faz o -o: Especifica a interface de saída para a regra.
# O que faz o ACCEPT: Especifica que os pacotes correspondentes à regra devem ser aceitos e encaminhados.

echo ""
echo "Aplicando regras de NAT..."
sleep 0.5
sudo iptables -t nat -A POSTROUTING -o "$WAN_IF" -j MASQUERADE
sudo iptables -A FORWARD -i "$LAN_IF" -o "$WAN_IF" -j ACCEPT
sudo iptables -A FORWARD -i "$WAN_IF" -o "$LAN_IF" -m state --state RELATED,ESTABLISHED -j ACCEPT

# 6.5 - Tornar as regras persistentes (para reboot)
# O que faz: Instala o pacote iptables-services para permitir a persistência das regras de iptables após reboot.

# O que faz o dnf install -y iptables-services: Instala o pacote iptables-services usando o gestor de pacotes DNF com a opção -y para automatizar a instalação.
# O que faz o service iptables save: Salva as regras atuais do iptables para que sejam restauradas automaticamente na reinicialização do sistema.
# O que faz o systemctl enable iptables: Habilita o serviço iptables para iniciar automaticamente na inicialização do sistema.

echo ""
echo "A guardar as regras de NAT para persistirem após reboot."
sleep 0.5
sudo dnf install -y iptables-services
sudo service iptables save
sudo systemctl enable iptables

# 6.6 - Firewall
# O que faz: Configura a firewall (firewalld) para permitir o serviço DHCP e ativar o masquerading, garantindo que os clientes possam comunicar com o servidor e aceder à Internet.
# O que é o masquerade: Técnica de NAT que permite que múltiplos dispositivos numa rede local acedam à Internet usando um único endereço IP público.

echo ""
echo "A configurar os acessos à firewall..."
sleep 0.5
sudo firewall-cmd --permanent --add-service=dhcp
sudo firewall-cmd --permanent --add-masquerade
sudo firewall-cmd --reload

echo ""
echo "Interfaces e NAT configurados com sucesso!"
sleep 0.5
echo "WAN ($WAN_IF) -> Internet via NAT"
echo "LAN ($LAN_IF) -> IP fixo $IP_SERVIDOR/24 + DHCP KEA"

# 7 - Instalação do Fail2ban
# O que faz: Instala o Fail2Ban e a integração com o firewalld para proteger o servidor contra tentativas de acesso não autorizadas.

echo "A instalar EPEL..."
sudo dnf install -y epel-release 

echo "A instalar Fail2Ban e firewalld integration..."
sleep 0.5

sudo dnf install -y fail2ban fail2ban-firewalld

echo "Fail2Ban instalado com sucesso!"
sleep 0.5

# 8 - Edição do Config do DHCP (Kea)
# O que faz: Escreve o ficheiro de configuração JSON do Kea DHCPv4 com os parâmetros fornecidos.

# O que faz o sudo tee: Permite escrever múltiplas linhas de texto em ficheiros que requerem privilégios de superutilizador.
# O que faz o >/dev/null: Redireciona a saída padrão para /dev/null, suprimindo a saída do comando no terminal.
# O que faz o << DHCP: Inicia um "here document" que permite inserir múltiplas linhas de texto até encontrar a palavra-chave DHCP.

# O que faz o interfaces-config: Define as interfaces de rede que o Kea DHCPv4 irá escutar.
# O que faz o lease-database: Configura o tipo de base de dados para armazenar os leases (memfile neste caso, que é um ficheiro em memória).
# O que faz o type memfile: Indica que os leases serão armazenados em ficheiros no sistema de ficheiros.
# O que faz o lfc-interval: Define o intervalo em segundos para a limpeza dos leases expirados.

# O que faz o valid-lifetime: Define o tempo de vida válido para os leases atribuídos aos clientes DHCP.
# O que faz o renew-timer: Define o tempo em segundos após o qual um cliente DHCP deve tentar renovar o seu lease.
# O que faz o rebind-timer: Define o tempo em segundos após o qual um cliente DHCP deve tentar rebind se a renovação falhar.

# O que faz o option-data: Define as opções DHCP que serão fornecidas aos clientes, como servidores DNS, gateway, máscara de sub-rede e endereço de broadcast.

# O que faz o subnet4: Define a sub-rede e os pools de endereços IP que o Kea DHCPv4 irá gerir.

# O que faz o loggers: Configura o sistema de logging do Kea DHCPv4, especificando o ficheiro de log, o nível de severidade e o nível de debug.
# O que faz o name: Especifica o nome do logger (kea-dhcp4 neste caso).
# O que faz o output_options: Define as opções de saída para o logger, incluindo o ficheiro onde os logs serão armazenados.
# O que faz o severity: Define o nível de severidade dos logs (INFO neste caso).
# O que faz o debuglevel: Define o nível de detalhe dos logs de debug (0 neste caso, indicando nenhum detalhe adicional).

# O que difere de DHCP tradicional: A configuração do Kea DHCPv4 é baseada em JSON, diferente do formato tradicional usado pelo dhcpd, que é baseado em texto simples.

read -p "Tempo de concessão dos leases desejado, em segundos (Ex: 3600 para 1 hora): " LEASE_TIME

RENEW_TIMER=$((LEASE_TIME / 2))
REBIND_TIMER=$((LEASE_TIME * 7 / 8))

sudo mkdir -p /etc/kea
sudo chmod 755 /etc/kea
sudo chown root:root /etc/kea

sudo mkdir -p /var/log/kea
sudo chmod 755 /var/log/kea
sudo chown root:root /var/log/kea

if [ "$ACESSO" == "1" ]; then
    # Acesso à Internet ativado
    IP_GATEWAY="$IP_SERVIDOR"
    sudo tee /etc/kea/kea-dhcp4.conf << DHCP
{
    "Dhcp4": {
        "interfaces-config": {
            "interfaces": [ "${LAN_IF}" ]
        },
        "expired-leases-processing": {
            "reclaim-timer-wait-time": 10,
            "flush-reclaimed-timer-wait-time": 25,
            "hold-reclaimed-time": 3600,
            "max-reclaim-leases": 100,
            "max-reclaim-time": 250,
            "unwarned-reclaim-cycles": 5
        },
        "renew-timer": ${RENEW_TIMER},
        "rebind-timer": ${REBIND_TIMER},
        "valid-lifetime": ${LEASE_TIME},
        "option-data": [
            {
                "name": "domain-name-servers",
                "data": "${IP_DNS_BIND}"
            },
            {
                "name": "domain-name",
                "data": "${DOMAIN_NAME}"
            },
            {
                "name": "domain-search",
                "data": "${DOMAIN_NAME}"
            }
        ],
        "subnet4": [
            {
                "id": 1,
                "subnet": "${IP_REDE}/24",
                "pools": [
                    { "pool": "${IP_RANGE_INICIO} - ${IP_RANGE_FIM}" }
                ],
                "option-data": [
                    {
                        "name": "routers",
                        "data": "${IP_GATEWAY}"
                    }
                ]
            }
        ],
        "loggers": [
            {
                "name": "kea-dhcp4",
                "output-options": [
                    { "output": "/var/log/kea/kea-dhcp4.log" }
                ],
                "severity": "INFO",
                "debuglevel": 0
            }
        ]
    }
}
DHCP

else
    # Acesso à Internet desativado
    sudo tee /etc/kea/kea-dhcp4.conf << DHCP
{
    "Dhcp4": {
        "interfaces-config": {
            "interfaces": [ "${LAN_IF}" ]
        },
        "expired-leases-processing": {
            "reclaim-timer-wait-time": 10,
            "flush-reclaimed-timer-wait-time": 25,
            "hold-reclaimed-time": 3600,
            "max-reclaim-leases": 100,
            "max-reclaim-time": 250,
            "unwarned-reclaim-cycles": 5
        },
        "renew-timer": 900,
        "rebind-timer": 1800,
        "valid-lifetime": 3600,
        "option-data": [
            {
                "name": "domain-name",
                "data": "${DOMAIN_NAME}"
            }
        ],
        "subnet4": [
            {
                "id": 1,
                "subnet": "${IP_REDE}/24",
                "pools": [
                    { "pool": "${IP_RANGE_INICIO} - ${IP_RANGE_FIM}" }
                ]
            }
        ],
        "loggers": [
            {
                "name": "kea-dhcp4",
                "output-options": [
                    { "output": "/var/log/kea/kea-dhcp4.log" }
                ],
                "severity": "INFO",
                "debuglevel": 0
            }
        ]
    }
}
DHCP
fi

# 8.1 - Permissões dos Ficheiros de Configuração e Log do Kea DHCPv4
# O que faz: Define as permissões corretas para o ficheiro de configuração do Kea DHCPv4 e o ficheiro de log, garantindo que apenas o utilizador root tenha acesso de escrita.

sudo chmod 644 /etc/kea/kea-dhcp4.conf
sudo chown root:root /etc/kea/kea-dhcp4.conf

sudo touch /var/log/kea-dhcp4.log
sudo chmod 644 /var/log/kea-dhcp4.log
sudo chown root:root /var/log/kea-dhcp4.log

echo "A validar as configurações do Kea DHCP4..."
if ! sudo kea-dhcp4 -t /etc/kea/kea-dhcp4.conf; then
    echo "Erro: Configuração inválida detetada. Por favor, reveja o ficheiro de configuração."
    exit 1
    sleep 0.5
fi

# 9 - Configuração do Fail2Ban para o Kea DHCPv4
# O que faz: Configura o Fail2Ban para monitorizar os logs do Kea DHCPv4 e bloquear IPs que apresentem comportamento suspeito, como múltiplas tentativas de DHCPDISCOVER.

# O que faz o sudo tee /etc/fail2ban/filter.d/kea-dhcp.conf: Cria um ficheiro de filtro personalizado para o Kea DHCP dentro do diretório de filtros do Fail2Ban.
# O que faz o failregex: Define os padrões de expressão regular que o Fail2Ban irá procurar nos logs para identificar tentativas suspeitas.
# O que faz o ignoreregex: Define padrões de expressão regular que o Fail2Ban
# irá ignorar nos logs.
# O que faz o datepattern: Define o padrão de data que corresponde ao formato JSON do
# Kea, essencial para o findtime funcionar corretamente.

sudo tee /etc/fail2ban/filter.d/kea-dhcp.conf >/dev/null << 'EOF'
# ============================================================================ #
# FILTRO FAIL2BAN PARA KEA DHCP (JSON)
# ============================================================================ #

[Definition]

# Usa ADDR para capturar o IP do cliente (quando presente) ou outro identificador.
# Corresponde a logs como: {"message":"DHCPDISCOVER from 00:00:00:00:00:00 via eth0"}
failregex = ^.*"message":\s*"DHCPDISCOVER from (?:<ADDR>|\S+) via \S+".*$
            ^.*"message":\s*"DHCPREQUEST .*from (?:<ADDR>|\S+) via \S+".*$

ignoreregex =

[Init]
# Padrão de data que corresponde ao formato JSON do KEA, essencial para o findtime funcionar.
datepattern = ^"timestamp":\s*"%%Y-%%m-%%d\s+%%H:%%M:%%S\.%%f"
EOF

echo "Ficheiro de filtro /etc/fail2ban/filter.d/kea-dhcp.conf criado."
sleep 0.5

# 10 - Configuração do Fail2Ban para o KEA DHCP
# O que faz: Cria uma jail personalizada no Fail2Ban para o Kea DHCP, definindo as regras de monitorização e bloqueio.

# O que faz o sudo tee /etc/fail2ban/jail.d/kea-dhcp.conf: Cria um ficheiro de configuração de jail personalizado para o Kea DHCP dentro do diretório de jails do Fail2Ban.
# O que faz o enabled = true: Ativa a jail para o Kea DHCP.
# O que faz o filter = kea-dhcp: Especifica o filtro a ser usado para esta jail, que foi definido anteriormente.
# O que faz o port = 67,68: Define as portas UDP que o Fail2Ban irá monitorizar para o Kea DHCP.
# O que faz o protocol = udp: Especifica o protocolo de rede (UDP) a ser monitorizado.
# O que faz o logpath = /var/log/kea/kea-dhcp4.log: Define o caminho do ficheiro de log do Kea DHCP que o Fail2Ban irá monitorizar.
# O que faz o backend = polling: Define o método de monitorização do ficheiro de log.
# O que faz o maxretry = 20: Define o número máximo de tentativas permitidas antes de um IP ser bloqueado.
# O que faz o findtime = 120: Define o período de tempo (em segundos) durante o qual as tentativas são contadas.
# O que faz o bantime = 7200: Define a duração (em segundos) do bloqueio para IPs que excedam o limite de tentativas.

echo ""
echo "A configurar regras de proteção..."

sudo tee /etc/fail2ban/jail.d/kea-dhcp.conf >/dev/null << EOF
# ============================================================================ #
# JAIL KEA DHCP - Configuração Final
# ============================================================================ #

[kea-dhcp]
enabled  = true
filter   = kea-dhcp
port     = 67,68
protocol = udp
logpath  = /var/log/kea/kea-dhcp4.log
backend  = polling 
maxretry = 20
findtime = 120
bantime  = 7200

# IPs que NUNCA serão bloqueados: Certificar-se de que a variável é resolvida.
ignoreip = 127.0.0.1/8 ${IP_SERVIDOR}

action   = firewallcmd-ipset
EOF

echo "Configuração criada: /etc/fail2ban/jail.d/kea-dhcp.conf"
sleep 0.5

# 11 - Iniciar o Fail2Ban
# O que faz: Ativa e inicia o serviço Fail2Ban, garantindo que ele arranca automaticamente no boot.

echo ""
echo "A iniciar o Fail2Ban..."

sudo systemctl enable --now fail2ban

echo "Fail2Ban ativo!"
sleep 0.5

echo "Proteção ativa contra ataques DHCP."
echo "IPs maliciosos serão bloqueados automaticamente."
sleep 0.5

# 12 - Add o Service à firewall
# O que faz: Configura a firewall (firewalld) para permitir o serviço DHCP (kea/dhcp), garantindo que os clientes podem comunicar com o servidor.

# O que difere de DHCP tradicional: Nada nesta secção difere do DHCP tradicional, pois a configuração da firewall é independente do serviço DHCP utilizado.

sudo firewall-cmd --permanent --add-service=dhcp
echo "Serviço adicionado à Firewall."
sleep 0.5

sudo firewall-cmd --runtime-to-permanent
echo "Alterações temporárias aplicadas permanentemente na firewall."
sleep 0.5

sudo systemctl restart firewalld
echo "Serviço firewalld reiniciado."
sleep 0.5

# 13 - Restart dos Services
# O que faz: Inicia o serviço do servidor DHCP (dhcpd) e garante que ele arranca automaticamente no boot. O sudo journalctl é usado para mostrar os logs do serviço, confirmando que o DHCP está ativo e a funcionar.

# O que faz o -t do kea-dhcp4: Testa a configuração do Kea DHCPv4 antes de iniciar o serviço, garantindo que não há erros no ficheiro de configuração.

# O que difere de DHCP tradicional: Nada nesta secção difere do DHCP tradicional, pois o controlo dos serviços é independente do serviço DHCP utilizado.

sudo kea-dhcp4 -t /etc/kea/kea-dhcp4.conf
echo "A iniciar o serviço Kea ..."
sleep 0.5

sudo systemctl enable --now kea-dhcp4
echo "Serviço Kea DHCP4 iniciado e pronto para iniciar no arranque."
sleep 0.5

sudo systemctl restart kea-dhcp4
echo "Serviço Kea DHCP4 reiniciado."
sleep 0.5

echo "Recomenda-se um reboot do sistema para garantir que todas as alterações tenham efeito."
echo "Para reiniciar o sistema, execute: reboot"
sleep 0.5

# 14 - Configuração final
# O que faz: Oferece ao utilizador a opção de executar verificações finais, como verificar o status do serviço, listar os leases atribuídos e visualizar as últimas linhas do log.

# O que faz o case: Estrutura de controle em bash que permite executar diferentes blocos de código com base na opção escolhida pelo utilizador.
# O que faz o sudo systemctl status kea-dhcp4: Verifica o status do serviço Kea DHCPv4, mostrando se está ativo e a funcionar corretamente.
# O que faz o cat /var/lib/kea/kea-leases4.csv: Exibe o conteúdo do ficheiro de leases, mostrando os endereços IP atribuídos aos clientes DHCP.
# O que faz o tail -n 10 /var/log/kea-dhcp4.log: Mostra as últimas 10 linhas do ficheiro de log do Kea DHCPv4, permitindo ao utilizador ver eventos recentes e mensagens de erro, se houver.
# O que faz o tail -f /var/log/kea-dhcp4.log: Permite ao utilizador monitorizar o ficheiro de log em tempo real, exibindo novas entradas à medida que são adicionadas.
# O que faz o systemctl status kea-dhcp4: Permite ao utilizador verificar o status do serviço Kea DHCPv4 a qualquer momento.

# O que faz o ;;: Indica o fim de um bloco de código dentro de uma estrutura case em bash, semelhante a um break.
# O que faz o *) : Captura qualquer entrada que não corresponda às opções listadas anteriormente, funcionando como um "default" em outras linguagens de programação.
# O que faz o esac: Indica o fim da estrutura case em bash.

while true; do
    echo ""
    echo "Deseja executar verificações finais?"
    echo "1) Verificar status do serviço KEA;"
    echo "2) Ver leases atribuídos;"
    echo "3) Ver últimas linhas do log;"
    echo "4) Verificar status do Fail2Ban;"
    echo "5) Sair."
    echo ""
    read -p "Escolha uma opção (1-5): " OPCAO_VERIFICACAO

    case $OPCAO_VERIFICACAO in
        1)
            echo ""
            echo "--- Status do Serviço Kea DHCP4 ---"

            # 14.1 - Verificar status do serviço KEA
            # O que faz: Mostra o status atual do serviço Kea DHCPv4.

            sudo systemctl status kea-dhcp4
            ;;
        2)
            echo ""
            echo "--- Leases Atribuídos ---"

            # 14.2 - Ver leases atribuídos
            # O que faz: Exibe a lista de leases atualmente atribuídos pelo servidor DHCP.

            if [ -f /var/lib/kea/kea-leases4.csv ]; then
                cat /var/lib/kea/kea-leases4.csv
            else
                echo "Ainda não existem leases atribuídos."
            fi
            ;;
        3)
            echo ""
            echo "--- Últimas 10 linhas do Log ---"

            # 14.3 - Ver últimas linhas do log
            # O que faz: Mostra as últimas 10 linhas do ficheiro de log do Kea DHCPv4.

            if [ -f /var/log/kea/kea-dhcp4.log ]; then
                tail -n 10 /var/log/kea/kea-dhcp4.log
            else
                echo "Ficheiro de log ainda não existe."
            fi
            ;;
        4)
            echo ""
            echo "--- Status do Fail2Ban ---"

            # 14.4 - Verificar status do Fail2Ban
            # O que faz: Mostra o status atual do serviço Fail2Ban e detalhes da jail do Kea DHCP.

            sudo systemctl status fail2ban
            echo ""
            echo "--- Jail KEA DHCP ---"

            # 14.5 - Ver detalhes da jail do KEA DHCP
            # O que faz: Exibe informações específicas sobre a jail do Kea DHCP no Fail2Ban.

            sudo fail2ban-client status kea-dhcp
            ;;
        5)
            echo ""
            echo "A sair do menu de verificações."
            break
            ;;
        *)
            echo ""
            echo "Opção inválida. Por favor, escolha entre 1 e 5."
            ;;
    esac
done

# 15 - Mensagem Final
# O que faz: Exibe uma mensagem final com comandos úteis para o utilizador.

echo ""
echo "=========================================="
echo "   COMANDOS ÚTEIS PARA O FUTURO"
echo "=========================================="
echo ""
echo "- Ver leases: cat /var/lib/kea/kea-leases4.csv"
echo "- Ver logs KEA: tail -f /var/log/kea/kea-dhcp4.log"
echo "- Status KEA: systemctl status kea-dhcp4"
echo "- Status Fail2Ban: sudo fail2ban-client status kea-dhcp"
echo "- Ver IPs banidos: sudo fail2ban-client status kea-dhcp"
echo "- Desbanir IP: sudo fail2ban-client set kea-dhcp unbanip <IP>"
echo ""
echo "Recomenda-se um reboot do sistema para garantir que todas as alterações tenham efeito."
echo "Para reiniciar o sistema, execute: reboot"

#reboot - Caso queira reiniciar automaticamente, descomente esta linha.
