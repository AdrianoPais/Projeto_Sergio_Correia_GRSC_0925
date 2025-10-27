#!/bin/bash
# Devido a limitações de conhecimento, este programa vai operar unicamente sobre um CIDR /24. Esperamos, no futuro, alargar a escolha.

#
# =========================================================================================#
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
# =========================================================================================#
#

# Commit

# 1 - Instalação do Service
# O que faz: Instala o servidor DHCP KEA usando o gestor de pacotes DNF. Ao contrário de DHCP tradicional (dhcpd), o KEA vai usar o dnf para instalação.
# O que faz o -y: Responde "sim" automaticamente a todas as perguntas durante a instalação, permitindo que o processo seja não interativo.

# O que difere de DHCP tradicional (dhcpd): O KEA DHCP4 é uma alternativa moderna ao dhcpd, instalado em CentOS 10 como norma.

set -e

chmod 775 config_kea_dhcp.sh

sudo dnf install -y kea-dhcp4

# 2 - Criação do backup config
# O que faz: Cria uma cópia de segurança do ficheiro de configuração original do KEA DHCP4, caso este exista e ainda não tenha sido feito um backup.
# O que faz o -f: Verifica se o ficheiro especificado existe. - file
# O que faz o -e: Verifica se o ficheiro ou diretório especificado existe (usado aqui para garantir que o backup não seja sobrescrito). - Exists

# O que difere de DHCP tradicional (dhcpd): O ficheiro de configuração do KEA DHCP4 é diferente do dhcpd, por isso o caminho do ficheiro também é diferente.

if [ -f /etc/kea/kea-dhcp4.conf ] && [ ! -e /etc/kea/kea-dhcp4.conf.backup ]; then
	sudo cp /etc/kea/kea-dhcp4.conf /etc/kea/kea-dhcp4.conf.backup
fi

# 3 - Validação do IP da Máquina
# Verifica se o IP pertence à Classe C (192.168.x.x). Depois, garante que o terceiro octeto do IP não é 0 nem 255.

while true; do

	# 3.1 - Validação da Classe C
	# O que faz: Verifica se o IP do servidor pertence à Classe C (192.168.x.x) e se os octetos estão dentro dos intervalos válidos (1-254).
	# O que faz o =~: Operador de correspondência de expressão regular em bash, usado para validar o formato do IP. Como funciona: Verifica se a variável à esquerda corresponde ao padrão regex à direita.
	# O que faz o ^: Indica o início da string.
	# O que faz o $: Indica o fim da string.
	# O que faz o \.: Escapa o ponto, que é um caractere especial em regex, para que seja interpretado literalmente.
	# O que faz o [0-9]{1,3}: Corresponde a qualquer número entre 0 e 999, mas a validação adicional garante que os octetos estão entre 1 e 254.

    # O que difere de DHCP tradicional: Nada nesta secção difere do DHCP tradicional, pois a validação do IP é independente do serviço DHCP utilizado.

	read -p "Digite o IP desejado para o Servidor (Inserir unicamente IPs de Classe C): " IP_SERVIDOR

	TERCEIRO_OCTETO=$(echo "$IP_SERVIDOR" | cut -d'.' -f3)
	QUARTO_OCTETO=$(echo "$IP_SERVIDOR" | cut -d'.' -f4)

	if [[ ! $IP_SERVIDOR =~ ^192\.168\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
		echo "Erro 1! IP deve começar com 192.168.x.x."

	elif (( TERCEIRO_OCTETO < 0 || TERCEIRO_OCTETO > 254 )); then
		echo "Erro 2! O 3º octeto deve estar entre 1 e 254."

	elif (( QUARTO_OCTETO < 2 || QUARTO_OCTETO >= 254 )); then
		echo "Erro 3! O 4º octeto deve estar entre 2 e 253."

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
    read -p "Inserir o 4º octeto do IP de Gateway (1 ou 254): " OCTETO_IP_GATEWAY
    read -p "Inserir o IP de DNS (8.8.8.8 ou 1.1.1.1): " IP_DNS

    # 4.2 - Extrair a subrede do servidor
	# O que faz: Usa o cut para extrair os primeiros três octetos do IP do servidor, formando a sub-rede.
	# O que faz o cut: Divide uma string em partes com base em um delimitador especificado (neste caso, o ponto ".") e extrai as partes desejadas. - cut -d'.' -f1-3 ( Semelhante ao .split em Python)

    IP_SUBNET_SERVIDOR_C=$(echo "$IP_SERVIDOR" | cut -d'.' -f1-3)

    # 4.3 - Criar IPs completos
	# O que faz: Concatena a sub-rede com os octetos fornecidos pelo utilizador para formar os IPs completos necessários para a configuração do DHCP.

    IP_RANGE_INICIO="${IP_SUBNET_SERVIDOR_C}.${OCTETO_INICIO_RANGE}"
    IP_RANGE_FIM="${IP_SUBNET_SERVIDOR_C}.${OCTETO_FIM_RANGE}"
    IP_GATEWAY="${IP_SUBNET_SERVIDOR_C}.${OCTETO_IP_GATEWAY}"
    IP_REDE="${IP_SUBNET_SERVIDOR_C}.0"

    # 4.4 - Octetos individuais para validações
	# O que faz: Extrai os octetos individuais do IP do servidor e do DNS para facilitar as validações subsequentes.

    OCTETO_IP_DNS=$(echo "$IP_DNS" | cut -d'.' -f4)

    # 4.5 - Validação do IP da Gateway
	# O que faz: Verifica se o 4º octeto do IP da gateway é 1 ou 254, garantindo que a gateway está configurada corretamente.

    if [[ "$OCTETO_IP_GATEWAY" != "1" && "$OCTETO_IP_GATEWAY" != "254" ]]; then
        echo "Erro 4! O IP do Gateway só deve ser 1 ou 254."
        continue
    fi

    # 4.6 - Cálculo do Broadcast
	# O que faz: Calcula o IP de broadcast com base no 4º octeto da gateway. Se a gateway for .1, o broadcast será .255, e vice-versa.

    IP_BROADCAST="${IP_SUBNET_SERVIDOR_C}.255"

    # 4.7 - Validação do IP de DNS
	# O que faz: Verifica se o IP de DNS é um dos endereços públicos comuns
	# O que faz o !=: Operador de negação em bash, usado para verificar se uma condição não é verdadeira.
	# O que faz o &&: Operador lógico "E" em bash, usado para combinar múltiplas condições.

    if [[ "$IP_DNS" != "8.8.8.8" && "$IP_DNS" != "1.1.1.1" ]]; then
        echo "Erro 5! O IP de DNS só pode ser 8.8.8.8 (Google) ou 1.1.1.1 (Cloudflare)."
        continue
    fi

    # 4.8 - Validação do Range DHCP
    # O que faz: Garante que o início do range DHCP é menor que o fim e que o IP do servidor não está dentro do range DHCP.
    # O que faz o >=: Operador de comparação em bash, usado para verificar se um valor é maior ou igual a outro.


    if (( OCTETO_INICIO_RANGE >= OCTETO_FIM_RANGE )); then
    echo "Erro 6! Início do range deve ser menor que o fim."
    continue
    fi

    QUARTO_OCTETO_SERVIDOR=$(echo "$IP_SERVIDOR" | cut -d'.' -f4)

    if (( QUARTO_OCTETO_SERVIDOR >= OCTETO_INICIO_RANGE && QUARTO_OCTETO_SERVIDOR <= OCTETO_FIM_RANGE )); then
        echo "Erro 7! O IP do Servidor não pode estar dentro do range DHCP."
        continue
    fi

    # 4.9 - Mostrar resumo para confirmação
	# O que faz: Exibe um resumo dos IPs configurados para o utilizador revisar antes da confirmação final.

	echo -n "[ "

	for i in {1..40}; do
		echo -n "="
		sleep 0.2
	done

	echo " ]"

    echo "Resumo dos IPs configurados:"
    echo "IP Servidor: $IP_SERVIDOR"
    echo "Range DHCP: $IP_RANGE_INICIO - $IP_RANGE_FIM"
    echo "IP Gateway: $IP_GATEWAY"
    echo "IP DNS: $IP_DNS"
    echo "IP Broadcast: $IP_BROADCAST"
    echo "IP de Rede: $IP_REDE"


    # 4.10 - Solicitar confirmação final
	# O que faz: Pede ao utilizador para confirmar se os IPs estão corretos. Se a resposta for "y" ou "Y", o loop termina; caso contrário, o utilizador pode reinserir os valores.
	# O que faz o read -p: Exibe uma mensagem para o utilizador antes de esperar pela entrada.

    read -p "Validação básica concluída! Está tudo correto? (y/n): " VERIFICACAO

done

echo "Verificação concluída!"

echo "Aguarde enquanto aplicamos as definições!"

# Extra - Barra de Progresso para a espera da aplicação nova das configurações
# O que faz o -n do echo: Impede o echo de adicionar uma nova linha após a saída, permitindo que a barra de progresso seja exibida na mesma linha.

# O que difere de DHCP tradicional: Nada nesta secção difere do DHCP tradicional, pois a barra de progresso é apenas uma funcionalidade estética.

echo -n "[ "

for i in {1..40}; do
	echo -n "="
	sleep 0.1
done

echo " ]"
echo " Feito!"


# 5 - Deteção e Configuração da Placa de Rede
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

# 5.1 Validação final da interface
# O que faz: Verifica se a interface especificada pelo utilizador existe no sistema.

# O que faz o dev/null: Redireciona a saída padrão para /dev/null, suprimindo qualquer saída do comando no terminal.
# O que faz o &>: Redireciona tanto a saída padrão quanto a saída de erro para o destino especificado (neste caso, /dev/null).
# O que faz o exit 1: Sai do script com um código de status 1, indicando que ocorreu um erro.

if ! nmcli connection show "$INTERFACE" &>/dev/null; then
    echo "Erro: A interface '$INTERFACE' não existe no sistema!"
    echo "Interfaces disponíveis:"
    nmcli connection show
    exit 1
fi

echo "A usar interface: $INTERFACE"

echo "Configurando interface de rede..."
sudo nmcli connection modify "$INTERFACE" \
    ipv4.method manual \
    ipv4.addresses "$IP_SERVIDOR/24" \
    ipv4.gateway "$IP_GATEWAY" \
    ipv4.dns "$IP_DNS"
echo "Configurações de rede aplicadas."

echo "A reiniciar a interface de rede..."
sudo nmcli connection down "$INTERFACE" && sudo nmcli connection up "$INTERFACE"
echo "Restart da interface $INTERFACE concluído."

# Verificar a configuração
echo "A verificar a configuração de rede..."
ip addr show "$INTERFACE"

# 6 - Edição do Config do DHCP (Kea)
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

# Add directory and file permissions before Kea config
sudo mkdir -p /etc/kea
sudo chmod 755 /etc/kea
sudo chown root:root /etc/kea

sudo mkdir -p /var/log/kea
sudo chmod 755 /var/log/kea
sudo chown root:root /var/log/kea

sudo tee /etc/kea/kea-dhcp4.conf << DHCP
{
  "Dhcp4": {
    "interfaces-config": { "interfaces": [ "${INTERFACE}" ] },
    "lease-database": {
      "type": "memfile",
      "lfc-interval": 3600
    },
    "valid-lifetime": 7200,
    "renew-timer": 1800,
    "rebind-timer": 3600,
    "option-data": [
      { "name": "domain-name-servers", "data": "${IP_DNS}" },
      { "name": "routers", "data": "${IP_GATEWAY}" },
      { "name": "subnet-mask", "data": "255.255.255.0" },
      { "name": "broadcast-address", "data": "${IP_BROADCAST}" }
    ],
    "subnet4": [
      {
        "subnet": "${IP_REDE}/24",
        "pools": [ { "pool": "${IP_RANGE_INICIO} - ${IP_RANGE_FIM}" } ]
      }
    ],
    "loggers": [
      {
        "name": "kea-dhcp4",
        "output_options": [ { "output": "/var/log/kea-dhcp4.log" } ],
        "severity": "INFO",
        "debuglevel": 0
      }
    ]
  }
}
DHCP

# Set proper config file permissions
sudo chmod 644 /etc/kea/kea-dhcp4.conf
sudo chown root:root /etc/kea/kea-dhcp4.conf

# Create and set permissions for log file
sudo touch /var/log/kea-dhcp4.log
sudo chmod 644 /var/log/kea-dhcp4.log
sudo chown root:root /var/log/kea-dhcp4.log

# Add error handling for service restart
echo "Validating Kea DHCP4 configuration..."
if ! sudo kea-dhcp4 -t /etc/kea/kea-dhcp4.conf; then
    echo "Error: Invalid configuration detected. Please check the configuration file."
    exit 1
fi

# 7 - Add o Service à firewall
# O que faz: Configura a firewall (firewalld) para permitir o serviço DHCP (kea/dhcp), garantindo que os clientes podem comunicar com o servidor.

# O que difere de DHCP tradicional: Nada nesta secção difere do DHCP tradicional, pois a configuração da firewall é independente do serviço DHCP utilizado.

sudo firewall-cmd --permanent --add-service=dhcp
sudo systemctl restart firewalld

# 8 - Restart dos Services
# O que faz: Inicia o serviço do servidor DHCP (dhcpd) e garante que ele arranca automaticamente no boot. O sudo journalctl é usado para mostrar os logs do serviço, confirmando que o DHCP está ativo e a funcionar.
# O que faz o -t do kea-dhcp4: Testa a configuração do Kea DHCPv4 antes de iniciar o serviço, garantindo que não há erros no ficheiro de configuração.

# O que difere de DHCP tradicional: Nada nesta secção difere do DHCP tradicional, pois o controlo dos serviços é independente do serviço DHCP utilizado.

sudo kea-dhcp4 -t /etc/kea/kea-dhcp4.conf
sudo systemctl enable --now kea-dhcp4
sudo systemctl restart kea-dhcp4
sudo systemctl status kea-dhcp4

#echo "Journal, para mostrar que os logs estão active."
#sudo journalctl -u dhcpd -f

echo "Recomenda-se um reboot do sistema para garantir que todas as alterações tenham efeito."
echo "Para reiniciar o sistema, execute: reboot"
sleep 0.5

# 9 - Listar comandos disponíveis no Kea Shell (opcional)
# O que faz: Lista os comandos disponíveis no Kea Shell, uma ferramenta de linha de comandos para interagir com o servidor DHCP KEA.

#sudo kea-shell --host 127.0.0.1 --port 8000 list-commands

# 10 - Configuração final
# O que faz: Oferece ao utilizador a opção de executar verificações finais, como verificar o status do serviço, listar os leases atribuídos e visualizar as últimas linhas do log.
# O que faz o case: Estrutura de controle em bash que permite executar diferentes blocos de código com base na opção escolhida pelo utilizador.
# O que faz o sudo systemctl status kea-dhcp4: Verifica o status do serviço Kea DHCPv4, mostrando se está ativo e a funcionar corretamente.
# O que faz o cat /var/lib/kea/kea-leases4.csv: Exibe o conteúdo do ficheiro de leases, mostrando os endereços IP atribuídos aos clientes DHCP.
# O que faz o tail -n 10 /var/log/kea-dhcp4.log: Mostra as últimas 10 linhas do ficheiro de log do Kea DHCPv4, permitindo ao utilizador ver eventos recentes e mensagens de erro, se houver.
# O que faz o tail -f /var/log/kea-dhcp4.log: Permite ao utilizador monitorizar o ficheiro de log em tempo real, exibindo novas entradas à medida que são adicionadas.
# O que faz o systemctl status kea-dhcp4: Permite ao utilizador verificar o status do serviço Kea DHCPv4 a qualquer momento.

# O que faz o ;;: Indica o fim de um bloco de código dentro de uma estrutura case em bash, semelhante a um break.
# O que faz o *) : Captura qualquer entrada que não corresponda às opções listadas anteriormente, funcionando como um "default" em outras linguagens de programação.
# O qur faz o esac: Indica o fim da estrutura case em bash.

echo ""
echo "Deseja executar verificações finais?"
echo "1) Verificar status do serviço;"
echo "2) Ver leases atribuídos;"
echo "3) Ver últimas linhas do log;"
echo "4) Sair."
echo ""
read -p "Escolha uma opção (1-4): " OPCAO_VERIFICACAO

case $OPCAO_VERIFICACAO in
    1)
        echo ""
        echo "--- Status do Serviço Kea DHCP4 ---"
        sudo systemctl status kea-dhcp4
        ;;
    2)
        echo ""
        echo "--- Leases Atribuídos ---"
        if [ -f /var/lib/kea/kea-leases4.csv ]; then
            cat /var/lib/kea/kea-leases4.csv
        else
            echo "Ainda não existem leases atribuídos."
        fi
        ;;
    3)
        echo ""
        echo "--- Últimas 10 linhas do Log ---"
        if [ -f /var/log/kea-dhcp4.log ]; then
            tail -n 10 /var/log/kea-dhcp4.log
        else
            echo "Ficheiro de log ainda não existe."
        fi
        ;;
    4)
        echo ""
        echo "A sair sem verificações."
        ;;
    *)
        echo ""
        echo "Opção inválida. A sair sem verificações."
        ;;
esac

echo ""
echo "Comandos úteis para o futuro:"
echo "- Ver leases: cat /var/lib/kea/kea-leases4.csv"
echo "- Ver logs: tail -f /var/log/kea-dhcp4.log"
echo "- Status: systemctl status kea-dhcp4"
echo ""
echo "Recomenda-se um reboot do sistema para garantir que todas as alterações tenham efeito."
echo "Para reiniciar o sistema, execute: reboot"

#reboot - Caso queira reiniciar automaticamente, descomente esta linha.
