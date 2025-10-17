#!/bin/bash
# Devido a limitações de conhecimento, este programa vai operar unicamente sobre um CIDR /24. Esperamos, no futuro, alargar a escolha.

#
# =========================================================================================#
#
# Projeto: Automatização da Configuração de um Servidor DHCP (Classe C)
# Autor: Sérgio Correia / Daniel Santos / Martinho Marques
# Data: 20 09 2025
#
# Descrição:
# Este script foi concebido para simplificar a configuração de um servidor DHCP em CentOS,
# operando em redes de Classe C com um CIDR /24. O programa valida os endereços IP
# inseridos pelo utilizador, configura automaticamente as interfaces de rede e os
# serviços necessários, e garante que a comunicação na rede é segura e funcional.
# O objetivo é fornecer uma solução robusta e de fácil utilização para administradores
# de sistema.
#
# =========================================================================================#
#

# 1 - Instalação do Service
# O que faz: Instala o pacote do servidor DHCP (dhcp-server) no sistema operativo CentOS 9, usando o gestor de pacotes yum. A opção -y aprova automaticamente a instalação. 
# O que faz o -y do yum: Responde "sim" automaticamente a todas as perguntas durante a instalação, facilitando o processo.

sudo yum install dhcp-server -y

# 2 - Criação do backup config
# O que faz: Cria uma cópia de segurança do ficheiro de configuração padrão do DHCP (dhcpd.conf), para que possas reverter as alterações caso algo corra mal.
# O que faz o -e do if: Verifica se o ficheiro de backup já existe, evitando sobrescrever um backup existente. - exists.

if [ ! -e /etc/dhcp/dhcpd.conf.backup ]; then
	sudo cp /etc/dhcp/dhcpd.conf /etc/dhcp/dhcpd.conf.backup
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

	read -p "Digite o IP desejado para o Servidor (Inserir unicamente IPs de Classe C): " IP_SERVIDOR

    TERCEIRO_OCTETO=$(echo "$IP_SERVIDOR" | cut -d'.' -f3)
    QUARTO_OCTETO=$(echo "$IP_SERVIDOR" | cut -d'.' -f4)

    if [[ ! $IP_SERVIDOR =~ ^192\.168\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        echo "Erro 1! IP deve começar com 192.168.x.x."

    elif (( TERCEIRO_OCTETO < 1 || TERCEIRO_OCTETO > 254 )); then
        echo "Erro 2! O 3º octeto deve estar entre 1 e 254."

    elif (( QUARTO_OCTETO < 2 || QUARTO_OCTETO >= 254 )); then
        echo "Erro 3! O 4º octeto deve estar entre 1 e 254."

	else
    	echo "IP válido!"
		break
	fi

done

# 4 - Inserção e validação de IPs
# O que faz: Solicita ao utilizador todos os IPs necessários (Servidor, Range DHCP, Gateway e DNS), valida-os em tempo real
# e permite que, caso a validação final não seja confirmada, o utilizador volte a inserir todos os valores novamente.

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

    # 4.8 - Validação do IP do Servidor em relação ao Range DHCP
	# O que faz: Garante que o IP do servidor não está dentro do range DHCP definido pelo utilizador.
	# O que faz o &&: Operador lógico "E" em bash, usado para combinar múltiplas condições.
	# O que faz o >=: Operador de comparação "maior ou igual" em bash.

    if (( QUARTO_OCTETO_SERVIDOR >= OCTETO_INICIO_RANGE && QUARTO_OCTETO_SERVIDOR <= OCTETO_FIM_RANGE )); then
        echo "Erro 6! O IP do Servidor não pode estar dentro do range DHCP."
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

echo -n "[ "

for i in {1..40}; do
	echo -n "="
	sleep 0.1
done

echo " ]"
echo " Feito!"

# 5 - Configuração da Placa de Rede
# O que faz: Usa o nmcli para configurar a placa de rede (enp0s3) do servidor para um IP estático, desabilitando o DHCP e adicionando o IP do servidor de forma manual. Reinicia a placa para aplicar as alterações.

sudo nmcli connection modify enp0s3 ipv4.method manual
echo "Placa de rede alterada para manual."

sudo nmcli connection modify enp0s3 ipv4.method manual ipv4.addresses "$IP_SERVIDOR/24"
echo "IP alterado para o IP apontado anteriormente."

sudo nmcli connection down enp0s3
sudo nmcli connection up enp0s3
echo "Feito o restart, de novo, da Placa de Rede."

# 6 - Edição do Config do DHCP
# O que faz: Usa o cat para anexar as configurações que o utilizador inseriu ao ficheiro de configuração do DHCP. Assegura que o servidor DHCP opera na sub-rede e com o range de IPs definidos pelo utilizador.

sudo cat << DHCP >> /etc/dhcp/dhcpd.conf
# Configurações base do DHCP
# --------------------------------------
# default lease-time
default-lease-time 600;

# max lease-time
max-lease-time 7200;

# set for this instance to be the primary
authoritative;

# Config lease parameters subnet, netmask, ipaddress, broadcast, route, domain, subnet-mask

subnet ${IP_REDE} netmask 255.255.255.0 {
	# range ip lease
	range ${IP_RANGE_INICIO} ${IP_RANGE_FIM};
	# broadcast
	option broadcast-address ${IP_BROADCAST};
	# subnet-mask
	option subnet-mask 255.255.255.0;
	# dns
	option domain-name-servers ${IP_DNS};
	# gateway
	option routers ${IP_GATEWAY};
	}
DHCP

# 7 - Add o Service à firewall
# O que faz: Configura a firewall (firewalld) para permitir o serviço DHCP (dhcpd), garantindo que os clientes podem comunicar com o servidor. Em seguida, reinicia o serviço da firewall.

sudo firewall-cmd --permanent --add-service=dhcpd
sudo firewall-cmd --permanent --zone=public --add-service=dhcpd
sudo systemctl restart firewalld

# 8 - Restart dos Services
# O que faz: Inicia o serviço do servidor DHCP (dhcpd) e garante que ele arranca automaticamente no boot. O sudo journalctl é usado para mostrar os logs do serviço, confirmando que o DHCP está ativo e a funcionar.

sudo systemctl enable dhcpd
sudo systemctl start dhcpd
sudo systemctl status dhcpd

#echo "Journal, para mostrar que os logs estão active."
#sudo journalctl -u dhcpd -f

echo "Recomenda-se um reboot do sistema para garantir que todas as alterações tenham efeito."
echo "Para reiniciar o sistema, execute: reboot"
sleep 0.5

#reboot - Caso queira reiniciar automaticamente, descomente esta linha.

#============================================================================================================#

# GLOSSÁRIO

# $ # O que faz: Denota uma variável. Quando colocas $ antes de um nome, o Bash substitui o nome pelo valor que a variável armazena. Por exemplo, $IP_SERVIDOR é substituído pelo IP que o utilizador inseriu.

# ${} # O que faz: Permite delimitar o nome de uma variável. É usado para evitar ambiguidades, especialmente quando a variável é seguida por texto ou outro símbolo. Por exemplo, $IP_SUBNET_SERVIDOR_C e ${OCTETO_INICIO_RANGE} são unidos para formar um IP completo.

# " # O que faz: Usado para agrupar uma string e garantir que espaços e caracteres especiais sejam tratados como parte do mesmo valor. Sem as aspas, um comando como echo Hello World imprimiria duas palavras em vez de uma só frase.

# << DHCP # O que faz: Indica o início de um "heredoc" (here document). Permite que o script leia múltiplas linhas de texto e as direcione para um comando, como o cat. O Bash lê as linhas até encontrar a palavra-chave DHCP no início de uma nova linha.

# >> # O que faz: É um operador de redirecionamento de saída. Ele anexa (append) a saída de um comando ao final de um ficheiro, sem apagar o conteúdo existente. Por exemplo, cat << DHCP >> /etc/dhcp/dhcpd.conf anexa a configuração ao ficheiro DHCP sem apagar as linhas anteriores.

# | # O que faz: É o "pipe". Ele direciona a saída de um comando para a entrada de outro. Por exemplo, no teu script, echo "$IP_SERVIDOR" | cut -d'.' -f3 envia o IP do servidor para o comando cut.

# #!/bin/bash # O que faz: É um "shebang". Diz ao sistema operativo que o script deve ser executado pelo interpretador bash, garantindo que o código é processado corretamente.

# read -p # O que faz: É um comando do Bash que lê a entrada do utilizador a partir da linha de comando. A opção -p permite que se apresente uma mensagem ("prompt") ao utilizador antes de ler a entrada, como por exemplo, "Digite o IP desejado".

# sudo # O que faz: Executa um comando com privilégios de superutilizador (root). É essencial para comandos que alteram as configurações do sistema, como instalar pacotes (yum), modificar ficheiros de configuração ou gerir serviços.

# yum # O que faz: É o gestor de pacotes padrão no CentOS. É usado para instalar, remover ou atualizar software. O comando yum install dhcp-server -y instala o serviço DHCP e a opção -y responde "sim" automaticamente a todas as perguntas.

# cut # O que faz: É um comando que corta uma secção de um texto. No teu script, ele usa o ponto (-d'.') como delimitador para extrair octetos específicos de um endereço IP, como o primeiro, o terceiro, ou o quarto.

# while # O que faz: Cria um loop que se repete enquanto uma condição for verdadeira. No teu script, ele é crucial para validar os inputs do utilizador, forçando-o a inserir dados corretos até que a condição do loop seja falsa.

# nmcli # O que faz: É uma ferramenta de linha de comando para controlar o NetworkManager. É usado para configurar a placa de rede de forma manual, atribuindo um endereço IP estático ao servidor.

# firewall-cmd # O que faz: É o comando usado para gerir as regras da firewall. O teu script usa-o para permitir o serviço dhcpd na firewall, abrindo a porta 67 para que o servidor possa receber pedidos.

# systemctl # O que faz: É a principal ferramenta para controlar serviços do sistema (systemd). É usada para iniciar, parar, reiniciar ou ativar o serviço dhcpd para que este comece a funcionar automaticamente no arranque do sistema.

# reboot # O que faz: Reinicia o sistema operativo. É o passo final para garantir que todas as configurações de rede e serviços são aplicadas corretamente no arranque.

#===========================================================================================================#