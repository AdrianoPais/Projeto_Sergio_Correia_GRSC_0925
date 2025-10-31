Projeto: Servidor DNS (BIND) e DHCP (KEA) - Classe C

Este projeto inclui dois scripts BASH (config_dns.sh e config_kea.sh) para automatizar a instalação e configuração de serviços essenciais de rede (DNS e DHCP) em máquinas virtuais CentOS Stream 10.

A arquitetura assume uma rede de Classe C (/24), onde o servidor KEA também atua como Gateway/NAT.

Requisitos e Preparação

Antes de começar, certifique-se de que está a usar o CentOS Stream 10 e de que tem privilégios sudo.

    Necessário: Os scripts esperam que a máquina tenha pelo menos duas interfaces de rede (ou uma interface única, dependendo da configuração final do config_dns.sh).

    Limpeza: Garanta que o pacote dos2unix está instalado (sudo dnf install dos2unix).

Guia de Execução

Execute os scripts pela ordem abaixo. O set -e garante que o script para se houver algum erro de instalação.

Fase 1: Configuração do Servidor DNS (BIND)

O script config_dns.sh cria o servidor BIND, configura as zonas localmente e prepara a máquina para usar o seu próprio DNS.

    Executar:
    Bash

    ./config_dns.sh

    Entrada de Dados: Será solicitado:

        O Domínio (e.g., empresa.local).

        O IP Estático do servidor DNS.

        O Gateway (IP do router ou do servidor DHCP/NAT).

        O nome da Interface de Rede (ex: ens192).

    Resultado Esperado: O BIND é instalado, as zonas são criadas e validadas, e a Firewall permite o tráfego DNS (porta 53).

Fase 2: Configuração do Servidor DHCP (KEA) e NAT

O script config_kea.sh configura o servidor KEA para distribuir IPs e define as regras de roteamento (NAT) para acesso à Internet, assumindo que este servidor é o Gateway.

    Executar:
    Bash

    ./config_kea.sh

    Entrada de Dados: Será solicitado:

        IP Estático do Servidor (o seu IP de LAN).

        Range DHCP (início e fim do 4º octeto).

        IP DNS BIND (o mesmo IP que definiu na Fase 1, 192.168.1.10, ou outro servidor DNS na LAN).

        Nomes das interfaces WAN e LAN.

        DNS Externo (8.8.8.8 ou 1.1.1.1) para o servidor/Gateway.

    Resultado Esperado: O Kea é configurado, o Roteamento/NAT é ativado e a Firewall é ajustada para DHCP.

Verificação e Testes Finais

Use os comandos abaixo para confirmar que os serviços estão a funcionar e seguros.

I. Testes de Validação do DNS (no Servidor BIND)

    Status do Serviço:
    Bash

sudo systemctl status named

Resolução de Domínios Internos:
Bash

dig empresa.local

Resolução Externa (via Forwarder):
Bash

dig www.google.com

Verificar Logs:
Bash

    tail -f /var/log/named/bind_queries.log

II. Testes de Validação do DHCP (no Servidor KEA)

    Status do Serviço:
    Bash

sudo systemctl status kea-dhcp4

Ver Leases Atribuídos (IPs entregues):
Bash

    cat /var/lib/kea/kea-leases4.csv

    Teste num Cliente: Num cliente Linux/Windows, use o comando para obter um IP automaticamente (e.g., dhclient no Linux) e verifique se o Gateway e o DNS recebidos são os IPs estáticos que definiu.

Segurança e Operacionalidade

    IPs Estáticos: O KEA garante que o Servidor, o DNS e o Gateway estão fora do pool de IPs distribuídos dinamicamente.

    Segurança: A Firewall (Firewalld) está configurada em ambos os servidores, permitindo apenas tráfego essencial (DNS: porta 53, DHCP: porta 67) e o NAT está funcional.

    Persistência: As configurações de rede e as regras de NAT/Firewall são salvas para sobreviverem ao reboot.

    Recomendação: É altamente recomendado que se configure o Fail2Ban no servidor DNS (BIND) para proteção contra ataques de negação de serviço (DDoS/DNS Amplification).
