# Projeto: Servidor DNS (BIND) e DHCP (KEA) - Classe C

Este projeto inclui dois scripts Bash (config_dns.sh e config_kea.sh) que automatizam a instalação e configuração de dois serviços essenciais de rede: DNS (BIND) e DHCP (KEA) em máquinas CentOS Stream 10. A arquitetura assume uma rede Classe C (/24), onde o servidor KEA também pode atuar como Gateway/NAT para garantir saída para a Internet.

## Requisitos e Preparação

Antes de iniciar, é necessário garantir:

Sistema operativo CentOS Stream 10 instalado e atualizado.

Permissões sudo para executar os scripts.

O pacote dos2unix instalado (necessário para evitar erros de formatação).

As máquinas podem ter:

Uma interface de rede (servidor DNS isolado com LAN Segment), ou

Duas interfaces de rede (servidor DHCP atuando como Gateway/NAT).

## Guia de Execução

Deve-se executar os scripts pela ordem apresentada abaixo. Ambos param automaticamente caso seja detetado um erro crítico.


## Fase 1 — Configuração do Servidor DNS (BIND)

O script config_dns.sh instala e configura o BIND, cria as zonas direta e inversa e ajusta a firewall para permitir tráfego DNS.

Durante a execução serão solicitados:

Nome de domínio (ex.: empresa.local)

IP estático do servidor DNS

Gateway da rede

Interface de rede principal (ex.: ens192)

### Resultado esperado:

BIND instalado e ativo

Zonas criadas e validadas

Servidor a resolver nomes internos e externos

Firewall configurada para permitir DNS (porta 53)


## Fase 2 — Configuração do Servidor DHCP (KEA) + NAT

O script config_kea.sh configura o Kea DHCP para distribuir endereços IP e ativa o encaminhamento / tradução de endereços se o servidor atuar como Gateway.

Durante a execução serão solicitados:

IP estático do servidor (na LAN)

Intervalo de distribuição do DHCP (range)

IP do servidor DNS interno (o configurado na fase anterior)

Interface da LAN e interface da WAN

DNS externo (ex.: 8.8.8.8)

### Resultado esperado:

Servidor DHCP ativo e funcional

Distribuição automática de IPs, máscara, gateway e DNS aos clientes

NAT e routing configurados (caso o servidor seja Gateway)

Firewall ajustada para DHCP e tráfego WAN

## Testes de Verificação
Validação do DNS (BIND)

Confirmar que o serviço está ativo

Testar resolução interna (nomes da rede)

Testar resolução externa (com forwarders)

Verificar logs para confirmar consultas DNS

Validação do DHCP (KEA)

Confirmar que o serviço está ativo

Verificar ficheiro de leases para confirmar atribuição de IPs

Testar cliente Linux/Windows para receber IP automaticamente

Confirmar que gateway e DNS recebidos correspondem aos definidos no servidor

Segurança e Operacionalidade

O servidor reserva os IPs estáticos do DNS e do Gateway fora do range DHCP.

A firewall está configurada para permitir apenas tráfego essencial:

DNS: porta 53

DHCP: porta 67/UDP

As regras de firewall e NAT são persistentes após reinício.

### Recomendação adicional: Instalar e configurar Fail2ban no servidor BIND para aumentar a proteção contra ataques e abuso de resolução.
