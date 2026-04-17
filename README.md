🦅 Scout Network(OSINT Toolkit & Monitor)

Bem-vindo ao Projeto Scout Network, um conjunto prático de ferramentas desenvolvidas em Python para análise de tráfego, Inteligência de Fontes Abertas (OSINT) e Deteção de Intrusões Baseada em Host (HIDS).

💡 Propósito Educacional: Este projeto foi idealizado e construído inteiramente do zero, usando conceitos que vinha em mente e por pura prototipagem, tendo como inspiração wireshark e ferramentas mais elaboradas, não tendo base com nenhum propósito final. Ele nasceu puramente de ideias voltadas para o estudo, prática e entendimento profundo de como as redes de computadores e a cibersegurança funcionam "por baixo do capô", servindo como um excelente laboratório prático de experimentação.

Este repositório contém duas aplicações distintas, criadas para diferentes necessidades de cibersegurança e utilitários de rede. Ambas utilizam Raw Sockets para interceção de pacotes ao nível do IP, sem necessidade de drivers de captura externos (como o WinPcap/Npcap).

⚠️ NOTA TÉCNICA IMPORTANTE (Escopo de Rede): Como este projeto é executado diretamente na máquina local de um utilizador, a sua visão de captura está limitada ao tráfego que entra ou sai da própria máquina. Ele não monitoriza o tráfego de outros computadores da sua rede Wi-Fi/LAN (ex: o telemóvel do seu vizinho), a menos que a máquina que roda o script esteja configurada para atuar como um Ponto de Acesso (Access Point) ou Gateway de rede. É uma ferramenta de diagnóstico e defesa pessoal (Host-Based).

🧭 As Aplicações

O projeto está dividido em dois scripts principais. Escolha a ferramenta que melhor se adapta ao seu objetivo:

1. Scout GUI Toolkit (Scout_gui_toolkit.py)

O Canivete Suíço de OSINT: Uma ferramenta exploratória, de utilitários e de reconhecimento ativo com interface gráfica completa.

Principais Funcionalidades:

Ferramentas OSINT & Criptografia: Inclui pesquisa avançada de WHOIS/GeoIP, Gerador de Senhas Seguras, Calculadora de Força Bruta (Entropia) e Extrator de Cabeçalhos HTTP.

Monitorização Local (Sniffer): Captura e disseca pacotes TCP, UDP e ICMP da sua interface de rede, com extração de SNI (Server Name Indication) para identificar domínios acessados mesmo em conexões HTTPS.

Scanner de LAN e Portas: Integração com o motor Nmap para descobrir outros dispositivos na mesma rede local e mapear portas abertas com deteção de serviço (-sV).

Análise Comportamental Básica (NBA): Categoriza automaticamente se o seu tráfego atual parece ser Streaming, Gaming, Download ou Navegação Web.

2. Scout Monitor (Scout_monitor.py)

O Guarda-Costas Pessoal (HIDS): Um Sistema de Deteção de Intrusões (IDS) estritamente focado em proteger a máquina onde está a correr. Trabalha de forma autônoma para detetar anomalias no seu tráfego de rede.

Principais Funcionalidades:

Motor de Alertas e Ameaças (Threat Analyzer): Roda em segundo plano avaliando riscos de segurança em tempo real.

Deteção de Exfiltração: Alerta se a sua máquina começar a enviar volumes massivos de dados (Upload alto) para um IP não reconhecido/público (comportamento típico de roubo de dados/malware).

Alerta de Credenciais Inseguras: Dispara um alerta "CRÍTICO" se detetar credenciais (ex: password=, login=) a serem transmitidas em texto claro através da rede.

Sistema de Alarmes Intrusivos: Em caso de risco Alto ou Crítico, a aplicação muda de cor (para vermelho escuro), emite um som de aviso no sistema e traz a janela imediatamente para o primeiro plano.

🛠️ Detalhes Técnicos e Arquitetura "Pro"

Ambas as ferramentas foram desenhadas com foco em performance e estabilidade:

Event Queue (Fila de Tarefas Thread-Safe): Evita o bloqueio da interface gráfica (o famoso "Não Responde") usando queue.Queue(). O tráfego intenso é processado em lotes controlados (UI Throttling).

Gestão de Memória (Garbage Collector): Uma thread dedicada limpa as conexões inativas da RAM periodicamente, prevenindo "Memory Leaks" em monitorizações contínuas de longa duração.

Auto-Elevação: Os scripts requerem e solicitam automaticamente privilégios de Administrador/Root necessários para ligar Raw Sockets.

⚙️ Instalação e Requisitos

Pré-requisitos

Python 3.8+ instalado no sistema.

Nmap instalado nativamente no sistema operativo:

Windows: Baixe e instale a partir de nmap.org/download. O script detecta o caminho padrão.

Linux: sudo apt-get install nmap

Instalação

Clone o repositório:
```bash
git clone [https://github.com/Zidszs/Scout_OSINT_Toolkit.git](https://github.com/Zidszs/Scout_OSINT_Toolkit.git)
cd Scout_OSINT_Toolkit
```

Instale as bibliotecas Python necessárias:
```bash
pip install requests python-nmap
```

Como Executar

Para abrir a interface de utilitários e reconhecimento:
```bash
python Scout_gui_toolkit.py
```

Para iniciar o monitor de alertas de segurança em segundo plano:
```bash
python Scout_monitor.py
```

(Nota: O script tentará elevar as permissões no Windows automaticamente. Em Linux, execute com sudo para permitir a captura de pacotes).

⚠️ Aviso Legal e Ética

Este conjunto de ferramentas foi desenvolvido estritamente para fins educacionais, testes de penetração em laboratório e defesa cibernética pessoal. A interceção e análise de tráfego deve ser feita apenas em máquinas e redes que lhe pertencem ou onde possui autorização explícita. O autor não se responsabiliza pelo uso indevido deste software.

🤝 Contribuições

Bugs, sugestões e "Pull Requests" são bem-vindos! Se quiser adicionar novas heurísticas de deteção ao Scout Monitor ou novas ferramentas ao Toolkit, sinta-se à vontade para contribuir.

Licença: MIT
