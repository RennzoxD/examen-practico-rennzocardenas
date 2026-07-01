# Examen Practico Final - Seguridad Informatica

**Estudiante:** Rennzo Cardenas
**Curso:** Seguridad Informatica - Unidad IV (SIEM e IA)
**Repositorio:** examen-practico-rennzocardenas

## Entorno de trabajo

Se opto por un entorno **local** (VirtualBox + Ubuntu 24.04 LTS) en lugar de AWS Academy,
ya que el equipo personal cumple los requisitos minimos recomendados (4 GB RAM asignados
a la VM, cumpliendo el minimo de Wazuh All-in-One). Se utilizo una estrategia hibrida:
la VM corre en segundo plano en VirtualBox con adaptador NAT y reenvio de puertos
(2222->22 SSH, 8443->443 Wazuh Dashboard, 8888->8888 Jupyter), controlada desde
PowerShell/SSH en Windows.

## Versiones instaladas

- Ubuntu: 24.04.4 LTS (kernel 6.8.0-124-generic)
- Python: 3.11.9
- Wazuh: 4.9.2 (Indexer + Manager + Dashboard, instalacion All-in-One)
- Librerias Python principales: pandas, matplotlib, seaborn, scikit-learn, joblib

## Comandos de configuracion del entorno

```bash
sudo apt update
sudo apt install -y git nano curl wget unzip

curl -sO https://packages.wazuh.com/4.9/wazuh-install.sh
sudo bash wazuh-install.sh -a
```

En Windows (PowerShell), Python se instalo desde python.org marcando "Add to PATH":

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install pandas matplotlib seaborn scikit-learn jupyter joblib
```

## Acceso a la VM

```powershell
ssh rennzo@127.0.0.1 -p 2222
```

## Estructura del repositorio

- `lab1/` - Analisis forense de logs con Python (scripts, reportes JSON, graficas, evidencias)
- `lab2/` - Reglas de correlacion Wazuh (XML, evidencias de disparo de alertas)
- `lab3/` - Modelo de deteccion de anomalias con ML (notebook, modelo exportado, evidencias)
- `lab4/` - Dashboard de monitoreo SOC (export JSON, evidencias)

## Como reproducir cada laboratorio

### Lab 1 (ejecutado en Windows con venv de Python)
```powershell
cd lab1
python analizar_ssh.py
python analizar_web.py
python visualizar.py
```

### Lab 2 (ejecutado en la VM Ubuntu, vía SSH)
```bash
sudo cp lab2/local_rules_ssh.xml /var/ossec/etc/rules/
sudo cp lab2/local_rules_exfil.xml /var/ossec/etc/rules/
sudo systemctl restart wazuh-manager
sudo bash lab2/simular_bruteforce.sh 45.33.32.156 15
sudo grep "45.33.32.156" /var/ossec/logs/alerts/alerts.log
```

### Lab 3 (ejecutado en la VM Ubuntu vía Jupyter)
```bash
cd lab3
jupyter notebook --no-browser --ip=0.0.0.0 --port=8888
# abrir en Windows: http://127.0.0.1:8888/?token=...
python3 predecir.py nuevo_trafico.csv
```

### Lab 4
Acceder a `https://127.0.0.1:8443` (usuario admin, credenciales generadas por el
instalador de Wazuh en `wazuh-install-files.tar`). Dashboard "SOC - Monitor de
Seguridad" importable desde `lab4/dashboard_soc.json` via Saved Objects > Import.

## Nota tecnica - Lab 2

Durante las pruebas se detecto que la regla nativa de Wazuh 5763 (brute force generico, 
frequency=8/timeframe=120) reinicia el contador de eventos de la regla 5760 antes de que 
un umbral mas alto (10/60s) pudiera cumplirse. Se ajusto la regla personalizada 100050 a 
un umbral de 5 intentos en 30 segundos para que dispare de forma independiente y verificable, 
documentado en el comentario XML de local_rules_ssh.xml.
