# DDoS Traffic Detector / Mitigator

[![CI](https://github.com/Believe-sec-io/ddos-traffic-detector/actions/workflows/ci.yml/badge.svg)](https://github.com/Believe-sec-io/ddos-traffic-detector/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.11%20%7C%203.14-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)

Un détecteur d'anomalies de trafic réseau écrit en Python, capable de repérer
(et d'atténuer) des attaques par déni de service distribué (**DDoS**) :

- **SYN flood** (abus de connexions half-open)
- **UDP flood** (y compris trafic de réflexion/amplification)
- **ICMP flood** (ping flood)
- **Volumetric flood** (saturation brute en paquets/s)
- **Single-source flood** (une seule IP qui sature le lien)
- **Distributed flood** (attaque multi-sources, sans IP unique à bloquer)
- **Adaptive anomaly** (pic statistiquement anormal vs. la ligne de base du réseau)

Il fonctionne en **capture live** (Npcap/libpcap via scapy) ou en **replay de
fichiers `.pcap`** (idéal pour la démo, les tests et l'analyse post-incident).

## Avertissement légal / éthique (IMPORTANT)

Cet outil est destiné **uniquement** à la surveillance de réseaux que vous
possédez ou pour lesquels vous disposez d'une autorisation écrite explicite.
L'atténuation est en **`dry_run: true` par défaut** : aucune règle de pare-feu
n'est créée tant que vous ne l'activez pas explicitement. N'utilisez jamais ce
projet pour attaquer, sonder ou perturber un système tiers (cela est illégal).

## Architecture

```
main.py                      Point d'entrée CLI
config.yaml                  Seuils de détection / atténuation
src/
  models.py                  PacketEvent, Alert, Protocol, AlertType, Severity
  stats.py                   TrafficWindow (fenêtre glissante) + BaselineTracker (baseline adaptative)
  detector.py                AnomalyDetector : 7 règles de détection (une méthode par règle)
  mitigator.py               Mitigator : blocage d'IP (dry-run ou pare-feu Windows)
  capture.py                 Capture live (scapy) + replay .pcap -> PacketEvent
  engine.py                  DetectionEngine : capture -> fenêtres -> détection -> atténuation
  logger_config.py           Configuration du logging
  cli.py                     Sous-commandes `live` et `replay`
tools/
  generate_sample_pcap.py    Génère un .pcap de démo (trafic normal + attaques)
tests/                       Suite pytest (unitaires + intégration + régression)
```

Le cœur de la détection (`models`, `stats`, `detector`, `mitigator`, `engine`)
**ne dépend pas de scapy ni du réseau** : c'est ce qui rend la suite de tests
rapide, déterministe et exécutable sans privilèges administrateur. scapy n'est
importé que dans `capture.py`.

## Installation

```powershell
cd "c:\Users\SocAnalyst\bussiness sites\App\ddos-traffic-detector"
python -m pip install -r requirements.txt        # scapy + PyYAML
python -m pip install -r requirements-dev.txt    # + pytest
```

Sur **Windows**, la capture live nécessite en plus **Npcap**
(https://npcap.com/) — vérifiable avec :

```powershell
Get-Service npcap
```

## Utilisation

### 1. Démo hors-ligne (aucun privilège requis, recommandé pour commencer)

```powershell
python tools\generate_sample_pcap.py sample_attack.pcap   # trafic normal + UDP flood + SYN flood
python main.py replay sample_attack.pcap --speed 0        # --speed 0 = aussi vite que possible
```

Sortie attendue :

```
... [WARNING] ddos_detector.engine: ALERT[SYN_FLOOD/HIGH] SYN ratio 100.0% exceeds threshold 60.0% (500 SYNs)
... [WARNING] ddos_detector.engine: ALERT[SOURCE_FLOOD/HIGH] Source 203.0.113.5 sending 500.0 pps exceeds threshold 200.0 pps
... [INFO] ddos_detector.mitigator: [DRY-RUN] Would block IP 203.0.113.5 until ... | reason: Source 203.0.113.5 sending 500.0 pps exceeds threshold 200.0 pps
... [INFO] ddos_detector.cli: Done. Total alerts raised: 2
```

### 2. Capture live

À lancer **en administrateur** (Npcap a besoin des privilèges de capture) :

```powershell
python main.py live                                   # interface + filtre IP par défaut
python main.py live --interface "Wi-Fi" --filter "tcp or udp"
python main.py live --log-file logs\monitor.log --log-level DEBUG
```

`Ctrl+C` arrête proprement la capture (la dernière fenêtre partielle est
évaluée au lieu d'être perdue).

### 3. Activer réellement le blocage (mitigation)

Par défaut `dry_run: true` : tout est journalisé mais rien n'est bloqué.
Pour créer de vraies règles de pare-feu Windows (`netsh advfirewall`), éditez
`config.yaml` :

```yaml
mitigator:
  dry_run: false            # ⚠️ crée de vraies règles de blocage
  block_duration_seconds: 300
```

Puis lancez le CLI **en administrateur**. Les IP bloquées sont automatiquement
débloquées à l'expiration de `block_duration_seconds`.

## Détection : comment ça marche

1. `capture.py` convertit chaque paquet scapy en `PacketEvent` normalisé
   (timestamp, IP source/destination, protocole, taille, flags TCP).
2. `DetectionEngine` agrège les événements dans des fenêtres glissantes de
   `window_duration_seconds` (1 s par défaut) → `TrafficWindow`.
3. `AnomalyDetector` évalue chaque fenêtre fermée contre 7 règles :

| Règle | Seuil configurable | Signification |
|---|---|---|
| `VOLUMETRIC_FLOOD` | `max_total_pps` | débit global anormal |
| `SYN_FLOOD` | `syn_ratio_threshold`, `min_syn_count` | ratio de SYNs nus élevé |
| `UDP_FLOOD` | `udp_pps_threshold` | débit UDP anormal |
| `ICMP_FLOOD` | `icmp_pps_threshold` | débit ICMP anormal |
| `SOURCE_FLOOD` | `max_per_src_pps` | une IP domine le trafic |
| `DISTRIBUTED_FLOOD` | `unique_ip_threshold` | trop de sources distinctes + volume élevé |
| `ANOMALY_SPIKE` | `adaptive_k` | `pps > moyenne + k × écart-type` des fenêtres passées |

4. Une alerte qui porte une IP source (règle `SOURCE_FLOOD`, ou `SYN_FLOOD`
   quand une source dépasse `dominant_source_ratio` du trafic) déclenche un
   blocage ; les alertes purement volumétriques/distribuées sont journalisées
   (il faut alors du *rate-limiting* ou du *scrubbing* en amont).

## Tests

```powershell
python -m pytest -q          # suite complète : ~3 s
```

Couverture : agrégation et baseline (`test_stats.py`), les 7 règles de
détection (`test_detector.py`), atténuation et expiration des blocages
(`test_mitigator.py`), câblage de bout en bout + lecture de `config.yaml`
(`test_engine.py`), conversion scapy → `PacketEvent` + test de régression
exécuté dans un interpréteur neuf (`test_capture.py`), parsing CLI et replay
complet (`test_cli.py`).

## Limitations connues

- Détection **heuristique** par fenêtres d'une seconde : ce n'est pas un
  système de mitigation d'opérateur (pas d'analyse par flux, pas de
  scrubbing en amont, pas de défense contre l'épuisement du lien).
- Le blocage local ne protège pas contre une saturation de la bande passante :
  il faut dans ce cas une action chez le fournisseur d'accès.
- Les adresses IP peuvent être usurpées (**spoofing**) : bloquer une IP source
  est alors inutile, seules les règles distribuées/adaptatives aident.
- Windows uniquement pour l'atténuation réelle (implémentée via
  `netsh advfirewall`) ; la détection et le replay sont multiplateformes.

## Licence

MIT — voir le fichier `LICENSE`.