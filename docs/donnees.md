# Données : CIC-Bell-DNS-EXF-2021

Source : <https://www.unb.ca/cic/datasets/dns-exf-2021.html>. Citation obligatoire :
Mahdavifar, S., et al. *Lightweight Hybrid Detection of Data Exfiltration using DNS based on
Machine Learning*. ICCNS 2021.

## Contenu reçu (23/11/2026)

Seule la partie **« light »** est présente, **uniquement en CSV** (14 Mo) : ni PCAP, ni attaques
« heavy », ni bénin « heavy ».

```
data/
  Benign/   stateless_features-light_benign.pcap.csv      60 091 lignes
            stateful_features-_light_benign.pcap.csv      22 768 lignes
  Attacks/  stateless_features-light_<type>.pcap.csv      42 683 lignes au total
            stateful_features-light_<type>.pcap.csv       11 295 lignes au total
            <type> ∈ audio, compressed, exe, image, text, video
```

L'étiquette n'existe qu'au niveau du **fichier** (dossier `Attacks/` ou `Benign/`).
Les captures sont successives : bénin le 21/11/2020 de 14 h 18 à 18 h 09, puis un fichier
d'attaque après l'autre de 19 h 13 à 03 h 38.

### Fichiers stateless (une ligne = une requête DNS)

`timestamp, FQDN_count, subdomain_length, upper, lower, numeric, entropy, special, labels,
labels_max, labels_average, longest_word, sld, len, subdomain`

- **Le nom de domaine brut n'est pas fourni**, mais les features se recalculent à partir de lui.
  Exemple vérifié à la main sur `10.1.168.192.in-addr.arpa` (suffixe `in-addr.arpa`,
  sld `192`, sous-domaine `10.1.168`) :
  `FQDN_count`=25 (longueur totale), `subdomain_length`=8, `lower`=10, `numeric`=9,
  `special`=6 (points et tirets), `labels`=6, `labels_max`=7 (`in-addr`),
  `labels_average`=3,33, `len`=12 (sous-domaine + sld), `subdomain`=1 (présence d'un sous-domaine).
- `sld` et `longest_word` sont du **texte** (ex. `192`, `microsoft`, `DESKTOP-3JF04TC`),
  pas des nombres. `longest_word` a 4 valeurs manquantes.

### Fichiers stateful (une ligne = une fenêtre de requêtes)

Fréquences par type d'enregistrement (`A_frequency`, `PTR_frequency`, `TXT_frequency`…), TTL,
entropie et longueur des noms, et des colonnes sérialisées en texte Python (`{'PTR'}`, `set()`, `[1, 1]`).

## Constat bloquant : les attaques ne contiennent pas d'exfiltration visible

| Mesure | Stateless | Stateful |
|---|---|---|
| Lignes d'attaque **strictement identiques** à une ligne bénigne | **99,94 %** (24 lignes inédites sur 42 683) | **98,6 %** |
| Sous-domaine le plus long côté attaque | 19 caractères | — |
| Lignes avec un enregistrement TXT côté attaque | — | 1 sur 11 295 |

L'outil d'attaque du dataset, DNSExfiltrator, encode les données en base64 dans des
**sous-domaines longs** (jusqu'à 63 caractères par label) et utilise des réponses TXT.
**Aucune requête de ce type n'apparaît.** Les 24 lignes d'attaque inédites sont du trafic
ordinaire (`microsoft`, `msftncsi`, `googleapis`, `digicert`…). Les fichiers d'attaque
« light » ne contiennent donc que le **trafic de fond** du poste capturé pendant l'attaque.

Conséquence mesurée : une Random Forest sur les features stateless obtient une ROC-AUC de 0,80
(split stratifié 70/30), mais elle apprend un **artefact**. Le trafic de fond des captures
d'attaque est surtout fait de résolutions inverses (PTR) de `192.168.x.x`, celui de la capture
bénigne de requêtes A. Le modèle classerait toute résolution inverse du réseau local comme une
exfiltration. **Ce modèle ne détecte pas l'exfiltration.**

## Suite

Décision en attente (voir `docs/decisions.md`) : récupérer les **PCAP** et/ou la partie
**heavy** du dataset pour vérifier qu'ils contiennent bien les requêtes d'exfiltration.
