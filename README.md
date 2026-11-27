# exfildns

Application de machine learning qui détecte les requêtes DNS servant à **exfiltrer des données**
(DNS tunneling). Elle lit une capture réseau, attribue à chaque requête DNS une probabilité
d'exfiltration avec un réseau de neurones TensorFlow, et liste les requêtes suspectes.

Projet ENSIBS — module IA pour la cybersécurité. Entraîné sur le dataset CIC-Bell-DNS-EXF-2021.

## Démarrage rapide avec Docker (recommandé)

**Prérequis** : une machine **Linux** (la capture utilise le réseau de l'hôte), Docker Engine ≥ 24
avec le plugin Compose (`docker compose version` doit répondre), 3 à 4 Go d'espace disque.
Le modèle entraîné doit se trouver dans `models/exfildns.keras`.

> **S'il vous manque le modèle**, l'entraîner à partir du dataset : voir
> [Données](#données-seulement-pour-réentraîner-le-modèle) puis [Entraîner](#entraîner)
> (environ 2 minutes).


```bash
git clone https://github.com/PabloHavane/exfildns.git && cd exfildns
docker compose up -d --build      # premier lancement : quelques minutes (téléchargement de TensorFlow)
docker compose ps                 # deux services « Up », le dashboard « healthy » après ~30 s
```

Ouvrir **<http://localhost:8501>** : c'est le dashboard. Il affiche en direct chaque requête
DNS émise par la machine, notée par le modèle (bleu : bénigne, rouge : suspecte).

Arrêter : `docker compose down` (ajouter `-v` pour effacer les détections).

Rien n'apparaît ? `docker compose logs sniff` affiche l'interface surveillée et les erreurs ;
voir le [dépannage](docs/deploiement.md#6-dépannage).

## Tester une vraie exfiltration DNS : le labo

Le labo rejoue une attaque réelle avec l'outil de tunneling DNS **iodine**, sur un réseau
Docker isolé (aucun accès à Internet, domaine fictif `tunnel.labo`) :

- `victime` : poste compromis qui envoie 200 Ko de données par le tunnel DNS, toutes les 30 s ;
- `attaquant` : serveur iodine qui reçoit les données ;
- `sniff` : exfildns, qui écoute le trafic DNS de l'attaquant ;
- `dashboard` : le dashboard du labo, sur le port **8502**.

Il peut tourner en même temps que le déploiement ci-dessus (ports et volumes distincts).

```bash
docker compose -f compose.labo.yaml up -d --build
docker compose -f compose.labo.yaml logs -f victime   # attendre « Connection setup complete » (~15 s), puis Ctrl+C
```

Ouvrir **<http://localhost:8502>** et choisir la période « 5 dernières minutes » dans la
barre latérale. En moins de 30 secondes :

1. le graphique d'activité DNS se remplit de requêtes **rouges** (suspectes) ;
2. la **file d'alertes** affiche une alerte de sévérité haute vers `tunnel.labo`, depuis le
   poste `172.30.53.20` (la victime) ;
3. l'onglet **Requêtes** liste les requêtes ; un clic sur l'une d'elles montre le sous-domaine
   encodé, ses features comparées aux requêtes bénignes et un essai de décodage.

Dans le terminal : `docker compose -f compose.labo.yaml logs sniff | grep tunnel.labo` montre
les requêtes suspectes avec leur score (plusieurs centaines par envoi de 200 Ko).

Arrêter et effacer le labo : `docker compose -f compose.labo.yaml down -v` (à lancer aussi
avant de relancer le labo, pour repartir d'une base vide).

Le labo a besoin de `/dev/net/tun` sur l'hôte (présent sur toute distribution Linux courante).
Détails et résultats mesurés : [docs/deploiement.md](docs/deploiement.md#mini-labo--une-vraie-exfiltration-dns-sur-un-réseau-isolé).

**Sans réseau ni labo**, l'onglet **Analyser une capture** du dashboard accepte un fichier
`.pcap` et l'analyse de la même façon.

## Utilisation sans Docker

Prérequis : [uv](https://docs.astral.sh/uv/) (il installe lui-même Python 3.12) et, pour la
capture en direct, `libpcap` (`libpcap0.8` sous Debian/Ubuntu).

```bash
pip install uv          # si uv n'est pas installé
uv sync                 # crée l'environnement et installe les dépendances
uv run exfildns --help
```

### Données (seulement pour réentraîner le modèle)

1. Télécharger [CIC-Bell-DNS-EXF-2021](https://www.unb.ca/cic/datasets/dns-exf-2021.html)
   (formulaire du CIC), partie **PCAP heavy**.
2. Placer les captures ainsi (le dossier `data/` n'est pas versionné) :

```
data/
  Attacks/  heavy_audio.pcap  heavy_compressed.pcap  heavy_exe.pcap
            heavy_image.pcap  heavy_text.pcap        heavy_video.pcap
  Benign/   benign_heavy_1.pcap  benign_heavy_2.pcap  benign_heavy_3.pcap
```

> Mahdavifar, S., et al. *Lightweight Hybrid Detection of Data Exfiltration using DNS based on
> Machine Learning*. ICCNS 2021.

### Entraîner

```bash
uv run exfildns train          # data/ → models/exfildns.keras
```

```
Entraînement sur 220037 requêtes, test sur 70159.
Arrêt après 13 époques.
Modèle sauvegardé : models/exfildns.keras
Résultats sur le jeu de test :
  rappel (exfiltrations détectées) : 1.0000
  taux de faux positifs            : 0.000039
  ...
```

Le premier lancement lit les PCAP (~1 min 30) et garde les requêtes dans `data/requetes.csv` ;
les suivants prennent une dizaine de secondes. Supprimer ce fichier pour relire les PCAP.

Options : `-o` fichier du modèle, `--epochs` nombre maximal d'époques, `--captures-test`
captures mises de côté pour le test (par défaut `heavy_video benign_heavy_3`).

### Évaluer un modèle sauvegardé

```bash
uv run exfildns evaluate       # métriques de models/exfildns.keras sur le jeu de test
```

`train` et `evaluate` prennent en argument le dossier de données (`data` par défaut) ;
`evaluate` accepte `-m` pour choisir le modèle.

### Analyser une capture

```bash
uv run exfildns scan capture.pcap [--seuil 0.5] [--max 20] [-m models/exfildns.keras]
```

```
42081 requêtes DNS analysées, 41987 suspectes (seuil 0.5).

Serveurs DNS destinataires des requêtes suspectes :
  192.168.20.72                            41987

Alertes : domaines ayant reçu au moins 5 requêtes suspectes (1) :
  (nom incomplet dans la capture)          41987

Requêtes suspectes (3 plus probables) :
  1.000  192.168.20.38 -> 192.168.20.72  18038.E_yl9iUnLNtXYEU7YNi-AOL_Q_0gRze-oSx
  ...
```

Une **alerte** est levée quand un même domaine parent reçoit au moins `--min-requetes` (5)
requêtes suspectes : un tunnel en envoie des milliers, un faux positif isolé une seule. Les
domaines de la liste blanche (CDN et cloud connus, plus ceux d'un fichier `--liste-blanche`,
un par ligne) n'alertent jamais.

Code de sortie : **0** sans alerte, **1** si au moins une alerte est levée,
**2** si le modèle est introuvable (une autre erreur, comme une capture introuvable, renvoie
aussi 1 avec un message d'erreur). Dans un script :

```bash
uv run exfildns scan capture.pcap > rapport.txt
[ $? -eq 1 ] && grep -q suspectes rapport.txt && echo "Exfiltration suspectée"
```

### Détecter en direct sur le réseau

```bash
sudo .venv/bin/exfildns sniff -i wlan0 [--base detections.db] [--seuil 0.5] [-m models/exfildns.keras] [--retention 3]
```

`--retention 3` supprime les requêtes de plus de 3 jours, au démarrage puis toutes les heures
(par défaut tout est gardé ; 3 jours dans le déploiement Docker).

```
Capture DNS sur wlan0, requêtes enregistrées dans detections.db.
Requêtes suspectes (seuil 0.5) ; Ctrl+C pour arrêter.
1.000  192.168.1.20 -> 192.168.1.1  0.PbRnw5CzRaPatJvFwgVhKtw12qpxW7fhoFxsLeQY.attaquant.example
^C
Capture arrêtée : 214 requêtes analysées, 1 suspectes.
```

Chaque requête DNS vue sur l'interface est notée par le même modèle que `scan`, puis
enregistrée avec son score dans la base SQLite `--base` (lue par le dashboard). Les requêtes
suspectes s'affichent au fil de l'eau. La capture demande **root** ou la capacité
**`CAP_NET_RAW`** ; sans `-i` (ou avec `-i auto`), l'interface de la route par défaut est
choisie et son nom s'affiche au démarrage.
Ctrl+C ou SIGTERM (`docker stop`) arrêtent proprement la capture.

**Sans port miroir** : `exfildns sniff --journal /var/log/unbound/unbound.log` suit le journal
d'un résolveur **Unbound** au lieu du réseau, et voit ainsi les requêtes de tous les postes qui
l'utilisent (aucun privilège réseau, seulement le droit de lire le fichier). Mêmes features,
même base, même dashboard ; la configuration d'Unbound et les limites sont dans
[docs/deploiement.md](docs/deploiement.md).

### Superviser avec le dashboard

```bash
uv run exfildns dashboard [--base detections.db] [--statuts statuts.db] [-m models/exfildns.keras] [--port 8501] [--adresse localhost]
```

Ouvre <http://localhost:8501>, une vue pensée pour un analyste SOC :

- **bandeau d'état** : capteur actif / silencieux (plus d'1 min) / inactif (plus de 5 min)
  d'après l'âge de la dernière requête en base, ou « aucune requête » si la base est vide ; modèle chargé (nom, date, empreinte), seuil et période ;
- **Supervision en direct** : 8 chiffres clés avec leur variation par rapport à la période
  précédente, activité DNS (barres bénignes / suspectes à pas fixe, marqueurs d'alerte), file
  d'alertes triée par sévérité puis date, top domaines, top postes, types de requêtes,
  histogramme des scores avec le seuil, requêtes suspectes les plus récentes. Chaque alerte a
  un **statut** (nouvelle, en cours, faux positif, close) et un commentaire, modifiables depuis
  sa carte ; la file montre par défaut les alertes ouvertes (nouvelles et en cours), un filtre
  affiche les faux positifs, les closes ou toutes. Une alerte close qui reçoit de nouvelles
  requêtes suspectes redevient nouvelle ;
- **Requêtes** : tableau filtrable (poste, domaine, verdict, score, texte) ; un clic sur une
  ligne ouvre son détail : nom découpé (sous-domaine en évidence), features comparées à la
  moyenne des requêtes jugées bénignes par le modèle sur la période, séquence du même poste
  vers le même domaine, essais de décodage (base32, base64, hexadécimal) **affichés
  seulement** en hexadécimal ou ASCII échappé. Export CSV ou JSON de la vue filtrée (5 000
  requêtes les plus récentes au plus), de la requête seule (JSON) ou de sa séquence (CSV).

Seuil, nombre de requêtes pour une alerte et période se règlent dans la barre latérale ; la
supervision se rafraîchit toutes les 5 secondes (interrupteur), l'onglet Requêtes seulement
sur le bouton « Actualiser » ou un changement de période, pour ne pas perdre la ligne
sélectionnée. Chaque onglet se recalcule seul : un clic dans un tableau ne relance pas la
supervision. La sévérité d'une alerte
(haute, moyenne, basse) aide au tri sans changer quelles alertes sont levées.

L'onglet **Analyser une capture** accepte un fichier `.pcap` / `.pcapng` et l'analyse comme
`exfildns scan`, avec les vues de la supervision (sans variations ni statut d'alerte) suivies
du tableau de **toutes** ses requêtes, bénignes comprises, avec les mêmes filtres, détail et
exports que l'onglet Requêtes (identifiant d'une requête : sa position dans la capture). Utile
sans accès au réseau, ou pour rejouer une capture.
Le modèle est celui de `-m` (relancer le dashboard après un réentraînement : les analyses sont
mises en cache) ; les fichiers déposés sont limités à 100 Mo.

Le dashboard lit la base de `sniff` **en lecture seule** et sans privilège : il peut tourner
pendant la capture. Il n'écrit que dans sa propre base, celle des statuts d'alertes et de la
liste blanche (`--statuts`, par défaut `statuts.db` dans le dossier de `--base`). Le panneau
**Liste blanche** de la barre latérale ajoute ou retire un domaine (et ses sous-domaines) qui ne
doit plus alerter, en direct comme pour une capture importée ; la liste par défaut (CDN) reste
toujours appliquée. Il n'écoute que sur `localhost` par défaut, car il affiche les noms demandés
et les adresses des postes ; `--adresse 0.0.0.0` l'ouvre au réseau.

Avant de l'exposer, définir `EXFILDNS_MOT_DE_PASSE` (long : la pause après un échec ne freine
qu'une session) : le dashboard demande alors ce mot de passe
avant d'afficher quoi que ce soit (bouton « Se déconnecter » dans la barre latérale). Le
dashboard ne chiffre pas : hors de `localhost`, le placer derrière un proxy HTTPS pour que le
mot de passe ne circule pas en clair.

### Être notifié des alertes hautes

```bash
EXFILDNS_WEBHOOK=https://chat.exemple.fr/hooks/xxx uv run exfildns notifier [--base detections.db] [--statuts statuts.db]
```

Relit les bases toutes les 30 s (`--intervalle`) et envoie en POST JSON chaque alerte de
sévérité **haute** ouverte sur la dernière heure (`--fenetre 60`), une seule fois par alerte.
Mêmes alertes que le dashboard : liste blanche et statuts (faux positif, close) sont respectés.
Le champ `text` du message est affiché par Slack, Mattermost ou Rocket.Chat.

## Notebook de méthodologie

[notebooks/methodologie.ipynb](notebooks/methodologie.ipynb) déroule la démarche d'apprentissage
(données, features, découpage, modèles, métriques, explicabilité). Il est livré **exécuté** : il se
lit directement sur GitHub. Pour le relancer (dataset dans `data/`) :

```bash
uv sync --group notebook
uv run --group notebook jupyter lab notebooks/methodologie.ipynb   # puis « Run All »
```

Il réentraîne le réseau et réécrit `models/exfildns.keras`, le même modèle que `exfildns train`.

## Documentation

| Document | Contenu |
|---|---|
| [docs/deploiement.md](docs/deploiement.md) | Architecture, déploiement avec ou sans Docker, démo, mini-labo, dépannage, limites |
| [docs/algorithme.md](docs/algorithme.md) | Fonctionnement de bout en bout, à lire pour la soutenance |
| [docs/evaluation.md](docs/evaluation.md) | Protocole, métriques, résultats, importance des features, limites |
| [docs/donnees.md](docs/donnees.md) | Analyse du dataset et pièges rencontrés |
| [docs/decisions.md](docs/decisions.md) | Journal des décisions et de leurs justifications |

## Développement

```bash
uv run pytest                                      # ~40 s
uv run ruff check . && uv run ruff format --check .
```

Code dans `src/exfildns/` : `pcap.py` (lecture des captures), `features.py` (features d'un nom
de domaine), `dataset.py` (jeu étiqueté), `model.py` (modèles), `evaluation.py` (métriques et
explication), `cli.py` (commandes), `sniff.py` (capture en direct vers SQLite), `alertes.py`
(regroupement par domaine, liste blanche), `statuts.py` (statut des alertes), `liste_blanche.py` (domaines ajoutés depuis le dashboard), `notification.py` (webhook des alertes hautes), `journal.py` (journal du résolveur Unbound), `dashboard.py` (Streamlit), `synthese.py` (chiffres
clés, file d'alertes, panneaux) et `detail.py` (onglet Requêtes et capture importée : détail, décodage, export).
Conventions (GitLab Flow, commits, branches) : [CLAUDE.md](CLAUDE.md).

## Licence

Apache 2.0
