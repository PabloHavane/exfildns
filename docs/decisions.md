# Journal des décisions

Format : `AAAA-MM-JJ — décision` puis 2-3 lignes de justification.

## 2026-11-23 — Stack Python 3.12 + uv, TensorFlow/Keras, CLI argparse
TensorFlow/Keras pour le modèle (MLP), car l'équipe l'a déjà pratiqué en TP. scikit-learn reste
utilisé comme outil (split, métriques, régression logistique de référence). scapy lit les PCAP,
argparse (bibliothèque standard) suffit pour la CLI. Python 3.12 car supporté par TensorFlow.

## 2026-11-23 — GitLab Flow : `main` (intégration, protégée) → `production` (livraison)
Une branche par issue (supprimée après merge), petits commits sur la branche, PR mergée en squash
vers `main` avec CI verte. Promotion par PR `main` → `production` en merge (ou rebase), jamais en squash ;
`main` est la seule source autorisée vers `production`.

## 2026-11-23 — Entraînement sur les PCAP heavy, avec une étiquette par requête
Les CSV « light » ne contiennent pas de trafic d'exfiltration (99,94 % des lignes d'attaque sont
identiques à des lignes bénignes, voir `docs/donnees.md`). On entraîne donc sur les PCAP heavy
avec **notre propre calcul de features** (le même que l'application) :
- étiquette 1 : requête d'une capture d'attaque envoyée au serveur de l'attaquant `192.168.20.72` ;
- étiquette 0 : requête des captures bénignes, et trafic de fond des captures d'attaque (`8.8.8.8`).

## 2026-11-23 — Features calculées sur les 40 premiers caractères du nom de domaine
Les paquets sont tronqués à 96 octets : les noms d'exfiltration sont tous coupés vers 40 caractères.
Tronquer tous les noms de la même façon, à l'entraînement comme à l'inférence, empêche le modèle
d'apprendre la troncature au lieu de l'exfiltration.

## 2026-11-23 — Lecture du nom de domaine dans les octets bruts
scapy ne décode pas les requêtes DNS tronquées. scapy reste utilisé pour lire les fichiers
(pcap et pcapng), mais le nom de domaine est lu directement dans la charge UDP par une petite fonction.

## 2026-11-23 — 9 features stateless sur 14, calculées sur les seuls caractères du nom
Gardées : `FQDN_count`, `upper`, `lower`, `numeric`, `special`, `entropy`, `labels`, `labels_max`,
`labels_average` (noms de l'article). Écartées : `sld`, `subdomain`, `subdomain_length`, `len`,
qui supposent de connaître le suffixe public (`.com`, `.co.uk`…), jamais visible dans les noms
d'exfiltration tronqués ; `longest_word`, qui demande un dictionnaire. L'entropie est l'entropie
de Shannon du nom entier (tronqué) : elle diffère de celle des CSV du dataset (3,51 contre 2,56 sur
`10.1.168.192.in-addr.arpa`), ce qui est sans effet puisque ces CSV ne sont pas utilisés.
Limite : la longueur est très discriminante (100 % des noms d'exfiltration atteignent 40 caractères,
0,05 % des bénins) ; un vrai réseau a plus de noms bénins longs (CDN, cloud) que le top Alexa.

## 2026-11-23 — `load_dataset` renvoie un seul DataFrame, avec cache des requêtes brutes
Colonnes `capture, dst, qname, label` + features, au lieu d'un couple `(X, y)` : la colonne
`capture` est nécessaire pour découper train/test par capture (#5). Relire les PCAP prend ~1 min 30,
donc les requêtes brutes sont mises en cache dans `data/requetes.csv` (3 s ensuite). Les features
sont recalculées à chaque chargement ; supprimer le cache si les PCAP ou l'étiquetage changent.

## 2026-11-23 — Test sur des captures entières (`heavy_video` + `benign_heavy_3`)
Plutôt que le tirage aléatoire 70/30 de l'article : les requêtes d'une même capture se ressemblent
(docs/donnees.md, risque 3), un tirage aléatoire mettrait des quasi-doublons en train et en test.
Le test (~24 % des requêtes) ne couvre donc qu'un type de fichier exfiltré (vidéo) : les autres
types servent à l'entraînement. Modèle de référence : régression logistique standardisée,
`class_weight="balanced"` ; 0 erreur sur les 70 159 requêtes de test.

## 2026-11-23 — Réseau de neurones : Normalization → Dense 32 → Dense 16 → sortie sigmoïde
Style du TP Spam (Sequential, ReLU, adam, binary_crossentropy), sans Embedding puisque l'entrée
est un vecteur de 9 features numériques. La couche `Normalization` (adaptée sur le train) est
enregistrée dans le `.keras` : l'inférence applique la même mise à l'échelle. 20 % du train sert
de validation ; `EarlyStopping(patience=3, restore_best_weights=True)` automatise le choix
« époque de val_loss minimale » du cours. 865 paramètres entraînables, ~6 s d'entraînement,
1 erreur sur les 70 159 requêtes de test.

## 2026-11-23 — Métrique principale : rappel ; second critère : taux de faux positifs ; seuil 0,5
Rater une exfiltration est le pire cas, d'où le rappel. Le taux de faux positifs empêche le
détecteur « qui alerte sur tout ». L'accuracy est écartée car le dataset inverse la proportion
réelle des classes. Seuil 0,5 (défaut de la sigmoïde) : il n'est pas réglé sur le test pour éviter
une fuite. Détails et chiffres dans `docs/evaluation.md`.

## 2026-11-24 — Notebook Jupyter qui importe le paquet, livré exécuté, hors CI
Le notebook `notebooks/methodologie.ipynb` appelle les fonctions de `exfildns` au lieu de recopier
leur code : une seule implémentation des features et du modèle. Il est commité avec ses sorties
(lisible sans le relancer) et n'est pas exécuté en CI, qui n'a pas le dataset. Jupyter et
matplotlib sont dans un groupe de dépendances `notebook`, absent de l'application et de la CI.

## 2026-11-24 — Détection en direct : capture séparée, SQLite, Streamlit, Docker
La capture demande root ou `CAP_NET_RAW` : elle tourne dans un processus à part (`exfildns sniff`)
qui écrit dans une base SQLite ; le dashboard Streamlit la lit sans privilège. SQLite est dans la
bibliothèque standard et suffit pour un seul écrivain. Déploiement par Docker compose (deux
services), relu par l'agent `relecteur-docker`.

## 2026-11-24 — Alertes par domaine parent (≥ 5 requêtes suspectes) et liste blanche Le modèle
juge chaque requête seule ; un tunnel, lui, envoie beaucoup de requêtes vers un même domaine.
Une alerte n'est levée que si un domaine parent (deux derniers labels) reçoit au moins 5
requêtes suspectes : un faux positif isolé (nom long d'un CDN) n'alerte pas. Une liste blanche
(CDN et cloud connus, complétable par fichier) écarte les services légitimes. Le homelab prévu
pour ajuster ces seuils (#42) a été abandonné, remplacé par le mini-labo (#61). Limite : « deux
derniers labels » se trompe sur les suffixes comme `.co.uk`, sans gêner la détection d'un
tunnel. La fonction compte sur le tableau qu'on lui donne, sans fenêtre glissante : `scan` lui
passe la capture entière, le dashboard la période choisie (filtre SQL). Le code de sortie de
`scan` vaut 1 seulement s'il y a une **alerte** (et non plus dès une requête suspecte), pour
que les scripts ne subissent pas les faux positifs isolés.

## 2026-11-24 — Dashboard en lecture seule, sur localhost par défaut
Le dashboard ouvre la base SQLite en lecture seule (`mode=ro`) : il ne peut pas altérer les
détections et tourne sans privilège. Si la capture est arrêtée et que le fichier `-shm` ne peut pas être recréé
(capture lancée en root, ou volume Docker monté en `:ro`), il relit la base en `immutable` (plus
aucun écrivain). Il n'écoute que sur `localhost` par défaut : il affiche les
noms demandés et les adresses des postes, données sensibles à ne pas exposer sans le vouloir.

## 2026-11-24 — Docker : une image, deux services, privilèges minimaux
Image multi-étapes construite par uv depuis `uv.lock`, base épinglée par digest, sans données ni
modèle (montés). Les deux services tournent en utilisateur non root (uid 10001), `cap_drop: ALL`,
racine en lecture seule. La capture a besoin de `NET_RAW` : la capacité est posée par `setcap`
sur une **copie dédiée** de l'interpréteur (`python-capture`), utilisée par `sniff` seul ; sur le
Python commun, elle aurait empêché le dashboard (sans capacité) de démarrer. `no-new-privileges`
est activé pour le dashboard mais pas pour `sniff`, où il annulerait cette capacité. Le
dashboard n'est publié que sur `127.0.0.1`. Image lourde (~3,8 Go, dont 1,9 Go de TensorFlow) :
`tensorflow-cpu` (roue de 274 Mo contre 572 Mo) est possible sous Linux x86_64 avec des marqueurs
de plateforme, mais changerait la dépendance de l'environnement de développement à deux jours
de la soutenance : reporté à une issue dédiée, avec l'autre piste (prédire sans TensorFlow,
Keras 3 en backend NumPy). Les binaires setuid de l'image de base restent présents dans `sniff`
(sans no-new-privileges) : risque faible, seule NET_RAW est dans l'ensemble limitant et la racine
est en lecture seule.

## 2026-11-24 — Interface SOC (v2.1) : données affichées et limites

La table `requetes` gagne une colonne `taille` (octets du message DNS, lus dans l'en-tête UDP
pour rester justes sur un paquet tronqué), ajoutée par une migration additive dans `ouvrir_base` :
les anciennes lignes valent NULL. Elle sert à l'affichage seulement, pas au modèle. Les noms de
la base restent en français, comme l'existant. Le `rcode` n'est pas enregistré : la capture ne
voit que les requêtes, il faudrait capturer et apparier les réponses. Domaine parent = deux
derniers labels (pas de Public Suffix List). Pas de SHAP : le modèle est un réseau Keras, il
faudrait une dépendance lourde et charger TensorFlow dans le dashboard.

## 2026-11-24 — Sévérité des alertes et état du capteur (affichage seulement)

La file d'alertes trie par sévérité puis par dernière requête suspecte. Sévérité **haute** si
l'alerte est nette (score max ≥ 0,9) et fournie (au moins deux fois le minimum de requêtes
suspectes), **moyenne** si l'une des deux, **basse** sinon : une règle lisible à l'oral, qui ne
change pas quelles alertes sont levées. Le capteur est jugé actif si la dernière requête a moins
d'une minute, silencieux jusqu'à 5 minutes, inactif au-delà ; sans battement de cœur écrit par la
capture, un réseau très calme le fait paraître silencieux. Les variations des chiffres clés
comparent à la période précédente de même durée, et ne s'affichent pas si elle est vide.

## 2026-11-25 — Mini-labo Docker avec iodine à la place du homelab

**Décision** : valider en conditions réelles avec `compose.labo.yaml` (fichier séparé, pas un
profil : `compose.yaml` exige une interface hôte) : un serveur et un client **iodine** sur un
réseau Docker `internal`, le capteur partageant l'espace réseau du serveur. iodine vient du
paquet Debian officiel, version épinglée, sur une image Debian épinglée par empreinte.
**Justification** : le homelab (#42) n'est plus disponible ; iodine est un vrai outil, empaqueté
par Debian (pas d'image tierce), et le labo ne dépend d'aucune infrastructure externe. Prix :
`NET_ADMIN` et `/dev/net/tun` pour l'interface tunnel d'iodine, limités aux deux conteneurs iodine.

## 2026-11-25 — Statut des alertes dans une base séparée (#78)

Une alerte a un statut (nouvelle, en cours, faux positif, close), accroché au **domaine parent**
puisque les alertes sont recalculées à chaque affichage. Il vit dans `statuts.db`, écrite par le
dashboard seul (volume `statuts` sous Docker) : `detections.db` reste en lecture seule pour lui,
ce qui protège les détections et marche aussi quand `sniff` tourne en root hors Docker (fichier
de détections appartenant à root). « Faux positif » est un statut, réversible, et non un ajout à
la liste blanche ; pas d'auteur enregistré (aucune authentification). Une alerte close qui reçoit
de nouvelles requêtes suspectes redevient nouvelle ; « Alertes ouvertes » compte nouvelles et en
cours.

## 2026-11-26 — `tensorflow-cpu` sous Linux x86_64 (#58)

`pyproject.toml` installe `tensorflow-cpu` sous Linux x86_64 (marqueurs de plateforme) et
`tensorflow` ailleurs (macOS, ARM). **Justification** : aucun GPU n'est utilisé ; l'image passe
de 3,8 à 2,9 Go et les scores du modèle sont identiques (écart nul sur 2 000 requêtes). Prédire
sans TensorFlow (Keras 3, dont le backend NumPy demande jax ; ~1,5 Go de moins) a été mesuré viable mais écarté avant la
soutenance : plus de code et de dépendances à changer.

## 2026-11-26 — Livraison en v2.1.0, sans v2.0.0 (#45)

`production` passe directement de v1.0.0 à **v2.1.0**. Les milestones v2.0 (détection en direct :
capture, alertes, dashboard, Docker) et v2.1 (interface SOC) ont été développés à la suite sur
`main`, sans livraison intermédiaire : quand vient la livraison, `main` contient les deux. Taguer
`v2.0.0` annoncerait une version sans l'interface SOC alors qu'elle est livrée ; le numéro suit
donc le contenu réel. Une version **majeure** (2) car la v1 n'était qu'un modèle hors ligne
(`train`, `evaluate`, `scan`) : la v2 ajoute la capture en direct, le dashboard et le déploiement.

## 2026-11-26 — Liste blanche modifiable depuis le dashboard (#92)

Les domaines ajoutés par l'analyste vont dans `statuts.db`, table `liste_blanche` : c'est déjà la
seule base écrite par le dashboard, donc pas de nouveau volume ni de nouvelle option, et
`detections.db` reste en lecture seule. La liste par défaut (CDN) reste dans le code, toujours
appliquée et non modifiable depuis l'interface : un retrait par erreur ferait réapparaître des
faux positifs connus. Les saisies sont validées (forme d'un nom de domaine, au moins deux labels)
pour qu'un « com » ne blanchisse pas tout un TLD. `scan --liste-blanche` (fichier) est inchangé.

## 2026-11-26 — Notification des alertes hautes par webhook (#91)

**Webhook HTTP générique** (POST JSON, champ `text`) : accepté tel quel par Slack, Mattermost,
Rocket.Chat, ntfy…, sans dépendance (`urllib`). Un **service à part** (`exfildns notifier`), sans
privilège, relit `detections.db` et `statuts.db` en lecture seule : il voit exactement les
alertes du dashboard (liste blanche, statuts, sévérité) et la capture, qui a `NET_RAW`, reste
inchangée. **Anti-répétition** : une notification par alerte, mémorisée en mémoire ; l'alerte
est oubliée quand elle sort de la fenêtre d'une heure ou n'est plus ouverte, et un redémarrage
peut renvoyer les alertes en cours (assumé : rien de plus à stocker). Le domaine, venu du
réseau, est réduit à `[A-Za-z0-9._:-]` dans le message. Adresse passée par variable
d'environnement (elle contient souvent un jeton) et limitée à http/https.

## 2026-11-26 — Mot de passe vérifié par le dashboard (#93)

Le dashboard demande le mot de passe de `EXFILDNS_MOT_DE_PASSE` avant d'afficher quoi que ce soit
(comparaison en temps constant, pause d'1 s après un échec). Écarté : l'authentification native
de Streamlit, qui exige un fournisseur OIDC ; un reverse proxy dans compose, qui ajoute une image
tierce et ne protège pas le dashboard lancé hors Docker. Sans variable, l'accès reste libre (le
dashboard n'écoute que sur localhost). Limites assumées : un seul mot de passe partagé (à choisir long : la pause ne freine qu'une
session, pas des essais en parallèle), reconnexion à chaque rechargement de la page, pas
d'auteur des changements de statut, et pas de chiffrement : hors de localhost, un proxy HTTPS
devant le dashboard reste nécessaire.

## 2026-11-26 — Journal d'Unbound comme seconde source de `sniff` (#94)

**Unbound** (`log-queries`) plutôt que BIND ou Pi-hole : résolveur récursif répandu, une ligne
par requête et un **horodatage Unix**, alors que dnsmasq (Pi-hole) écrit une date syslog sans
année. Chaque ligne devient le même tuple qu'un paquet décodé (`pcap.requete_dns`) : notation,
base, alertes et dashboard sont inchangés (`noter` reçoit le décodeur). Option
`sniff --journal`, exclusive de `-i`, plutôt qu'une nouvelle commande. Pas de taille de message
dans le journal : la colonne reste vide, comme pour une base antérieure.

## 2026-11-27 — Rétention par défaut de 3 jours dans le déploiement Docker

`EXFILDNS_RETENTION` passe de 30 à 3 jours : le capteur enregistre chaque requête DNS et la
supervision relit toute la période affichée ; une base plus petite reste rapide sur une machine
de démonstration. Réglable dans `.env`.
