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
