# Évaluation des modèles

Mesures faites avec la graine 0 et les fonctions de `exfildns.dataset`, `exfildns.model` et
`exfildns.evaluation`. Le tableau de résultats est reproductible avec `exfildns train` / `evaluate` ;
les expériences complémentaires (type de fichier mis de côté, feature unique) ont été lancées avec
de petits scripts ponctuels qui enchaînent ces mêmes fonctions.

## Protocole

- **Données** : 290 196 requêtes DNS extraites des PCAP heavy, une étiquette par requête
  (`docs/donnees.md`).
- **Découpage par capture** : le test est fait de captures entières jamais vues à l'entraînement,
  `heavy_video` et `benign_heavy_3`, soit 70 159 requêtes (44 780 exfiltrations, 25 379 bénignes).
  Un tirage aléatoire mettrait des quasi-doublons des deux côtés et gonflerait les scores.
- **Validation** : 20 % du jeu d'entraînement, pour l'arrêt anticipé du réseau.
- **Modèles** : régression logistique de référence et réseau de neurones Keras
  (`docs/decisions.md`).

## Choix de la métrique

Classe positive : l'exfiltration. La matrice de confusion donne VP (exfiltrations détectées),
FN (exfiltrations manquées), FP (fausses alertes) et VN.

| Métrique | Formule | Question à laquelle elle répond |
|---|---|---|
| **Rappel** (métrique principale) | VP / (VP + FN) | Quelle part des exfiltrations détecte-t-on ? |
| **Taux de faux positifs** | FP / (FP + VN) | Quelle part du trafic normal déclenche une alerte ? |
| Précision | VP / (VP + FP) | Quelle part des alertes est justifiée ? |
| PR-AUC | aire sous la courbe précision-rappel | Qualité du classement, quel que soit le seuil |

Pourquoi ce choix :

- **Rater une exfiltration** (faux négatif) est le pire cas : les données sortent sans alerte.
  Le **rappel** est donc la métrique principale.
- Mais un détecteur qui alerte sur tout a un rappel de 100 % et ne sert à rien : le trafic DNS
  bénin est massif en conditions réelles, chaque point de **taux de faux positifs** se traduit
  par des milliers d'alertes inutiles. On le suit en second.
- L'**accuracy** est écartée : elle dépend de la proportion des classes, ici inversée par rapport
  à la réalité (3,3 exfiltrations pour 1 requête bénigne dans le dataset).

> Attention : la diapo 9 du cours inverse les formules de précision et de rappel. Les définitions
> ci-dessus sont les définitions standard (celles de scikit-learn).

**Seuil de décision : 0,5**, le seuil par défaut d'une sortie sigmoïde. Sur le test, un seuil
entre 0,66 (probabilité bénigne la plus haute) et 0,98 (probabilité d'exfiltration la plus basse)
supprimerait la seule fausse alerte du réseau, mais **choisir le seuil en regardant le jeu de test
serait une fuite** : le score ne mesurerait plus la généralisation. Il faudrait le régler sur la
validation, ce qui n'apporte rien ici. Le seuil est un paramètre (`seuil`) de `evaluer`.

## Résultats sur le jeu de test

| | Régression logistique | Réseau de neurones |
|---|---|---|
| Rappel | 1,0000 | 1,0000 |
| Taux de faux positifs | 0,0000 | 0,0000 (1 sur 25 379) |
| Précision | 1,0000 | 1,0000 (0,99998) |
| F1 | 1,0000 | 1,0000 (0,99999) |
| PR-AUC | 1,0000 | 1,0000 |
| Exfiltrations manquées | 0 | 0 |
| Fausses alertes | 0 | 1 |

Réseau : 13 époques (arrêt anticipé), environ 6 secondes d'entraînement sur CPU.

### Robustesse : chaque type de fichier mis de côté à tour de rôle

Réseau entraîné sans le type de fichier testé (et sans `benign_heavy_3`), puis testé dessus :

| Type de fichier exfiltré | Rappel | Exfiltrations manquées | Fausses alertes |
|---|---|---|---|
| audio | 1,0000 | 0 | 0 |
| compressed | 1,0000 | 0 | 0 |
| exe | 1,0000 | 0 | 0 |
| image | 0,99998 | 1 | 0 |
| text | 1,0000 | 0 | 1 |
| video | 1,0000 | 0 | 1 |

Le modèle généralise d'un type de fichier à l'autre : DNSExfiltrator encode tout en base64,
quel que soit le contenu.

## Explication du modèle : quelles features comptent ?

**Importance par permutation** (`importance_permutation`, sur le jeu de test) : on mélange les
valeurs d'une feature entre les requêtes, ce qui casse son lien avec l'étiquette, puis on mesure
de combien la perte (entropie croisée binaire) augmente. Une forte hausse signifie que le modèle
s'appuie sur cette feature. La méthode marche pour n'importe quel modèle, réseau compris.

| Feature | Hausse de la perte, réseau | Hausse de la perte, référence | Coefficient de la référence (features standardisées) |
|---|---|---|---|
| `entropy` | 0,117 | 0,114 | +3,77 |
| `upper` | 0,113 | 0,040 | +4,08 |
| `FQDN_count` | 0,071 | 0,037 | +3,05 |
| `labels_max` | 0,020 | 0,012 | +2,51 |
| `numeric` | 0,002 | 0,001 | +1,65 |
| `labels` | 0,000 | 0,000 | +0,42 |
| `labels_average` | 0,000 | 0,000 | −0,73 |
| `special` | 0,000 | 0,000 | +0,11 |
| `lower` | 0,000 | 0,000 | −0,35 |

Lecture :

- Les deux modèles s'appuient sur **les mêmes quatre signaux** : l'**entropie** (caractères
  aléatoires), les **majuscules** (absentes des domaines classiques, très présentes en base64),
  la **longueur** du nom et la **longueur du plus long label**. C'est exactement la signature
  d'un encodage base64 dans un sous-domaine.
- Signe des coefficients de la référence : positif = pousse vers « exfiltration », **les autres
  features restant fixes**. Comme `entropy`, `FQDN_count`, `upper` et `labels_max` augmentent
  ensemble, un coefficient isolé se lit mal : `labels_average` est négatif alors que sa valeur est
  bien plus haute pour l'exfiltration (médianes 19,5 contre 5,5), car son effet est déjà porté par
  `labels_max`. Leur **taille** n'a pas de sens absolu non plus : les classes étant parfaitement
  séparables, c'est la régularisation de la régression logistique qui fixe leur ordre de grandeur.
- Les hausses restent modestes alors que les modèles sont parfaits : les features sont
  **redondantes** (une seule suffit presque, voir plus haut). Quand on en brouille une, les autres
  compensent.
- `lower`, `special`, `labels` ne servent à rien : les domaines bénins et l'exfiltration en ont
  des quantités comparables. `labels_average`, lui, est **redondant** plutôt qu'inutile
  (`labels_max` porte la même information).

Phrase à retenir pour l'oral : *le réseau signale une requête quand son nom est long, aléatoire
(entropie élevée), contient des majuscules et un label très long, c'est-à-dire quand il ressemble
à des données encodées en base64 plutôt qu'à un nom de domaine choisi par un humain.*

## Validation en conditions réelles : mini-labo iodine

**Protocole** (25/11/2026) : `docker compose -f compose.labo.yaml up --build` (voir
[deploiement.md](deploiement.md#mini-labo--une-vraie-exfiltration-dns-sur-un-réseau-isolé)).
Le client iodine 0.7.0 envoie des blocs de 200 Ko aléatoires vers son serveur sur un réseau
Docker isolé ; `exfildns sniff` (modèle MLP du dépôt, seuil 0,5) enregistre chaque requête reçue
par le serveur. Comptage dans la base après ~2 minutes :

| Requêtes vers `tunnel.labo` | Nombre | Détectées (score ≥ 0,5) | Manquées |
|---|---|---|---|
| Données (nom > 40 caractères, ~238 en moyenne) | 1 862 | **1 833 (98,4 %)** | 29 |
| Contrôle (ouverture du tunnel, attente : `pabyaoly.tunnel.labo`…) | 21 | 0 | 21 |

Le domaine `tunnel.labo` dépasse largement les 5 requêtes suspectes : l'alerte apparaît dans le
dashboard. Les requêtes de contrôle, courtes, ne transportent presque rien et ressemblent à des
noms ordinaires : les manquer est attendu.

**Limite importante** : sans résolveur entre le client et le serveur, iodine choisit l'encodage
le plus dense (*Base128*, octets non ASCII), très différent d'un nom légitime. À travers un vrai
résolveur récursif, il peut se replier, selon ce que le résolveur laisse passer, sur du base64 ou du **base32 en minuscules** ; ce dernier, le modèle ne le
détecte pas (0 % lors d’un essai sur noms générés). iodine 0.7.0 ne permet pas d'imposer
l'encodage montant : ce cas reste à valider (généralisation du modèle, #62).

## Interprétation honnête : le dataset est trop facile

- **Une seule feature suffit presque** : la régression logistique sur une feature unique atteint
  99,99 % d'accuracy avec `entropy` ou `upper`, 99,97 % avec `FQDN_count`.
  Le base64 de DNSExfiltrator (long, majuscules, chiffres, entropie élevée) n'a rien à voir avec
  des domaines populaires (courts, en minuscules).
- La régression logistique fait donc aussi bien que le réseau. **Le réseau n'apporte rien sur ce
  dataset** ; il est gardé parce qu'il est demandé, et parce qu'il pourrait capter des
  combinaisons non linéaires sur des données plus difficiles.

Limites à garder en tête :

1. **Trafic bénin peu réaliste** : uniquement des domaines du top Alexa. Un vrai réseau contient des
   noms longs et aléatoires légitimes (CDN, cloud, antivirus, services Google `*.1e100.net`…),
   qui provoqueraient des faux positifs.
2. **Un seul outil d'attaque**, avec ses réglages par défaut. Un attaquant qui encode en
   minuscules (base32), raccourcit ses labels ou ralentit le débit réduirait fortement les écarts
   sur `upper`, `entropy` et `FQDN_count`.
3. **Analyse requête par requête** : le modèle ne voit ni le volume de requêtes vers un même
   domaine ni leur rythme, qui sont des signaux forts d'exfiltration (features *stateful* de
   l'article, écartées par simplicité).
