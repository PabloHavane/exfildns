# Comment fonctionne exfildns

Support pour la soutenance : le problème, la chaîne de traitement, le modèle, les résultats et
leurs limites. Les chiffres détaillés sont dans [evaluation.md](evaluation.md), les choix
justifiés dans [decisions.md](decisions.md).

## 1. Le problème : exfiltrer des données par le DNS

Le DNS traduit des noms (`www.exemple.com`) en adresses IP. Il est presque toujours autorisé à
sortir d'un réseau, même très filtré. Un attaquant qui contrôle un domaine (`attaquant.com`) et
son serveur DNS peut donc faire sortir des données **cachées dans les noms demandés** :

```
fichier secret → base64 → morceaux → 0.J4HgHlgzQH6j0WZF8m3DQx3j....attaquant.com
                                     1.4wB3-nhq9BXRXAXZX3ZQyduOz....attaquant.com
```

Chaque requête porte un morceau ; le serveur de l'attaquant les reçoit et reconstitue le fichier.
C'est ce que fait l'outil **DNSExfiltrator**, utilisé pour créer le dataset.

Ces noms ne ressemblent pas à des noms choisis par un humain : ils sont **longs**, **aléatoires**,
mélangent **majuscules, minuscules et chiffres**. C'est ce que le modèle apprend à reconnaître.

## 2. Les données

Dataset **CIC-Bell-DNS-EXF-2021** (Université du Nouveau-Brunswick), partie *heavy*, en PCAP :
6 captures pendant l'exfiltration de fichiers (audio, compressé, exécutable, image, texte, vidéo)
et 3 captures de navigation normale (domaines populaires du top Alexa).

Deux surprises, détaillées dans [donnees.md](donnees.md) :

- les **CSV fournis** par le dataset ne contiennent pas le trafic d'exfiltration (99,94 % des
  lignes « attaque » sont identiques à des lignes bénignes) : on ne s'en sert pas ;
- les **paquets sont coupés à 96 octets** : il ne reste qu'environ 40 caractères de chaque nom,
  et scapy ne sait pas décoder ces paquets tronqués.

**Étiquetage par requête** : dans une capture d'attaque, seules les requêtes envoyées au serveur
de l'attaquant (`192.168.20.72`) sont des exfiltrations ; le reste est du trafic normal du poste.
Résultat : **290 196 requêtes**, dont 222 849 exfiltrations et 67 347 bénignes.

## 3. La chaîne de traitement

```
capture .pcap ──► requêtes DNS ──► 9 features ──► réseau de neurones ──► probabilité ──► alerte
   pcap.py          (nom, IP)      features.py        model.py              ≥ 0,5        cli.py
```

**La même chaîne sert à l'entraînement et à l'analyse** : le modèle voit en production exactement
les mêmes features qu'à l'entraînement (même principe que `pretraiter()` dans le TP Spam).

### Lecture des captures (`pcap.py`)

scapy ouvre la capture ; pour chaque paquet UDP vers le port 53 qui est une requête, le nom est
lu **directement dans les octets** (longueur du label, puis le label, etc.), ce qui fonctionne
même si le paquet est coupé.

### Les 9 features (`features.py`)

Calculées sur les **40 premiers caractères** du nom, pour traiter de la même façon tous les noms
longs (ceux du dataset étant coupés). Noms repris de l'article de référence.

| Feature | Définition | Exfiltration (médiane) | Bénin (médiane) |
|---|---|---|---|
| `FQDN_count` | nombre de caractères | 40 | 14 |
| `upper` | majuscules | 14 | 0 |
| `lower` | minuscules | 14 | 13 |
| `numeric` | chiffres | 10 | 0 |
| `special` | autres caractères (points, tirets…) | 2 | 1 |
| `entropy` | entropie de Shannon, en bits par caractère | 4,78 | 3,28 |
| `labels` | nombre de parties séparées par des points | 2 | 2 |
| `labels_max` | longueur de la plus longue partie | 34 | 9 |
| `labels_average` | longueur moyenne des parties | 19,5 | 5,5 |

L'**entropie** mesure le désordre : `H = − Σ p(c) · log2 p(c)` sur la fréquence `p(c)` de chaque
caractère. `aaaa` vaut 0, un texte où 16 caractères apparaissent autant chacun vaut 4. Le base64
utilise 64 symboles de façon quasi uniforme, d'où une entropie élevée.

Les 5 autres features de l'article (`sld`, `subdomain`, `len`, `longest_word`…) sont écartées :
elles demandent de connaître le domaine de l'attaquant, jamais visible dans les noms coupés, ou un
dictionnaire.

### Le modèle (`model.py`)

Un réseau de neurones dense (perceptron multicouche), dans le style du TP Spam :

| Couche | Rôle | Paramètres |
|---|---|---|
| `Normalization` | met chaque feature à l'échelle (moyenne 0, écart-type 1) | 19 (non entraînables) |
| `Dense(32, relu)` | couche cachée | 9 × 32 + 32 = 320 |
| `Dense(16, relu)` | couche cachée | 32 × 16 + 16 = 528 |
| `Dense(1, sigmoid)` | probabilité d'exfiltration entre 0 et 1 | 16 + 1 = 17 |

- **Pas d'Embedding** (contrairement au TP Spam) : l'entrée est un vecteur de 9 nombres, pas du texte.
- **Normalization** : sans mise à l'échelle, `FQDN_count` (jusqu'à 40) écraserait `entropy`
  (autour de 4). La couche apprend moyenne et écart-type **sur le seul jeu d'entraînement** et est
  sauvegardée dans le fichier `.keras` : l'analyse d'une capture applique la même mise à l'échelle.
- **Entraînement** : optimiseur `adam`, perte `binary_crossentropy`, lots de 256 requêtes.
  `class_weight` compense le déséquilibre des classes (environ 4 exfiltrations pour
  1 requête bénigne dans le jeu d'entraînement).
- **Overfitting** : 20 % du jeu d'entraînement sert de validation ; l'arrêt anticipé
  (`EarlyStopping`, patience 3) stoppe quand la perte de validation ne baisse plus et **garde les
  poids de la meilleure époque**. C'est la règle du cours « prendre l'époque où `val_loss` est
  minimale », automatisée. En pratique : 13 époques, ~6 secondes.
- **Référence** : une régression logistique sert de point de comparaison simple.

## 4. Évaluation

- **Test sur des captures entières jamais vues** (`heavy_video` + `benign_heavy_3`, 70 159
  requêtes) : un tirage aléatoire mettrait des requêtes quasi identiques des deux côtés.
- **Métrique principale : le rappel** (part des exfiltrations détectées), car rater une
  exfiltration est le pire cas. **Second critère : le taux de faux positifs**, car un détecteur
  qui alerte sur tout est inutilisable. L'accuracy est écartée (proportion des classes inversée
  par rapport à la réalité).

| | Régression logistique | Réseau de neurones |
|---|---|---|
| Rappel | 1,0000 | 1,0000 |
| Fausses alertes | 0 sur 25 379 | 1 sur 25 379 |
| Exfiltrations manquées | 0 sur 44 780 | 0 sur 44 780 |

Le réseau garde ces résultats quand on met de côté n'importe quel type de fichier exfiltré
(au plus 1 erreur par type).

**Pourquoi le modèle décide** (importance par permutation) : il s'appuie sur l'**entropie**, les
**majuscules**, la **longueur** et le **plus long label**. Autrement dit : *une requête est
suspecte quand son nom est long, aléatoire, contient des majuscules et un label très long — quand
il ressemble à des données encodées plutôt qu'à un nom choisi par un humain.*

## 5. Limites (à dire à l'oral)

1. **Le dataset est trop facile** : une seule feature (l'entropie ou les majuscules) suffit à
   99,99 %. Le réseau ne fait pas mieux que la régression logistique ; les scores parfaits
   reflètent la simplicité du dataset, pas une performance garantie en conditions réelles.
2. **Trafic bénin peu réaliste** : uniquement des domaines populaires. Un vrai réseau contient des
   noms longs et aléatoires légitimes (CDN, cloud, antivirus) qui déclencheraient des fausses alertes.
3. **Un seul outil d'attaque** : un attaquant qui encode en minuscules (base32), raccourcit ses
   labels ou espace ses requêtes réduirait fortement les écarts mesurés.
4. **Analyse requête par requête** : le volume et le rythme des requêtes vers un même domaine,
   signaux forts d'exfiltration (features *stateful* de l'article), ne sont pas exploités.

Pistes d'amélioration : ajouter des features de volume par domaine sur une fenêtre de temps,
entraîner avec du trafic bénin réel et d'autres outils (iodine, dnscat2).

## 6. Glossaire

| Terme | Définition |
|---|---|
| PCAP | fichier de capture réseau (Wireshark, tcpdump) |
| Label DNS | partie d'un nom entre deux points (`www`, `exemple`, `com`) |
| Base64 | encodage de données binaires avec 64 caractères (A–Z, a–z, 0–9, `-`, `_`) |
| Rappel | VP / (VP + FN) : part des exfiltrations détectées |
| Précision | VP / (VP + FP) : part des alertes justifiées (la diapo 9 du cours inverse les deux formules) |
| Taux de faux positifs | FP / (FP + VN) : part du trafic normal signalée à tort |
| PR-AUC | aire sous la courbe précision-rappel, qualité du classement indépendante du seuil |
| Époque | un passage complet sur les données d'entraînement |
| Overfitting | le modèle apprend par cœur et généralise mal ; détecté par la remontée de `val_loss` |
