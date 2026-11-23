# Journal des décisions

Format : `AAAA-MM-JJ — décision` puis 2-3 lignes de justification.

## 2026-11-23 — Stack Python 3.12 + uv, TensorFlow/Keras, CLI argparse
TensorFlow/Keras pour le modèle (MLP), car l'équipe l'a déjà pratiqué en TP. scikit-learn reste
utilisé comme outil (split, métriques, régression logistique de référence). scapy lit les PCAP,
argparse (bibliothèque standard) suffit pour la CLI. Python 3.12 car supporté par TensorFlow.

## 2026-11-23 — GitLab Flow : `main` (intégration, protégée) → `production` (livraison)
Une branche par issue, petits commits, PR mergée en rebase vers `main` avec CI verte, promotion par PR `main` → `production`.
