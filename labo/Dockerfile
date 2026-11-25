# Image du mini-labo (compose.labo.yaml) : l'outil de tunneling DNS iodine, client et serveur.
# Paquet Debian officiel, version épinglée (pas d'image tierce) ; netcat sert à envoyer
# puis recevoir le fichier exfiltré à travers le tunnel.
FROM debian:bookworm-slim@sha256:e67eeead736ff7bbe258ef088bff683635c561b1fcfefad0806c1df4ab49ce0e
RUN apt-get update \
    && apt-get install -y --no-install-recommends iodine=0.7.0-10+b1 netcat-openbsd=1.219-1 \
    && rm -rf /var/lib/apt/lists/*
