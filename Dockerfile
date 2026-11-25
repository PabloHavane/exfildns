# Image unique d'exfildns, utilisée par les deux services de compose.yaml :
#   sniff      capture DNS en direct (seul à avoir la capacité NET_RAW)
#   dashboard  supervision Streamlit, sans aucun privilège
# Le modèle (.keras) et les données ne sont jamais dans l'image : ils sont montés.

# --- Étape 1 : environnement Python construit par uv, à partir de uv.lock ---
FROM python:3.12.16-slim-bookworm@sha256:82836454a795d9d75549a9e157fd08dbac6c383292cf89e99f4248a97ce6b2ff AS dependances
COPY --from=ghcr.io/astral-sh/uv:0.13.9@sha256:d3b601f0c7b118bc1753febf7c41cc80981df678445e0254284eecf84db79a7d /uv /usr/local/bin/uv
# Délai de téléchargement large : les roues de TensorFlow pèsent plus de 600 Mo
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_HTTP_TIMEOUT=300
WORKDIR /app
# Dépendances d'abord (couche en cache tant que uv.lock ne change pas), puis le code
COPY pyproject.toml uv.lock ./
# Cache uv partagé entre les builds (hors image) : pas de nouveau téléchargement à chaque fois
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev --no-install-project

# --- Étape 2 : le paquet exfildns seul, mis à part pour sa propre couche (quelques centaines de Ko) ---
FROM dependances AS construction
COPY README.md ./
COPY src ./src
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev --no-editable \
    && mkdir /projet \
    && cp -a --parents .venv/bin/exfildns .venv/lib/python3.12/site-packages/exfildns \
       .venv/lib/python3.12/site-packages/exfildns-*.dist-info /projet/

# --- Étape 3 : image d'exécution, sans uv ni outils de construction ---
FROM python:3.12.16-slim-bookworm@sha256:82836454a795d9d75549a9e157fd08dbac6c383292cf89e99f4248a97ce6b2ff
# libpcap : compilation du filtre BPF par scapy ; libcap2-bin (setcap) : retiré après usage
# hadolint ignore=DL3008
RUN apt-get update \
    && apt-get install -y --no-install-recommends libpcap0.8 libcap2-bin \
    && rm -rf /var/lib/apt/lists/*
# Dépendances (~1,9 Go) : couche inchangée tant que uv.lock ne change pas. Copier le venv complet
# de l'étape construction la referait à chaque modification du code, et l'export d'une couche
# de près de 2 Go (compression) prend plus d'une minute.
COPY --from=dependances /app/.venv /app/.venv
# Copie dédiée de l'interpréteur, seule à pouvoir capturer (capacité de fichier NET_RAW) :
# placée dans le venv, elle en utilise les paquets. Le Python commun reste sans capacité,
# ce qui permet au dashboard de tourner avec cap_drop: ALL.
RUN cp "$(readlink -f /usr/local/bin/python3.12)" /app/.venv/bin/python-capture \
    && setcap cap_net_raw+ep /app/.venv/bin/python-capture \
    && apt-get purge -y libcap2-bin \
    && useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin exfildns \
    && mkdir /data /etat \
    && chown exfildns /data /etat
# Le code d'exfildns en dernier : seule couche refaite quand src/ change
COPY --from=construction /projet/.venv/ /app/.venv/
ENV PATH="/app/.venv/bin:$PATH" \
    HOME=/tmp \
    PYTHONUNBUFFERED=1
USER exfildns
WORKDIR /data
ENTRYPOINT ["exfildns"]
CMD ["--help"]
