"""exfildns : détection d'exfiltration de données par DNS."""

import os

# Masque les messages internes de TensorFlow (avant tout import de tensorflow).
os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "2")

__version__ = "0.1.0"
