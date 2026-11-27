"""exfildns : détection d'exfiltration de données par DNS."""

import os

# Masque les messages internes de TensorFlow (avant tout import de tensorflow).
os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "2")

__version__ = "2.2.1"

# Seuil de décision : une requête est signalée si sa probabilité d'exfiltration dépasse 0,5.
# Défini ici, sans dépendance, pour que le dashboard et les alertes ne chargent pas TensorFlow.
SEUIL = 0.5
