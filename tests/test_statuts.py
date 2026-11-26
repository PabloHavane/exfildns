import sqlite3

import pandas as pd
import pytest

from exfildns import liste_blanche
from exfildns.alertes import COLONNES_ALERTES
from exfildns.statuts import appliquer, enregistrer, lire, ouvertes


def resume(*alertes):
    """Sortie minimale de `alertes.alertes` : (domaine, fin) par alerte."""
    lignes = [
        {"domaine": d, "requetes_suspectes": 5, "score_moyen": 0.9, "score_max": 0.9,
         "sources": 1, "postes": "10.0.0.1", "debut": fin - 10, "fin": fin}
        for d, fin in alertes
    ]  # fmt: skip
    return pd.DataFrame(lignes, columns=COLONNES_ALERTES)


def test_lire_base_absente(tmp_path):
    statuts = lire(tmp_path / "statuts.db")

    assert statuts.empty
    assert not (tmp_path / "statuts.db").exists()  # la lecture ne crée pas la base


def test_enregistrer_puis_lire(tmp_path):
    base = tmp_path / "sous-dossier" / "statuts.db"

    enregistrer(base, "attaquant.example", "en_cours", "  poste isolé ", maintenant=100.0)

    ligne = lire(base).iloc[0]
    assert ligne.to_dict() == {
        "domaine": "attaquant.example",
        "statut": "en_cours",
        "commentaire": "poste isolé",
        "modifie_le": 100.0,
    }


def test_enregistrer_remplace_le_statut(tmp_path):
    base = tmp_path / "statuts.db"
    enregistrer(base, "attaquant.example", "en_cours", "à voir", maintenant=100.0)

    enregistrer(base, "attaquant.example", "close", maintenant=200.0)

    statuts = lire(base)
    assert len(statuts) == 1
    assert statuts.loc[0, "statut"] == "close"
    assert pd.isna(statuts.loc[0, "commentaire"])  # commentaire vide -> NULL
    assert statuts.loc[0, "modifie_le"] == 200.0


def test_enregistrer_statut_inconnu(tmp_path):
    with pytest.raises(ValueError, match="statut inconnu"):
        enregistrer(tmp_path / "statuts.db", "attaquant.example", "ignoree")
    assert not (tmp_path / "statuts.db").exists()


def test_schema_refuse_un_statut_inconnu(tmp_path):
    base = tmp_path / "statuts.db"
    enregistrer(base, "a.example", "close")

    with sqlite3.connect(base) as connexion, pytest.raises(sqlite3.IntegrityError):
        connexion.execute("INSERT INTO statuts_alertes VALUES ('b.example', 'x', NULL, 1)")


def test_appliquer_sans_statut_alerte_nouvelle(tmp_path):
    resultat = appliquer(resume(("a.example", 50.0)), lire(tmp_path / "statuts.db"))

    assert resultat["statut"].tolist() == ["nouvelle"]
    assert resultat["commentaire"].tolist() == [None]  # pas NaN (affiché « nan »)


def test_appliquer_statuts_enregistres(tmp_path):
    base = tmp_path / "statuts.db"
    enregistrer(base, "a.example", "en_cours", "en analyse", maintenant=100.0)
    enregistrer(base, "b.example", "faux_positif", maintenant=100.0)
    enregistrer(base, "c.example", "close", maintenant=100.0)
    enregistrer(base, "autre.example", "close", maintenant=100.0)  # sans alerte sur la période

    resultat = appliquer(
        resume(("a.example", 50.0), ("b.example", 50.0), ("c.example", 50.0)), lire(base)
    )

    assert resultat["statut"].tolist() == ["en_cours", "faux_positif", "close"]
    assert resultat["commentaire"].tolist()[0] == "en analyse"
    assert ouvertes(resultat)["domaine"].tolist() == ["a.example"]


def test_appliquer_alerte_close_rouverte_par_de_nouvelles_requetes(tmp_path):
    base = tmp_path / "statuts.db"
    enregistrer(base, "a.example", "close", maintenant=100.0)
    enregistrer(base, "b.example", "faux_positif", maintenant=100.0)

    resultat = appliquer(resume(("a.example", 150.0), ("b.example", 150.0)), lire(base))

    # seule une alerte close se rouvre ; un faux positif reste écarté
    assert resultat["statut"].tolist() == ["nouvelle", "faux_positif"]


def test_appliquer_sans_alerte(tmp_path):
    base = tmp_path / "statuts.db"
    enregistrer(base, "a.example", "close")

    resultat = appliquer(resume(), lire(base))

    assert resultat.empty
    assert {"statut", "commentaire"} <= set(resultat.columns)
    assert ouvertes(resultat).empty


def test_lire_base_creee_par_la_liste_blanche(tmp_path):
    base = tmp_path / "statuts.db"
    liste_blanche.ajouter(base, "exemple.com")  # la base existe, sans table des statuts

    assert lire(base).empty
