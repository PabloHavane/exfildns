import pytest

from exfildns import __version__
from exfildns.cli import main


def test_sans_commande_affiche_aide(capsys):
    assert main([]) == 0
    assert "exfildns" in capsys.readouterr().out


def test_version(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_train_puis_evaluate(dossier_donnees, tmp_path, capsys):
    modele = tmp_path / "modeles" / "exfildns.keras"

    assert main(["train", str(dossier_donnees), "-o", str(modele), "--epochs", "50"]) == 0
    sortie = capsys.readouterr().out
    assert modele.exists()
    assert "rappel" in sortie
    assert "Modèle sauvegardé" in sortie

    assert main(["evaluate", str(dossier_donnees), "-m", str(modele)]) == 0
    sortie = capsys.readouterr().out
    rappel = float(sortie.split("rappel (exfiltrations détectées) : ")[1].split()[0])
    assert rappel > 0.9


def test_captures_test_inconnues(dossier_donnees):
    with pytest.raises(ValueError):
        main(["evaluate", str(dossier_donnees), "--captures-test", "inexistante"])
