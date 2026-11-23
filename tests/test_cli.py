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
