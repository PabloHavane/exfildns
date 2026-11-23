import pytest
from conftest import NOM_EXFIL, ecrire_pcap, requete

from exfildns.dataset import COLONNES_REQUETES, IP_ATTAQUANT, NOM_CACHE, load_dataset
from exfildns.features import FEATURES


@pytest.fixture
def dossier(tmp_path):
    """Mini-dataset : une capture d'attaque (exfiltration + trafic de fond), une bénigne."""
    (tmp_path / "Attacks").mkdir()
    (tmp_path / "Benign").mkdir()
    ecrire_pcap(
        tmp_path / "Attacks" / "heavy_test.pcap",
        [
            requete(NOM_EXFIL, dst=IP_ATTAQUANT),
            requete("1." + NOM_EXFIL[2:], dst=IP_ATTAQUANT),
            requete("www.microsoft.com"),  # trafic de fond vers 8.8.8.8
        ],
        snaplen=96,
    )
    ecrire_pcap(
        tmp_path / "Benign" / "benign_test.pcap",
        [requete("example.com"), requete("www.wikipedia.org")],
    )
    (tmp_path / "Benign" / "ignore.pcap.csv").write_text("pas un pcap")
    return tmp_path


def test_etiquettes_par_requete(dossier):
    df = load_dataset(dossier, cache=False)

    assert list(df.columns) == COLONNES_REQUETES + FEATURES
    assert len(df) == 5
    attaque = df[df.capture == "heavy_test"]
    assert attaque.label.tolist() == [1, 1, 0]  # le trafic de fond reste bénin
    assert df[df.capture == "benign_test"].label.tolist() == [0, 0]
    assert not (dossier / NOM_CACHE).exists()


def test_features_calculees_sur_les_noms(dossier):
    df = load_dataset(dossier, cache=False)

    exfil = df[df.label == 1]
    assert (exfil.FQDN_count == 40).all()
    assert df.loc[df.qname == "example.com", "labels"].item() == 2


def test_cache_reutilise(dossier):
    premier = load_dataset(dossier)
    assert (dossier / NOM_CACHE).exists()

    for pcap in dossier.rglob("*.pcap"):
        pcap.unlink()  # le second chargement ne doit plus lire les PCAP
    second = load_dataset(dossier)

    assert second.equals(premier)


def test_dossier_sans_pcap(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_dataset(tmp_path, cache=False)
