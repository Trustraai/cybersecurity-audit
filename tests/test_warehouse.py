import pytest

from secaudit_workbench.warehouse import SnapshotIntegrityError, Warehouse


def test_loads_and_verifies_digest():
    wh = Warehouse()
    assert wh.version
    assert len(wh.controls()) > 0


def test_tampered_digest_refused(tmp_path):
    import json
    import shutil

    from secaudit_workbench import warehouse as wmod

    src_dir = wmod._DATA_DIR
    dst = tmp_path / "data"
    shutil.copytree(src_dir, dst)

    wh_path = dst / "warehouse.json"
    data = json.loads(wh_path.read_text())
    data["nodes"][0]["title"] = "tampered"
    wh_path.write_text(json.dumps(data))

    with pytest.raises(SnapshotIntegrityError):
        Warehouse(warehouse_path=str(wh_path), controls_path=str(dst / "controls.json"))


def test_by_dimension_and_node_lookup():
    wh = Warehouse()
    vulns = wh.by_dimension("vulnerability")
    assert len(vulns) == 1
    assert wh.node(vulns[0]["id"]) is not None
