import tempfile
from osigdetector.ingestion.build_ucg import build_ucg
from osigdetector.mining.miner import StaticMiner

def test_static_miner_runs(tmp_path):
    # create tiny repo
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    f = repo_dir / "app.py"
    f.write_text("import requests\nrequests.get('http://example.com')\n")

    db_path = tmp_path / "ucg.sqlite"
    build_ucg(str(repo_dir), languages=["python"], db_path=str(db_path))

    miner = StaticMiner(str(db_path))
    miner.run()

    # verify anchors table not empty
    from sqlite3 import connect
    con = connect(db_path)
    cur = con.cursor()
    rows = cur.execute("SELECT kind, raw_fields FROM anchors").fetchall()
    assert rows, "anchors table should not be empty"
