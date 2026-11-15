from pathlib import Path

from alembic import command
from alembic.config import Config
from digital_forensics.settings import get_settings


def test_initial_migration_matches_model_metadata(monkeypatch, tmp_path: Path) -> None:
    database_path = (tmp_path / "migration-test.db").as_posix()
    monkeypatch.setenv("DIGITAL_FORENSICS_DATABASE_URL", f"sqlite:///{database_path}")
    get_settings.cache_clear()
    alembic_config = Config(str(Path(__file__).parents[1] / "alembic.ini"))

    try:
        command.upgrade(alembic_config, "head")
        command.check(alembic_config)
    finally:
        get_settings.cache_clear()
