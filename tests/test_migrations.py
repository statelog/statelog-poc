import importlib.util
from pathlib import Path
from app.config import settings

MIGRATION_DIR = Path("alembic/versions")

BASELINE = MIGRATION_DIR / "0001_v8_baseline.py"
V81 = MIGRATION_DIR / "0002_v81_security_hardening.py"
V82 = MIGRATION_DIR / "0003_v82_key_rotation_and_webhooks.py"
V83 = MIGRATION_DIR / "0004_v83_replay_explainability.py"


def load_migration(path: Path):
    spec = importlib.util.spec_from_file_location(
        f"test_migration_{path.stem}",
        path,
    )
    assert spec is not None
    assert spec.loader is not None

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def migration_source(path: Path) -> str:
    return path.read_text(encoding="utf-8")


# #785
def test_migration_files_are_present_in_expected_order():
    names = sorted(
        path.name
        for path in MIGRATION_DIR.glob("*.py")
        if not path.name.startswith("__")
    )

    assert names == [
        "0001_v8_baseline.py",
        "0002_v81_security_hardening.py",
        "0003_v82_key_rotation_and_webhooks.py",
        "0004_v83_replay_explainability.py",
        "0005_request_log_policy_fields.py",
        "0006_policy_and_workflow_tables.py",
        "0007_outbox_claim_lease.py",
    ]


# #786
def test_baseline_revision_identity():
    migration = load_migration(BASELINE)

    assert migration.revision == "0001_v8_baseline"
    assert migration.down_revision is None


# #787
def test_v81_revision_follows_baseline():
    migration = load_migration(V81)

    assert migration.revision == "0002_v81_security_hardening"
    assert migration.down_revision == "0001_v8_baseline"


# #788
def test_v82_revision_follows_v81():
    migration = load_migration(V82)

    assert migration.revision == "0003_v82"
    assert migration.down_revision == "0002_v81_security_hardening"


# #789
def test_v83_revision_follows_v82():
    migration = load_migration(V83)

    assert migration.revision == "0004_v83"
    assert migration.down_revision == "0003_v82"


# #790
def test_all_migrations_define_upgrade_and_downgrade():
    for path in (BASELINE, V81, V82, V83):
        migration = load_migration(path)

        assert callable(migration.upgrade)
        assert callable(migration.downgrade)


# #791
def test_baseline_creates_all_core_tables():
    source = migration_source(BASELINE)

    for table in (
        "tenants",
        "client_credentials",
        "devices",
        "access_rights",
        "request_logs",
        "webhook_subscriptions",
        "outbox_events",
    ):
        assert f'"{table}"' in source


# #792
def test_baseline_tenant_name_is_unique():
    source = migration_source(BASELINE)

    assert 'sa.UniqueConstraint("name")' in source


# #793
def test_baseline_client_identity_is_unique_per_tenant():
    source = migration_source(BASELINE)

    assert (
        'sa.UniqueConstraint("tenant_id", "client_id", '
        'name="uq_client_per_tenant")'
        in source
    )


# #794
def test_baseline_device_identity_is_unique_per_tenant():
    source = migration_source(BASELINE)

    assert (
        'sa.UniqueConstraint("tenant_id", "device_id", '
        'name="uq_device_per_tenant")'
        in source
    )


# #795
def test_baseline_right_identity_is_unique_per_tenant():
    source = migration_source(BASELINE)

    assert (
        'sa.UniqueConstraint("tenant_id", "right_id", '
        'name="uq_right_per_tenant")'
        in source
    )


# #796
def test_baseline_request_idempotency_is_unique_per_tenant():
    source = migration_source(BASELINE)

    assert (
        'sa.UniqueConstraint("tenant_id", "idempotency_key", '
        'name="uq_request_idempotency_per_tenant")'
        in source
    )


# #797
def test_baseline_request_logs_have_required_lookup_indexes():
    source = migration_source(BASELINE)

    for index in (
        "tenant_id",
        "right_id",
        "client_id",
        "source_client",
        "device_id",
        "ip_hash",
        "trace_id",
        "idempotency_key",
        "token_jti",
        "request_fingerprint",
        "created_at",
    ):
        assert index in source

    assert "ix_request_logs_" in source
    assert "op.create_index" in source
    assert "request_logs" in source

# #798
def test_baseline_outbox_has_delivery_indexes():
    source = migration_source(BASELINE)

    assert "ix_outbox_events_event_type" in source
    assert "ix_outbox_events_next_attempt_at" in source
    assert "ix_outbox_events_tenant_id" in source


# #799
def test_v81_upgrade_is_intentionally_noop():
    source = migration_source(V81)

    upgrade_section = source.split(
        "def upgrade() -> None:",
        1,
    )[1].split(
        "def downgrade() -> None:",
        1,
    )[0]

    assert "pass" in upgrade_section

# #800
def test_v81_downgrade_restores_legacy_ip_address():
    source = migration_source(V81)

    assert "add_column" in source
    assert "request_logs" in source
    assert "ip_address" in source
    assert "UPDATE request_logs SET ip_address = ip_hash" in source
    assert "drop_index" in source
    assert "ix_request_logs_ip_hash" in source
    assert "drop_column" in source
    assert "ip_hash" in source


# #801
def test_v82_adds_encrypted_webhook_secret():
    source = migration_source(V82)

    assert "op.add_column" in source
    assert "webhook_subscriptions" in source
    assert "signing_secret_encrypted" in source
    assert "sa.Text()" in source


# #802
def test_v82_adds_key_version_and_dead_letter_state():
    source = migration_source(V82)

    assert "signing_secret_key_version" in source
    assert "dead_lettered" in source
    assert "server_default='v1'" in source
    assert "server_default=sa.false()" in source


# #803
def test_v82_creates_webhook_delivery_attempt_history():
    source = migration_source(V82)

    assert "webhook_delivery_attempts" in source
    assert "event_id" in source
    assert "subscription_id" in source
    assert "attempt_number" in source
    assert "successful" in source
    assert "response_status_code" in source
    assert "error_message" in source
    assert "signature_version" in source
    assert "outbox_events.id" in source
    assert "webhook_subscriptions.id" in source
    assert "ForeignKeyConstraint" in source


# #804
def test_v83_adds_and_removes_replay_explainability_columns():
    source = migration_source(V83)

    assert '"decision_source"' in source
    assert '"decision_path"' in source

    assert (
        'op.drop_column("request_logs", "decision_path")'
        in source
    )
    assert (
        'op.drop_column("request_logs", "decision_source")'
        in source
    )

# #835
def test_alembic_upgrade_head_creates_expected_tables(tmp_path, monkeypatch):
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import create_engine, inspect

    database_path = tmp_path / "statelog-migration.db"
    database_url = f"sqlite:///{database_path.as_posix()}"

    monkeypatch.setattr(
        settings,
        "database_url",
        database_url,
    )

    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", database_url)

    command.upgrade(config, "head")

    engine = create_engine(database_url)
    inspector = inspect(engine)

    expected_tables = {
        "tenants",
        "client_credentials",
        "devices",
        "access_rights",
        "request_logs",
        "webhook_subscriptions",
        "outbox_events",
        "webhook_delivery_attempts",
    }

    assert expected_tables.issubset(set(inspector.get_table_names()))


# #836
def test_alembic_upgrade_head_request_logs_has_replay_columns(tmp_path, monkeypatch):
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import create_engine, inspect

    database_path = tmp_path / "statelog-migration.db"
    database_url = f"sqlite:///{database_path.as_posix()}"

    monkeypatch.setattr(
        settings,
        "database_url",
        database_url,
    )

    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", database_url)

    command.upgrade(config, "head")

    engine = create_engine(database_url)
    columns = {
        column["name"]
        for column in inspect(engine).get_columns("request_logs")
    }

    assert "decision_source" in columns
    assert "decision_path" in columns


# #837
def test_alembic_upgrade_head_webhook_subscription_has_encrypted_secret(tmp_path, monkeypatch):
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import create_engine, inspect

    database_path = tmp_path / "statelog-migration.db"
    database_url = f"sqlite:///{database_path.as_posix()}"

    monkeypatch.setattr(
        settings,
        "database_url",
        database_url,
    )

    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", database_url)

    command.upgrade(config, "head")

    engine = create_engine(database_url)
    columns = {
        column["name"]
        for column in inspect(engine).get_columns(
            "webhook_subscriptions"
        )
    }

    assert "signing_secret_encrypted" in columns
    assert "signing_secret_key_version" in columns


# #838
def test_alembic_upgrade_head_creates_delivery_attempt_table(tmp_path, monkeypatch):
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import create_engine, inspect

    database_path = tmp_path / "statelog-migration.db"
    database_url = f"sqlite:///{database_path.as_posix()}"

    monkeypatch.setattr(
        settings,
        "database_url",
        database_url,
    )

    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", database_url)

    command.upgrade(config, "head")

    engine = create_engine(database_url)
    columns = {
        column["name"]
        for column in inspect(engine).get_columns(
            "webhook_delivery_attempts"
        )
    }

    assert {
        "id",
        "event_id",
        "subscription_id",
        "attempt_number",
        "successful",
        "response_status_code",
        "error_message",
        "signature_version",
        "created_at",
    }.issubset(columns)


# #839
def test_alembic_upgrade_head_request_log_columns_match_orm(tmp_path, monkeypatch):
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import create_engine, inspect

    from app.models import RequestLog

    database_path = tmp_path / "statelog-migration.db"
    database_url = f"sqlite:///{database_path.as_posix()}"

    monkeypatch.setattr(
        settings,
        "database_url",
        database_url,
    )

    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", database_url)

    command.upgrade(config, "head")

    engine = create_engine(database_url)
    migrated_columns = {
        column["name"]
        for column in inspect(engine).get_columns("request_logs")
    }

    orm_columns = {
        column.name
        for column in RequestLog.__table__.columns
    }

    assert migrated_columns == orm_columns

# #840
def test_v85_revision_follows_v83():
    migration = load_migration(
        MIGRATION_DIR / "0005_request_log_policy_fields.py"
    )

    assert migration.revision == "0005_request_log_policy_fields"
    assert migration.down_revision == "0004_v83"


# #841
def test_alembic_upgrade_head_contains_policy_tables(tmp_path, monkeypatch):
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import create_engine, inspect

    database_path = tmp_path / "statelog-migration.db"
    database_url = f"sqlite:///{database_path.as_posix()}"

    monkeypatch.setattr(
        settings,
        "database_url",
        database_url,
    )

    config = Config("alembic.ini")
    command.upgrade(config, "head")

    engine = create_engine(database_url)
    tables = set(inspect(engine).get_table_names())

    assert "policies" in tables
    assert "policy_history" in tables


# #842
def test_alembic_upgrade_head_contains_workflow_tables(tmp_path, monkeypatch):
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import create_engine, inspect

    database_path = tmp_path / "statelog-migration.db"
    database_url = f"sqlite:///{database_path.as_posix()}"

    monkeypatch.setattr(
        settings,
        "database_url",
        database_url,
    )

    config = Config("alembic.ini")
    command.upgrade(config, "head")

    engine = create_engine(database_url)
    tables = set(inspect(engine).get_table_names())

    assert "workflow_configs" in tables
    assert "workflow_config_history" in tables

# #843
def test_alembic_policy_columns_match_orm(tmp_path, monkeypatch):
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import create_engine, inspect

    from app.models import PolicyRecord

    database_path = tmp_path / "statelog-migration.db"
    database_url = f"sqlite:///{database_path.as_posix()}"

    monkeypatch.setattr(settings, "database_url", database_url)

    config = Config("alembic.ini")
    command.upgrade(config, "head")

    engine = create_engine(database_url)

    migrated_columns = {
        column["name"]
        for column in inspect(engine).get_columns("policies")
    }

    orm_columns = {
        column.name
        for column in PolicyRecord.__table__.columns
    }

    assert migrated_columns == orm_columns


# #844
def test_alembic_policy_history_columns_match_orm(tmp_path, monkeypatch):
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import create_engine, inspect

    from app.models import PolicyHistory

    database_path = tmp_path / "statelog-migration.db"
    database_url = f"sqlite:///{database_path.as_posix()}"

    monkeypatch.setattr(settings, "database_url", database_url)

    config = Config("alembic.ini")
    command.upgrade(config, "head")

    engine = create_engine(database_url)

    migrated_columns = {
        column["name"]
        for column in inspect(engine).get_columns("policy_history")
    }

    orm_columns = {
        column.name
        for column in PolicyHistory.__table__.columns
    }

    assert migrated_columns == orm_columns


# #845
def test_alembic_workflow_config_columns_match_orm(tmp_path, monkeypatch):
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import create_engine, inspect

    from app.models import WorkflowConfigRecord

    database_path = tmp_path / "statelog-migration.db"
    database_url = f"sqlite:///{database_path.as_posix()}"

    monkeypatch.setattr(settings, "database_url", database_url)

    config = Config("alembic.ini")
    command.upgrade(config, "head")

    engine = create_engine(database_url)

    migrated_columns = {
        column["name"]
        for column in inspect(engine).get_columns("workflow_configs")
    }

    orm_columns = {
        column.name
        for column in WorkflowConfigRecord.__table__.columns
    }

    assert migrated_columns == orm_columns


# #846
def test_alembic_workflow_history_columns_match_orm(tmp_path, monkeypatch):
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import create_engine, inspect

    from app.models import WorkflowConfigHistory

    database_path = tmp_path / "statelog-migration.db"
    database_url = f"sqlite:///{database_path.as_posix()}"

    monkeypatch.setattr(settings, "database_url", database_url)

    config = Config("alembic.ini")
    command.upgrade(config, "head")

    engine = create_engine(database_url)

    migrated_columns = {
        column["name"]
        for column in inspect(engine).get_columns(
            "workflow_config_history"
        )
    }

    orm_columns = {
        column.name
        for column in WorkflowConfigHistory.__table__.columns
    }

    assert migrated_columns == orm_columns

# #847
def test_alembic_policy_unique_constraint_matches_orm(tmp_path, monkeypatch):
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import create_engine, inspect

    database_path = tmp_path / "statelog-migration.db"
    database_url = f"sqlite:///{database_path.as_posix()}"

    monkeypatch.setattr(settings, "database_url", database_url)

    config = Config("alembic.ini")
    command.upgrade(config, "head")

    engine = create_engine(database_url)
    constraints = inspect(engine).get_unique_constraints("policies")

    assert any(
        constraint["name"] == "uq_policy_name_per_tenant"
        and set(constraint["column_names"]) == {"tenant_id", "name"}
        for constraint in constraints
    )


# #848
def test_alembic_policy_indexes_exist(tmp_path, monkeypatch):
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import create_engine, inspect

    database_path = tmp_path / "statelog-migration.db"
    database_url = f"sqlite:///{database_path.as_posix()}"

    monkeypatch.setattr(settings, "database_url", database_url)

    config = Config("alembic.ini")
    command.upgrade(config, "head")

    engine = create_engine(database_url)
    indexes = inspect(engine).get_indexes("policies")

    indexed_columns = {
        tuple(index["column_names"])
        for index in indexes
    }

    assert ("tenant_id",) in indexed_columns
    assert ("name",) in indexed_columns


# #849
def test_alembic_policy_history_indexes_exist(tmp_path, monkeypatch):
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import create_engine, inspect

    database_path = tmp_path / "statelog-migration.db"
    database_url = f"sqlite:///{database_path.as_posix()}"

    monkeypatch.setattr(settings, "database_url", database_url)

    config = Config("alembic.ini")
    command.upgrade(config, "head")

    engine = create_engine(database_url)
    indexes = inspect(engine).get_indexes("policy_history")

    indexed_columns = {
        tuple(index["column_names"])
        for index in indexes
    }

    assert ("policy_id",) in indexed_columns
    assert ("tenant_id",) in indexed_columns


# #850
def test_alembic_workflow_history_tenant_index_exists(tmp_path, monkeypatch):
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import create_engine, inspect

    database_path = tmp_path / "statelog-migration.db"
    database_url = f"sqlite:///{database_path.as_posix()}"

    monkeypatch.setattr(settings, "database_url", database_url)

    config = Config("alembic.ini")
    command.upgrade(config, "head")

    engine = create_engine(database_url)
    indexes = inspect(engine).get_indexes("workflow_config_history")

    indexed_columns = {
        tuple(index["column_names"])
        for index in indexes
    }

    assert ("tenant_id",) in indexed_columns


# #851
def test_alembic_new_tables_have_tenant_foreign_keys(tmp_path, monkeypatch):
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import create_engine, inspect

    database_path = tmp_path / "statelog-migration.db"
    database_url = f"sqlite:///{database_path.as_posix()}"

    monkeypatch.setattr(settings, "database_url", database_url)

    config = Config("alembic.ini")
    command.upgrade(config, "head")

    engine = create_engine(database_url)
    inspector = inspect(engine)

    for table_name in (
        "policies",
        "policy_history",
        "workflow_configs",
        "workflow_config_history",
    ):
        foreign_keys = inspector.get_foreign_keys(table_name)

        assert any(
            fk["referred_table"] == "tenants"
            and fk["constrained_columns"] == ["tenant_id"]
            and fk["referred_columns"] == ["id"]
            for fk in foreign_keys
        )

# #852
def test_alembic_new_tables_nullable_matches_orm(tmp_path, monkeypatch):
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import create_engine, inspect

    from app.models import (
        PolicyHistory,
        PolicyRecord,
        WorkflowConfigHistory,
        WorkflowConfigRecord,
    )

    database_path = tmp_path / "statelog-migration.db"
    database_url = f"sqlite:///{database_path.as_posix()}"

    monkeypatch.setattr(settings, "database_url", database_url)

    config = Config("alembic.ini")
    command.upgrade(config, "head")

    engine = create_engine(database_url)
    inspector = inspect(engine)

    tables = {
        "policies": PolicyRecord,
        "policy_history": PolicyHistory,
        "workflow_configs": WorkflowConfigRecord,
        "workflow_config_history": WorkflowConfigHistory,
    }

    for table_name, model in tables.items():
        migrated_nullable = {
            column["name"]: column["nullable"]
            for column in inspector.get_columns(table_name)
        }

        orm_nullable = {
            column.name: column.nullable
            for column in model.__table__.columns
        }

        assert migrated_nullable == orm_nullable

# #853
def test_alembic_new_tables_column_types_match_orm(tmp_path, monkeypatch):
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import create_engine, inspect

    from app.models import (
        PolicyHistory,
        PolicyRecord,
        WorkflowConfigHistory,
        WorkflowConfigRecord,
    )

    database_path = tmp_path / "statelog-migration.db"
    database_url = f"sqlite:///{database_path.as_posix()}"

    monkeypatch.setattr(settings, "database_url", database_url)

    config = Config("alembic.ini")
    command.upgrade(config, "head")

    engine = create_engine(database_url)
    inspector = inspect(engine)

    tables = {
        "policies": PolicyRecord,
        "policy_history": PolicyHistory,
        "workflow_configs": WorkflowConfigRecord,
        "workflow_config_history": WorkflowConfigHistory,
    }

    for table_name, model in tables.items():
        migrated_columns = {
            column["name"]: column["type"]
            for column in inspector.get_columns(table_name)
        }

        orm_columns = {
            column.name: column.type
            for column in model.__table__.columns
        }

        assert migrated_columns.keys() == orm_columns.keys()

        for column_name in migrated_columns:
            migrated_type = migrated_columns[column_name]
            orm_type = orm_columns[column_name]

            assert migrated_type._type_affinity is orm_type._type_affinity

# #854
def test_alembic_new_tables_primary_keys_match_orm(tmp_path, monkeypatch):
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import create_engine, inspect

    from app.models import (
        PolicyHistory,
        PolicyRecord,
        WorkflowConfigHistory,
        WorkflowConfigRecord,
    )

    database_path = tmp_path / "statelog-migration.db"
    database_url = f"sqlite:///{database_path.as_posix()}"
    monkeypatch.setattr(settings, "database_url", database_url)

    config = Config("alembic.ini")
    command.upgrade(config, "head")

    inspector = inspect(create_engine(database_url))
    tables = {
        "policies": PolicyRecord,
        "policy_history": PolicyHistory,
        "workflow_configs": WorkflowConfigRecord,
        "workflow_config_history": WorkflowConfigHistory,
    }

    for table_name, model in tables.items():
        migrated_pk = set(
            inspector.get_pk_constraint(table_name)["constrained_columns"]
        )
        orm_pk = {column.name for column in model.__table__.primary_key.columns}
        assert migrated_pk == orm_pk


# #855
def test_alembic_new_tables_string_lengths_match_orm(tmp_path, monkeypatch):
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import String, create_engine, inspect

    from app.models import (
        PolicyHistory,
        PolicyRecord,
        WorkflowConfigHistory,
        WorkflowConfigRecord,
    )

    database_path = tmp_path / "statelog-migration.db"
    database_url = f"sqlite:///{database_path.as_posix()}"
    monkeypatch.setattr(settings, "database_url", database_url)

    config = Config("alembic.ini")
    command.upgrade(config, "head")

    inspector = inspect(create_engine(database_url))
    tables = {
        "policies": PolicyRecord,
        "policy_history": PolicyHistory,
        "workflow_configs": WorkflowConfigRecord,
        "workflow_config_history": WorkflowConfigHistory,
    }

    for table_name, model in tables.items():
        migrated = {
            column["name"]: column["type"].length
            for column in inspector.get_columns(table_name)
            if isinstance(column["type"], String)
        }
        orm = {
            column.name: column.type.length
            for column in model.__table__.columns
            if isinstance(column.type, String)
        }
        assert migrated == orm


# #856
def test_alembic_policy_history_policy_id_index_is_single_column(tmp_path, monkeypatch):
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import create_engine, inspect

    database_path = tmp_path / "statelog-migration.db"
    database_url = f"sqlite:///{database_path.as_posix()}"
    monkeypatch.setattr(settings, "database_url", database_url)

    config = Config("alembic.ini")
    command.upgrade(config, "head")

    indexes = inspect(create_engine(database_url)).get_indexes("policy_history")

    assert any(
        index["column_names"] == ["policy_id"] and not index["unique"]
        for index in indexes
    )


# #857
def test_alembic_policy_history_tenant_index_is_single_column(tmp_path, monkeypatch):
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import create_engine, inspect

    database_path = tmp_path / "statelog-migration.db"
    database_url = f"sqlite:///{database_path.as_posix()}"
    monkeypatch.setattr(settings, "database_url", database_url)

    config = Config("alembic.ini")
    command.upgrade(config, "head")

    indexes = inspect(create_engine(database_url)).get_indexes("policy_history")

    assert any(
        index["column_names"] == ["tenant_id"] and not index["unique"]
        for index in indexes
    )


# #858
def test_alembic_workflow_history_tenant_index_is_single_column(tmp_path, monkeypatch):
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import create_engine, inspect

    database_path = tmp_path / "statelog-migration.db"
    database_url = f"sqlite:///{database_path.as_posix()}"
    monkeypatch.setattr(settings, "database_url", database_url)

    config = Config("alembic.ini")
    command.upgrade(config, "head")

    indexes = inspect(create_engine(database_url)).get_indexes(
        "workflow_config_history"
    )

    assert any(
        index["column_names"] == ["tenant_id"] and not index["unique"]
        for index in indexes
    )


# #859
def test_alembic_policies_tenant_index_is_non_unique(tmp_path, monkeypatch):
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import create_engine, inspect

    database_path = tmp_path / "statelog-migration.db"
    database_url = f"sqlite:///{database_path.as_posix()}"
    monkeypatch.setattr(settings, "database_url", database_url)

    config = Config("alembic.ini")
    command.upgrade(config, "head")

    indexes = inspect(create_engine(database_url)).get_indexes("policies")

    assert any(
        index["column_names"] == ["tenant_id"] and not index["unique"]
        for index in indexes
    )


# #860
def test_alembic_policies_name_index_is_non_unique(tmp_path, monkeypatch):
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import create_engine, inspect

    database_path = tmp_path / "statelog-migration.db"
    database_url = f"sqlite:///{database_path.as_posix()}"
    monkeypatch.setattr(settings, "database_url", database_url)

    config = Config("alembic.ini")
    command.upgrade(config, "head")

    indexes = inspect(create_engine(database_url)).get_indexes("policies")

    assert any(
        index["column_names"] == ["name"] and not index["unique"]
        for index in indexes
    )


# #861
def test_alembic_policy_unique_constraint_is_exactly_tenant_name(tmp_path, monkeypatch):
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import create_engine, inspect

    database_path = tmp_path / "statelog-migration.db"
    database_url = f"sqlite:///{database_path.as_posix()}"
    monkeypatch.setattr(settings, "database_url", database_url)

    config = Config("alembic.ini")
    command.upgrade(config, "head")

    constraints = inspect(create_engine(database_url)).get_unique_constraints(
        "policies"
    )

    matching = [
        constraint
        for constraint in constraints
        if constraint["name"] == "uq_policy_name_per_tenant"
    ]

    assert len(matching) == 1
    assert matching[0]["column_names"] == ["tenant_id", "name"]


# #862
def test_alembic_new_table_tenant_foreign_keys_are_not_duplicated(tmp_path, monkeypatch):
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import create_engine, inspect

    database_path = tmp_path / "statelog-migration.db"
    database_url = f"sqlite:///{database_path.as_posix()}"
    monkeypatch.setattr(settings, "database_url", database_url)

    config = Config("alembic.ini")
    command.upgrade(config, "head")

    inspector = inspect(create_engine(database_url))

    for table_name in (
        "policies",
        "policy_history",
        "workflow_configs",
        "workflow_config_history",
    ):
        tenant_fks = [
            fk
            for fk in inspector.get_foreign_keys(table_name)
            if fk["constrained_columns"] == ["tenant_id"]
            and fk["referred_table"] == "tenants"
            and fk["referred_columns"] == ["id"]
        ]

        assert len(tenant_fks) == 1


# #863
def test_alembic_new_tables_have_no_unexpected_unique_constraints(tmp_path, monkeypatch):
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import create_engine, inspect

    database_path = tmp_path / "statelog-migration.db"
    database_url = f"sqlite:///{database_path.as_posix()}"
    monkeypatch.setattr(settings, "database_url", database_url)

    config = Config("alembic.ini")
    command.upgrade(config, "head")

    inspector = inspect(create_engine(database_url))

    expected = {
        "policies": {("tenant_id", "name")},
        "policy_history": set(),
        "workflow_configs": set(),
        "workflow_config_history": set(),
    }

    for table_name, expected_constraints in expected.items():
        actual = {
            tuple(constraint["column_names"])
            for constraint in inspector.get_unique_constraints(table_name)
        }

        assert actual == expected_constraints

# #864
def test_alembic_downgrade_from_head_to_0005_removes_new_tables(tmp_path, monkeypatch):
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import create_engine, inspect

    database_path = tmp_path / "statelog-migration.db"
    database_url = f"sqlite:///{database_path.as_posix()}"
    monkeypatch.setattr(settings, "database_url", database_url)

    config = Config("alembic.ini")
    command.upgrade(config, "head")
    command.downgrade(config, "0005_request_log_policy_fields")

    tables = set(inspect(create_engine(database_url)).get_table_names())

    assert "policies" not in tables
    assert "policy_history" not in tables
    assert "workflow_configs" not in tables
    assert "workflow_config_history" not in tables


# #865
def test_alembic_downgrade_to_0005_preserves_request_log_policy_fields(tmp_path, monkeypatch):
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import create_engine, inspect

    database_path = tmp_path / "statelog-migration.db"
    database_url = f"sqlite:///{database_path.as_posix()}"
    monkeypatch.setattr(settings, "database_url", database_url)

    config = Config("alembic.ini")
    command.upgrade(config, "head")
    command.downgrade(config, "0005_request_log_policy_fields")

    columns = {
        column["name"]
        for column in inspect(create_engine(database_url)).get_columns("request_logs")
    }

    assert {
        "transaction_amount",
        "new_owner_id",
        "risk_signals",
        "policy_matched",
        "policy_name",
        "policy_id",
        "policy_version",
        "workflow_version",
    } <= columns


# #866
def test_alembic_downgrade_from_0005_to_0004_removes_request_log_policy_fields(
    tmp_path, monkeypatch
):
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import create_engine, inspect

    database_path = tmp_path / "statelog-migration.db"
    database_url = f"sqlite:///{database_path.as_posix()}"
    monkeypatch.setattr(settings, "database_url", database_url)

    config = Config("alembic.ini")
    command.upgrade(config, "0005_request_log_policy_fields")
    command.downgrade(config, "0004_v83")

    columns = {
        column["name"]
        for column in inspect(create_engine(database_url)).get_columns("request_logs")
    }

    removed = {
        "transaction_amount",
        "new_owner_id",
        "risk_signals",
        "policy_matched",
        "policy_name",
        "policy_id",
        "policy_version",
        "workflow_version",
    }

    assert columns.isdisjoint(removed)


# #867
def test_alembic_downgrade_to_0004_preserves_replay_columns(tmp_path, monkeypatch):
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import create_engine, inspect

    database_path = tmp_path / "statelog-migration.db"
    database_url = f"sqlite:///{database_path.as_posix()}"
    monkeypatch.setattr(settings, "database_url", database_url)

    config = Config("alembic.ini")
    command.upgrade(config, "head")
    command.downgrade(config, "0004_v83")

    columns = {
        column["name"]
        for column in inspect(create_engine(database_url)).get_columns("request_logs")
    }

    assert "decision_source" in columns
    assert "decision_path" in columns


# #868
def test_alembic_round_trip_0005_to_head_restores_new_tables(tmp_path, monkeypatch):
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import create_engine, inspect

    database_path = tmp_path / "statelog-migration.db"
    database_url = f"sqlite:///{database_path.as_posix()}"
    monkeypatch.setattr(settings, "database_url", database_url)

    config = Config("alembic.ini")
    command.upgrade(config, "head")
    command.downgrade(config, "0005_request_log_policy_fields")
    command.upgrade(config, "head")

    tables = set(inspect(create_engine(database_url)).get_table_names())

    assert {
        "policies",
        "policy_history",
        "workflow_configs",
        "workflow_config_history",
    } <= tables


# #869
def test_alembic_round_trip_0004_to_head_restores_request_log_fields(
    tmp_path, monkeypatch
):
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import create_engine, inspect

    database_path = tmp_path / "statelog-migration.db"
    database_url = f"sqlite:///{database_path.as_posix()}"
    monkeypatch.setattr(settings, "database_url", database_url)

    config = Config("alembic.ini")
    command.upgrade(config, "head")
    command.downgrade(config, "0004_v83")
    command.upgrade(config, "head")

    columns = {
        column["name"]
        for column in inspect(create_engine(database_url)).get_columns("request_logs")
    }

    assert {
        "transaction_amount",
        "new_owner_id",
        "risk_signals",
        "policy_matched",
        "policy_name",
        "policy_id",
        "policy_version",
        "workflow_version",
    } <= columns


# #870
def test_alembic_round_trip_restores_policy_indexes(tmp_path, monkeypatch):
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import create_engine, inspect

    database_path = tmp_path / "statelog-migration.db"
    database_url = f"sqlite:///{database_path.as_posix()}"
    monkeypatch.setattr(settings, "database_url", database_url)

    config = Config("alembic.ini")
    command.upgrade(config, "head")
    command.downgrade(config, "0005_request_log_policy_fields")
    command.upgrade(config, "head")

    indexes = inspect(create_engine(database_url)).get_indexes("policies")
    indexed_columns = {tuple(index["column_names"]) for index in indexes}

    assert ("tenant_id",) in indexed_columns
    assert ("name",) in indexed_columns


# #871
def test_alembic_round_trip_restores_policy_unique_constraint(tmp_path, monkeypatch):
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import create_engine, inspect

    database_path = tmp_path / "statelog-migration.db"
    database_url = f"sqlite:///{database_path.as_posix()}"
    monkeypatch.setattr(settings, "database_url", database_url)

    config = Config("alembic.ini")
    command.upgrade(config, "head")
    command.downgrade(config, "0005_request_log_policy_fields")
    command.upgrade(config, "head")

    constraints = inspect(create_engine(database_url)).get_unique_constraints("policies")

    assert any(
        constraint["name"] == "uq_policy_name_per_tenant"
        and constraint["column_names"] == ["tenant_id", "name"]
        for constraint in constraints
    )


# #872
def test_alembic_round_trip_restores_request_log_policy_index(tmp_path, monkeypatch):
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import create_engine, inspect

    database_path = tmp_path / "statelog-migration.db"
    database_url = f"sqlite:///{database_path.as_posix()}"
    monkeypatch.setattr(settings, "database_url", database_url)

    config = Config("alembic.ini")
    command.upgrade(config, "head")
    command.downgrade(config, "0004_v83")
    command.upgrade(config, "head")

    indexes = inspect(create_engine(database_url)).get_indexes("request_logs")

    assert any(
        index["column_names"] == ["policy_id"] and not index["unique"]
        for index in indexes
    )


# #873
def test_alembic_full_round_trip_returns_to_head_revision(tmp_path, monkeypatch):
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import create_engine, text

    database_path = tmp_path / "statelog-migration.db"
    database_url = f"sqlite:///{database_path.as_posix()}"
    monkeypatch.setattr(settings, "database_url", database_url)

    config = Config("alembic.ini")
    command.upgrade(config, "head")
    command.downgrade(config, "0004_v83")
    command.upgrade(config, "head")

    engine = create_engine(database_url)
    with engine.connect() as connection:
        revision = connection.execute(
            text("SELECT version_num FROM alembic_version")
        ).scalar_one()

    assert revision == "0007_outbox_claim_lease"

# #874
def test_alembic_head_adds_outbox_claim_columns(tmp_path, monkeypatch):
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import create_engine, inspect

    database_path = tmp_path / "statelog-migration.db"
    database_url = f"sqlite:///{database_path.as_posix()}"
    monkeypatch.setattr(settings, "database_url", database_url)

    config = Config("alembic.ini")
    command.upgrade(config, "head")

    columns = {
        column["name"]
        for column in inspect(create_engine(database_url)).get_columns(
            "outbox_events"
        )
    }

    assert "claimed_by" in columns
    assert "claim_expires_at" in columns


# #875
def test_alembic_head_adds_outbox_claim_expiry_index(tmp_path, monkeypatch):
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import create_engine, inspect

    database_path = tmp_path / "statelog-migration.db"
    database_url = f"sqlite:///{database_path.as_posix()}"
    monkeypatch.setattr(settings, "database_url", database_url)

    config = Config("alembic.ini")
    command.upgrade(config, "head")

    indexes = inspect(create_engine(database_url)).get_indexes(
        "outbox_events"
    )

    assert any(
        index["name"] == "ix_outbox_events_claim_expires_at"
        and index["column_names"] == ["claim_expires_at"]
        and not index["unique"]
        for index in indexes
    )


# #876
def test_alembic_downgrade_0007_removes_outbox_claim_fields(
    tmp_path,
    monkeypatch,
):
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import create_engine, inspect

    database_path = tmp_path / "statelog-migration.db"
    database_url = f"sqlite:///{database_path.as_posix()}"
    monkeypatch.setattr(settings, "database_url", database_url)

    config = Config("alembic.ini")
    command.upgrade(config, "head")
    command.downgrade(config, "0006_policy_and_workflow_tables")

    inspector = inspect(create_engine(database_url))
    columns = {
        column["name"]
        for column in inspector.get_columns("outbox_events")
    }
    indexes = inspector.get_indexes("outbox_events")

    assert "claimed_by" not in columns
    assert "claim_expires_at" not in columns
    assert not any(
        index["name"] == "ix_outbox_events_claim_expires_at"
        for index in indexes
    )


# #877
def test_alembic_0007_round_trip_restores_outbox_claim_fields(
    tmp_path,
    monkeypatch,
):
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import create_engine, inspect, text

    database_path = tmp_path / "statelog-migration.db"
    database_url = f"sqlite:///{database_path.as_posix()}"
    monkeypatch.setattr(settings, "database_url", database_url)

    config = Config("alembic.ini")

    command.upgrade(config, "head")
    command.downgrade(config, "0006_policy_and_workflow_tables")
    command.upgrade(config, "head")

    engine = create_engine(database_url)
    inspector = inspect(engine)

    columns = {
        column["name"]
        for column in inspector.get_columns("outbox_events")
    }
    indexes = inspector.get_indexes("outbox_events")

    with engine.connect() as connection:
        revision = connection.execute(
            text("SELECT version_num FROM alembic_version")
        ).scalar_one()

    assert "claimed_by" in columns
    assert "claim_expires_at" in columns
    assert any(
        index["name"] == "ix_outbox_events_claim_expires_at"
        for index in indexes
    )
    assert revision == "0007_outbox_claim_lease"