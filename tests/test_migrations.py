import importlib.util
from pathlib import Path


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