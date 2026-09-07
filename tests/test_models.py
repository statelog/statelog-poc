from app.models import (
    AccessRight,
    ClientCredential,
    Device,
    OutboxEvent,
    PolicyHistory,
    PolicyRecord,
    RequestLog,
    Tenant,
    WebhookDeliveryAttempt,
    WebhookSubscription,
    WorkflowConfigHistory,
    WorkflowConfigRecord,
)


# #805
def test_tenant_table_name():
    assert Tenant.__tablename__ == "tenants"


# #806
def test_client_credential_table_name():
    assert ClientCredential.__tablename__ == "client_credentials"


# #807
def test_device_table_name():
    assert Device.__tablename__ == "devices"


# #808
def test_access_right_table_name():
    assert AccessRight.__tablename__ == "access_rights"


# #809
def test_request_log_table_name():
    assert RequestLog.__tablename__ == "request_logs"


# #810
def test_webhook_subscription_table_name():
    assert WebhookSubscription.__tablename__ == "webhook_subscriptions"


# #811
def test_outbox_event_table_name():
    assert OutboxEvent.__tablename__ == "outbox_events"


# #812
def test_webhook_delivery_attempt_table_name():
    assert WebhookDeliveryAttempt.__tablename__ == "webhook_delivery_attempts"


# #813
def test_policy_record_table_name():
    assert PolicyRecord.__tablename__ == "policies"


# #814
def test_policy_history_table_name():
    assert PolicyHistory.__tablename__ == "policy_history"


# #815
def test_workflow_config_table_name():
    assert WorkflowConfigRecord.__tablename__ == "workflow_configs"


# #816
def test_workflow_config_history_table_name():
    assert WorkflowConfigHistory.__tablename__ == "workflow_config_history"


# #817
def test_client_credential_has_tenant_client_unique_constraint():
    names = {
        constraint.name
        for constraint in ClientCredential.__table__.constraints
    }
    assert "uq_client_per_tenant" in names


# #818
def test_device_has_tenant_device_unique_constraint():
    names = {
        constraint.name
        for constraint in Device.__table__.constraints
    }
    assert "uq_device_per_tenant" in names


# #819
def test_access_right_has_tenant_right_unique_constraint():
    names = {
        constraint.name
        for constraint in AccessRight.__table__.constraints
    }
    assert "uq_right_per_tenant" in names


# #820
def test_request_log_has_tenant_idempotency_unique_constraint():
    names = {
        constraint.name
        for constraint in RequestLog.__table__.constraints
    }
    assert "uq_request_idempotency_per_tenant" in names


# #821
def test_policy_record_has_tenant_name_unique_constraint():
    names = {
        constraint.name
        for constraint in PolicyRecord.__table__.constraints
    }
    assert "uq_policy_name_per_tenant" in names


# #822
def test_request_log_primary_key_is_id():
    primary_keys = [
        column.name
        for column in RequestLog.__table__.primary_key.columns
    ]
    assert primary_keys == ["id"]


# #823
def test_outbox_event_primary_key_is_id():
    primary_keys = [
        column.name
        for column in OutboxEvent.__table__.primary_key.columns
    ]
    assert primary_keys == ["id"]


# #824
def test_webhook_delivery_attempt_primary_key_is_id():
    primary_keys = [
        column.name
        for column in WebhookDeliveryAttempt.__table__.primary_key.columns
    ]
    assert primary_keys == ["id"]


# #825
def test_request_log_workflow_version_is_nullable():
    assert RequestLog.__table__.c.workflow_version.nullable is True


# #826
def test_request_log_decision_source_is_nullable():
    assert RequestLog.__table__.c.decision_source.nullable is True


# #827
def test_request_log_decision_path_is_nullable():
    assert RequestLog.__table__.c.decision_path.nullable is True


# #828
def test_webhook_subscription_encrypted_secret_is_not_nullable():
    assert (
        WebhookSubscription.__table__.c.signing_secret_encrypted.nullable
        is False
    )


# #829
def test_webhook_delivery_attempt_event_foreign_key_target():
    targets = {
        fk.target_fullname
        for fk in WebhookDeliveryAttempt.__table__.c.event_id.foreign_keys
    }
    assert targets == {"outbox_events.id"}


# #830
def test_webhook_delivery_attempt_subscription_foreign_key_target():
    targets = {
        fk.target_fullname
        for fk in WebhookDeliveryAttempt.__table__.c.subscription_id.foreign_keys
    }
    assert targets == {"webhook_subscriptions.id"}


# #831
def test_policy_record_tenant_foreign_key_target():
    targets = {
        fk.target_fullname
        for fk in PolicyRecord.__table__.c.tenant_id.foreign_keys
    }
    assert targets == {"tenants.id"}


# #832
def test_workflow_config_tenant_foreign_key_target():
    targets = {
        fk.target_fullname
        for fk in WorkflowConfigRecord.__table__.c.tenant_id.foreign_keys
    }
    assert targets == {"tenants.id"}


# #833
def test_request_log_expected_indexed_columns():
    indexed = {
        column.name
        for column in RequestLog.__table__.columns
        if column.index
    }

    assert {
        "tenant_id",
        "right_id",
        "client_id",
        "source_client",
        "device_id",
        "ip_hash",
        "policy_id",
        "trace_id",
        "idempotency_key",
        "token_jti",
        "request_fingerprint",
        "created_at",
    }.issubset(indexed)


# #834
def test_outbox_event_expected_indexed_columns():
    indexed = {
        column.name
        for column in OutboxEvent.__table__.columns
        if column.index
    }

    assert {
        "tenant_id",
        "event_type",
        "next_attempt_at",
    }.issubset(indexed)