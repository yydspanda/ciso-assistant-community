import pytest
from auditlog.models import LogEntry
from auditlog.registry import auditlog
from rest_framework.test import APIClient

from automation.workflows import actions
from automation.workflows.events import dispatch_internal_event, event_key_catalog
from automation.workflows.models import (
    Workflow,
    WorkflowInstance,
    WorkflowNode,
    WorkflowTrigger,
    WorkflowVersion,
)
from automation.workflows.tasks import dispatch_internal_event_task
from automation.workflows.tests.helpers import publisher_user
from regulatory.services import create_regulatory_chain

from .factories import (
    chain_payload,
    make_folder,
    make_synthetic_entity,
    make_user_with_permissions,
)


def _entry_model(entry):
    return entry["model"] if isinstance(entry, dict) else entry.model


def _regulatory_audit_models():
    return {
        model
        for model in auditlog.get_models()
        if model._meta.app_label == "regulatory"
    }


def test_regulatory_models_remain_audited_but_opt_out_of_workflow_events():
    models = _regulatory_audit_models()

    assert {model._meta.model_name for model in models} == {
        "entitydocumentregistration",
        "regulatoryapplicabilitydecision",
        "regulatoryapplicabilityreviewdisposition",
        "regulatorychaincorrectionevent",
        "regulatorydocument",
        "regulatorydocumentversion",
        "regulatoryobligation",
        "regulatoryobligationprovision",
        "regulatoryobligationreviewevent",
        "regulatoryprovision",
    }
    assert all(model.workflow_internal_events_enabled is False for model in models)

    catalog_models = {entry["model"] for entry in event_key_catalog()}
    assert not catalog_models.intersection(model._meta.model_name for model in models)


def test_workflow_action_registries_do_not_expose_regulatory_models():
    registries = [
        actions.CREATABLE_MODELS,
        actions.READABLE_MODELS,
        getattr(actions, "UPDATABLE_MODELS", {}),
    ]

    exposed = {
        _entry_model(entry)._meta.label_lower
        for registry in registries
        for entry in registry.values()
    }
    assert not any(label.startswith("regulatory.") for label in exposed)


@pytest.mark.django_db
def test_regulatory_event_keys_are_not_exposed_by_the_workflow_api(regulatory_root):
    client = APIClient()
    client.force_authenticate(publisher_user())

    response = client.get("/api/workflows/workflow-triggers/event-keys/")

    assert response.status_code == 200
    regulatory_model_names = {
        model._meta.model_name for model in _regulatory_audit_models()
    }
    assert not regulatory_model_names.intersection(
        entry["model"] for entry in response.json()
    )


@pytest.mark.django_db
def test_regulatory_writes_keep_auditlog_without_starting_stale_trigger(
    regulatory_root,
):
    folder = make_folder("Regulatory workflow isolation")
    entity = make_synthetic_entity(folder, "WORKFLOW-ISOLATION")
    actor = make_user_with_permissions(folder, "ingest_regulatoryrecord")
    runner = publisher_user()
    workflow = Workflow.objects.create(name="Stale regulatory trigger", folder=folder)
    version = WorkflowVersion.objects.create(
        workflow=workflow,
        status=WorkflowVersion.Status.PUBLISHED,
        run_as=runner,
    )
    WorkflowNode.objects.create(
        version=version,
        type=WorkflowNode.Type.TRIGGER,
        ref="legacy_regulatory_event",
        trigger_config={
            "type": "internal_event",
            "event_key": "regulatorydocument.created",
        },
    )
    WorkflowTrigger.objects.create(
        workflow=workflow,
        node_ref="legacy_regulatory_event",
        type=WorkflowTrigger.Type.INTERNAL_EVENT,
        enabled=True,
        event_key="regulatorydocument.created",
        config={
            "type": "internal_event",
            "event_key": "regulatorydocument.created",
        },
    )

    chain = create_regulatory_chain(
        actor=actor,
        entity=entity,
        payload=chain_payload("WORKFLOW-ISOLATION"),
        idempotency_key="regulatory-workflow-isolation",
    )
    event = {
        "event_key": "regulatorydocument.created",
        "model": "regulatorydocument",
        "app_label": "regulatory",
        "operation": "created",
        "object_id": str(chain.document.id),
        "object_repr": str(chain.document),
        "changes": {},
        "new_values": {},
        "folder_id": str(folder.id),
        "actor_email": actor.email,
        "timestamp": None,
    }

    log_entry = LogEntry.objects.filter(
        content_type__app_label="regulatory", object_pk=str(chain.document.pk)
    ).first()
    assert log_entry is not None

    # A task queued before deployment reconstructs the complete model identity
    # from LogEntry and must cross the same dispatch deny boundary.
    dispatch_internal_event_task.call_local(log_entry.pk, 0)
    assert not WorkflowInstance.objects.filter(workflow=workflow).exists()

    assert not dispatch_internal_event(
        "regulatorydocument.created", event, folder_id=folder.id
    )

    legacy_event = dict(event)
    legacy_event.pop("app_label")
    assert not dispatch_internal_event(
        "regulatorydocument.created", legacy_event, folder_id=folder.id
    )

    stripped_event = dict(legacy_event)
    stripped_event.pop("model")
    assert not dispatch_internal_event(
        "regulatorydocument.created", stripped_event, folder_id=folder.id
    )
    assert not dispatch_internal_event(
        "regulatorydocument.created", {}, folder_id=folder.id
    )

    forged_event = dict(event)
    forged_event.update(
        {
            "app_label": "core",
            "model": "appliedcontrol",
            "event_key": "regulatorydocument.created",
        }
    )
    assert not dispatch_internal_event(
        "regulatorydocument.created", forged_event, folder_id=folder.id
    )
    assert not WorkflowInstance.objects.filter(workflow=workflow).exists()
