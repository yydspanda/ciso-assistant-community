"""The benchmark command's transaction is not a persistent data importer.

Generators and measurements are bounded test doubles: these are rollback
regressions, not a benchmark run or comparative performance evidence.
"""

import importlib
import io

import pytest
from django.apps import apps
from django.db import connection
from iam.models import Folder

from core.models import AppliedControl, Asset, Comment
from core.startup import startup

pytestmark = pytest.mark.django_db


@pytest.fixture
def benchmark_command(monkeypatch):
    # The operational command enables flags at import time. Its tests must not
    # change the flag policy of unrelated API tests in the same Python process.
    import core.permissions
    import core.views
    import global_settings.utils

    # Load serializers under the real flag policy first. Otherwise importing
    # them from the command's discovery loop could capture its temporary flag
    # function in an additional module outside the three direct assignments.
    for app_config in apps.get_app_configs():
        try:
            importlib.import_module(f"{app_config.name}.serializers")
        except ModuleNotFoundError:
            pass
    flag_modules = (core.permissions, core.views, global_settings.utils)
    previous_flags = {module: module.ff_is_enabled for module in flag_modules}
    try:
        command = importlib.import_module(
            "core.management.commands.benchmark_n_plus_1_queries"
        )
    finally:
        for module, original_flag in previous_flags.items():
            module.ff_is_enabled = original_flag

    class BoundedDependencyTree:
        def load_models(self, models, *, blacklisted_models):
            pass

        def __iter__(self):
            return iter((Asset,))

    # No discovery, external dispatch, or global synthetic-object cache is used.
    monkeypatch.setattr(command.Global, "init", lambda count: None)
    monkeypatch.setattr(command, "DependencyTree", BoundedDependencyTree)
    return command


@pytest.fixture
def rollback_sentinels():
    startup(sender=None, **{})
    domain = Folder.objects.create(
        name="Synthetic benchmark domain",
        parent_folder=Folder.get_root_folder(),
        content_type=Folder.ContentType.DOMAIN,
    )
    asset = Asset.objects.create(name="Existing sentinel asset", folder=domain)
    control = AppliedControl.objects.create(
        name="Existing sentinel control", folder=domain, category="technical"
    )
    comment = Comment.objects.create(
        body="Existing sentinel comment", applied_control=control, folder=domain
    )
    return domain, asset, control, comment


def _ids():
    return {
        model: set(model.objects.values_list("id", flat=True))
        for model in (Asset, AppliedControl, Comment)
    }


@pytest.mark.parametrize("raise_after_creation", [False, True])
def test_benchmark_rolls_back_generated_work_and_preserves_existing_rows(
    benchmark_command, rollback_sentinels, monkeypatch, raise_after_creation
):
    command = benchmark_command
    domain, asset, control, comment = rollback_sentinels
    before = _ids()
    created_batches = []

    class BoundedObjectCreator:
        def __init__(self, model, count):
            assert model is Asset
            assert count == 2  # one initial row plus the requested extra row

        def create(self):
            assert connection.in_atomic_block
            generated_asset = Asset.objects.create(
                name="Temporary benchmark asset", folder=domain
            )
            generated_control = AppliedControl.objects.create(
                name="Temporary benchmark control", folder=domain, category="technical"
            )
            generated_comment = Comment.objects.create(
                body="Temporary benchmark comment",
                applied_control=generated_control,
                folder=domain,
            )
            created_batches.append(
                (generated_asset.id, generated_control.id, generated_comment.id)
            )
            assert all(len(_ids()[model]) == len(before[model]) + 1 for model in before)
            if raise_after_creation:
                raise RuntimeError("Synthetic generator failure")
            # This constant is not an actual N+1 query measurement.
            return 0

    monkeypatch.setattr(command, "ObjectCreator", BoundedObjectCreator)
    for _attempt in range(2):
        instance = command.Command(stdout=io.StringIO())
        if raise_after_creation:
            with pytest.raises(RuntimeError, match="Synthetic generator failure"):
                instance.handle(output=None, object_to_create_count=1)
        else:
            instance.handle(output=None, object_to_create_count=1)
        assert _ids() == before
        assert not connection.needs_rollback
        for sentinel in (asset, control, comment):
            sentinel.refresh_from_db()

    assert len(created_batches) == 2
    assert created_batches[0] != created_batches[1]
