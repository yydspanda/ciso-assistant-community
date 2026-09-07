from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest

from core.views import FindingsAssessmentViewSet
from iam.models import RoleAssignment


@pytest.mark.parametrize("action", ["md", "pdf"])
def test_denied_findings_export_returns_forbidden_without_status_shadow(
    monkeypatch, action
):
    monkeypatch.setattr(
        RoleAssignment,
        "is_object_accessible",
        lambda *_args, **_kwargs: False,
    )
    request = SimpleNamespace(user=object())

    response = getattr(FindingsAssessmentViewSet(), action)(
        request,
        pk=str(uuid.uuid4()),
    )

    assert response.status_code == 403
    assert response.data == {"error": "Permission denied"}
