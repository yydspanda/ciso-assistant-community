"""Smoke + redaction tests for the Typst audit posture PDF."""

from django.contrib.auth.models import Permission
from django.urls import reverse
from rest_framework import status

import pymupdf
import pytest

from core.generators import audit_context_for_typst, gen_audit_context
from core.models import AppliedControl, Commitment, Policy, RequirementAssessment, Team
from core.typst_render import localized_template, render_pdf
from core.helpers import (
    annotate_tree_with_aggregated_scores,
    get_sorted_requirement_nodes,
    scoped_requirement_assessments,
)
from core.models import RequirementNode
from iam.models import Folder, Role, RoleAssignment, User

from core.tests.test_audit_word_export import (  # noqa: F401  (fixtures)
    admin_client,
    app_config,
    audit,
)


def _tree(audit_obj):
    tree = get_sorted_requirement_nodes(
        RequirementNode.objects.filter(framework=audit_obj.framework).all(),
        RequirementAssessment.objects.filter(compliance_assessment=audit_obj).all(),
        audit_obj.max_score
        if audit_obj.max_score is not None
        else audit_obj.framework.max_score,
        audit_obj.min_score
        if audit_obj.min_score is not None
        else audit_obj.framework.min_score,
    )
    annotate_tree_with_aggregated_scores(tree, audit_obj)
    return tree


def _report_user():
    email = "typst-report-user@example.test"
    return User.objects.filter(email=email).first() or User.objects.create_superuser(
        email
    )


def _grant_report_permissions(user, folder, *codenames):
    role = Role.objects.create(
        name=f"Typst report role {user.id}",
        folder=Folder.get_root_folder(),
    )
    role.permissions.set(Permission.objects.filter(codename__in=codenames))
    assignment = RoleAssignment.objects.create(
        user=user,
        role=role,
        folder=Folder.get_root_folder(),
        is_recursive=False,
    )
    assignment.perimeter_folders.add(folder)
    return role


def _context(audit_obj, *, user=None):
    user = user or _report_user()
    return gen_audit_context(audit_obj.id, _tree(audit_obj), "en", user=user)


def _render(audit_obj, role, profile="full", lang="en", *, user=None):
    user = user or _report_user()
    payload, images = audit_context_for_typst(
        _context(audit_obj, user=user),
        audit_obj,
        role,
        lang,
        profile,
        user=user,
    )
    from core.generators import REPORT_PROFILES

    template = localized_template(REPORT_PROFILES[profile]["template"], lang)
    return render_pdf(template, payload, images=images), payload


@pytest.mark.django_db
def test_renders_a_pdf_for_the_auditor(audit):
    pdf, _ = _render(audit, "auditor")
    assert pdf[:5] == b"%PDF-", "output is not a PDF"
    doc = pymupdf.open(stream=pdf, filetype="pdf")
    assert doc.page_count >= 2
    assert audit.name in doc[0].get_text()


@pytest.mark.django_db
def test_respondent_render_omits_hidden_fields(audit):
    _, payload = _render(audit, "respondent")
    hidden = set(payload["hidden_fields"])
    assert hidden, "expected the default visibility map to hide something"
    for ra in payload["requirement_assessments"]:
        assert not (hidden & set(ra)), f"hidden field leaked into payload: {ra}"


@pytest.mark.django_db
def test_respondent_pdf_text_has_no_auditor_only_values(audit):
    reqs = list(RequirementAssessment.objects.filter(compliance_assessment=audit))
    for req in reqs:
        req.observation = "canary-observation"
        req.save()

    pdf, payload = _render(audit, "respondent")
    text = "".join(page.get_text() for page in pymupdf.open(stream=pdf, filetype="pdf"))
    assert "canary-observation" in text, "sanity: visible content must be rendered"
    if "status" in set(payload["hidden_fields"]):
        assert "Progress:" not in text
    if "score" in set(payload["hidden_fields"]):
        assert "Score:" not in text


@pytest.mark.django_db
def test_posture_pdf_endpoint_returns_pdf(admin_client, audit):
    url = reverse("compliance-assessments-posture-pdf", kwargs={"pk": str(audit.pk)})
    response = admin_client.get(url)

    assert response.status_code == status.HTTP_200_OK
    assert response["Content-Type"] == "application/pdf"
    assert "_full.pdf" in response["Content-Disposition"]
    assert response.content[:5] == b"%PDF-"


@pytest.mark.django_db
def test_posture_pdf_endpoint_rejects_anonymous(audit):
    from rest_framework.test import APIClient

    url = reverse("compliance-assessments-posture-pdf", kwargs={"pk": str(audit.pk)})
    response = APIClient().get(url)
    assert response.status_code in (
        status.HTTP_401_UNAUTHORIZED,
        status.HTTP_403_FORBIDDEN,
    )


@pytest.mark.django_db
def test_attestation_profile_renders_and_drops_measurement(audit):
    pdf, payload = _render(audit, "auditor", profile="attestation")
    assert pdf[:5] == b"%PDF-"

    text = "".join(page.get_text() for page in pymupdf.open(stream=pdf, filetype="pdf"))
    assert "Signatures" in text, "attestation must carry a signature block"

    # Dropped by the profile even though the reader is an auditor: the values must
    # be absent from the payload, not merely hidden by a template flag.
    for ra in payload["requirement_assessments"]:
        assert "score" not in ra
        assert "max_score" not in ra
        assert "extended_result" not in ra
    assert "category_scores" not in payload
    assert payload["charts"] == []


@pytest.mark.django_db
def test_full_profile_is_the_superset(audit):
    _, payload = _render(audit, "auditor", profile="full")
    assert payload["charts"], "full profile renders charts"
    assert "commitments" in payload
    assert "signatures" not in payload["sections"]


@pytest.mark.django_db
def test_scores_follow_the_audit_visibility_map(audit):
    """`score` is hidden from everyone by default; a scoring framework turns it on."""
    _, hidden_payload = _render(audit, "auditor", profile="full")
    assert "score" in hidden_payload["hidden_fields"]
    assert "category_scores" not in hidden_payload
    assert "category_radar.png" not in hidden_payload["charts"], (
        "a chart drawn from a hidden field must be dropped with it"
    )

    audit.field_visibility = {
        field: {"auditor": "edit", "respondent": "hidden"}
        for field in ("score", "is_scored")
    }
    audit.save()

    _, shown_payload = _render(audit, "auditor", profile="full")
    assert "score" not in shown_payload["hidden_fields"]
    assert "category_scores" in shown_payload
    assert "category_radar.png" in shown_payload["charts"]


@pytest.mark.django_db
@pytest.mark.parametrize("respondent_score_access", ("hidden", "edit"))
def test_scale_bounds_follow_combined_score_visibility_without_mutating_context(
    audit,
    respondent_score_access,
):
    audit.min_score = 37
    audit.max_score = 41
    audit.field_visibility = {
        "score": {"auditor": "edit", "respondent": respondent_score_access},
        "is_scored": {"auditor": "edit", "respondent": "hidden"},
    }
    audit.save(update_fields=["min_score", "max_score", "field_visibility"])
    RequirementAssessment.objects.filter(compliance_assessment=audit).update(
        is_scored=True,
        score=39,
    )

    respondent = User.objects.create_user("typst-scale-respondent@example.test")
    _grant_report_permissions(
        respondent,
        audit.folder,
        "view_complianceassessment",
        "view_framework",
        "view_requirementassessment",
        "view_requirementnode",
    )
    respondent_context = gen_audit_context(
        audit.id,
        _tree(audit),
        "en",
        charts=False,
        user=respondent,
    )
    respondent_payload, _ = audit_context_for_typst(
        respondent_context,
        audit,
        "respondent",
        "en",
        "full",
        user=respondent,
    )

    assert respondent_payload["audit"]["framework"]["name"] == audit.framework.name
    assert "score" in respondent_payload["hidden_fields"]
    assert "min_score" not in respondent_payload["audit"]["framework"]
    assert "max_score" not in respondent_payload["audit"]["framework"]
    assert "category_scores" not in respondent_payload
    for row in respondent_payload["requirement_assessments"]:
        assert "score" not in row
        assert "max_score" not in row
    assert respondent_context["audit"]["framework"]["min_score"] == 37
    assert respondent_context["audit"]["framework"]["max_score"] == 41

    auditor_context = gen_audit_context(
        audit.id,
        _tree(audit),
        "en",
        charts=False,
        user=_report_user(),
    )
    auditor_payload, _ = audit_context_for_typst(
        auditor_context,
        audit,
        "auditor",
        "en",
        "full",
        user=_report_user(),
    )
    assert auditor_payload["audit"]["framework"]["min_score"] == 37
    assert auditor_payload["audit"]["framework"]["max_score"] == 41


@pytest.mark.django_db
def test_requirement_max_scores_use_resolved_ca_and_node_scales(audit):
    audit.min_score = 1
    audit.max_score = 5
    audit.scoring_enabled = True
    audit.save(update_fields=["min_score", "max_score", "field_visibility"])

    requirements = list(
        RequirementNode.objects.filter(framework=audit.framework, assessable=True)
        .order_by("ref_id")
        .values_list("id", "ref_id")[:2]
    )
    overridden_id, overridden_ref = requirements[0]
    _, inherited_ref = requirements[1]
    RequirementNode.objects.filter(id=overridden_id).update(min_score=1, max_score=3)
    RequirementAssessment.objects.filter(compliance_assessment=audit).update(
        is_scored=True,
        score=2,
    )

    context = gen_audit_context(
        audit.id,
        _tree(audit),
        "en",
        charts=False,
        user=_report_user(),
    )
    rows = {row["ref_id"]: row for row in context["requirement_assessments"]}

    assert audit.framework.max_score != audit.max_score
    assert rows[overridden_ref]["max_score"] == 3
    assert rows[inherited_ref]["max_score"] == 5


@pytest.mark.django_db
def test_control_projection_respects_policy_proxy_permission(audit):
    audit.field_visibility = {
        "applied_controls": {"auditor": "edit", "respondent": "hidden"}
    }
    audit.save(update_fields=["field_visibility"])
    requirement = audit.requirement_assessments.filter(
        requirement__assessable=True
    ).first()
    ordinary = AppliedControl.objects.create(
        name="Visible ordinary report control",
        folder=audit.folder,
    )
    policy = Policy.objects.create(
        name="Independently protected report policy",
        folder=audit.folder,
    )
    requirement.applied_controls.add(ordinary, policy)

    user = User.objects.create_user("typst-control-reader@example.test")
    role = _grant_report_permissions(
        user,
        audit.folder,
        "view_appliedcontrol",
        "view_requirementassessment",
    )

    without_policy = _context(audit, user=user)
    assert {row["name"] for row in without_policy["full_controls"]} == {ordinary.name}

    role.permissions.add(Permission.objects.get(codename="view_policy"))
    with_policy = _context(audit, user=user)
    assert {row["name"] for row in with_policy["full_controls"]} == {
        ordinary.name,
        policy.name,
    }


@pytest.mark.django_db
def test_contributor_projection_does_not_expand_hidden_team_members(audit):
    hidden_member = User.objects.create_user("hidden-team-member@example.test")
    hidden_member.folder = audit.folder
    hidden_member.save(update_fields=["folder"])
    team = Team.objects.create(
        name="Visible report team",
        team_email="visible-team@example.test",
        folder=audit.folder,
    )
    team.members.add(hidden_member)
    audit.authors.add(team.actor)

    user = User.objects.create_user("typst-team-reader@example.test")
    role = _grant_report_permissions(
        user,
        audit.folder,
        "view_requirementassessment",
        "view_team",
    )

    without_user_access = _context(audit, user=user)
    assert "visible-team@example.test" in without_user_access["contributors"]
    assert hidden_member.email not in without_user_access["contributors"]

    role.permissions.add(Permission.objects.get(codename="view_user"))
    with_user_access = _context(audit, user=user)
    assert hidden_member.email in with_user_access["contributors"]


@pytest.mark.django_db
def test_undertakings_do_not_read_a_hidden_commitment(audit):
    from core.generators import audit_undertakings

    requirement = audit.requirement_assessments.filter(
        requirement__assessable=True
    ).first()
    control = AppliedControl.objects.create(
        name="Commitment-protected report control",
        folder=audit.folder,
    )
    requirement.applied_controls.add(control)
    Commitment.objects.create(
        target=control,
        state=Commitment.State.IN_NEGOTIATION,
        notes="hidden commitment note",
    )
    user = User.objects.create_user("typst-commitment-reader@example.test")
    role = _grant_report_permissions(
        user,
        audit.folder,
        "view_appliedcontrol",
        "view_requirementassessment",
    )

    hidden_commitments, _ = audit_undertakings(audit, user=user)
    assert hidden_commitments == []

    role.permissions.add(Permission.objects.get(codename="view_commitment"))
    visible_commitments, _ = audit_undertakings(audit, user=user)
    assert [row["notes"] for row in visible_commitments] == ["hidden commitment note"]


@pytest.mark.django_db
def test_attestation_takes_the_respondent_column_but_discloses_the_verdict(audit):
    """Mirrors THIRD_PARTY_VISIBILITY: the verdict is auditor-only during the
    questionnaire, and the attestation is where it gets stated for agreement."""
    audit.field_visibility = {
        "result": {"auditor": "edit", "respondent": "hidden"},
        "score": {"auditor": "edit", "respondent": "hidden"},
        "is_scored": {"auditor": "edit", "respondent": "hidden"},
        "applied_controls": {"auditor": "edit", "respondent": "hidden"},
    }
    audit.save()

    _, full = _render(audit, "auditor", profile="full")
    assert "score" not in full["hidden_fields"]

    _, att = _render(audit, "auditor", profile="attestation")
    # Configured hidden-from-respondent fields drop, even for an auditor caller.
    assert "score" in att["hidden_fields"]
    assert "applied_controls" in att["hidden_fields"]
    # ... except the one the document exists to communicate.
    assert "result" not in att["hidden_fields"]
    for ra in att["requirement_assessments"]:
        assert "result" in ra
        assert "score" not in ra
        assert "applied_controls" not in ra


@pytest.mark.django_db
def test_respondent_attestation_cannot_disclose_the_auditor_verdict(audit):
    audit.field_visibility = {
        "result": {"auditor": "edit", "respondent": "hidden"},
    }
    audit.save()
    respondent = User.objects.create_user("typst-respondent@example.test")
    _grant_report_permissions(
        respondent,
        audit.folder,
        "view_complianceassessment",
        "view_framework",
        "view_requirementassessment",
        "view_requirementnode",
    )

    _, attestation = _render(
        audit,
        "respondent",
        profile="attestation",
        user=respondent,
    )

    assert "result" in attestation["hidden_fields"]
    assert attestation["requirement_assessments"]
    for ra in attestation["requirement_assessments"]:
        assert "result" not in ra
        assert "result_key" not in ra


@pytest.mark.django_db
def test_respondent_cannot_escalate_via_the_full_profile(audit):
    _, payload = _render(audit, "respondent", profile="full")
    assert "status" in payload["hidden_fields"]


@pytest.mark.django_db
def test_unknown_profile_is_rejected(admin_client, audit):
    url = reverse("compliance-assessments-posture-pdf", kwargs={"pk": str(audit.pk)})
    assert admin_client.get(url, {"profile": "nope"}).status_code == 400
    assert admin_client.get(url, {"profile": "attestation"}).status_code == 200


@pytest.mark.django_db
def test_attestation_endpoint_filename_carries_the_profile(admin_client, audit):
    url = reverse("compliance-assessments-posture-pdf", kwargs={"pk": str(audit.pk)})
    response = admin_client.get(url, {"profile": "attestation"})
    assert response.status_code == status.HTTP_200_OK
    assert "_attestation.pdf" in response["Content-Disposition"]
    assert response.content[:5] == b"%PDF-"


@pytest.mark.django_db
def test_attestation_is_a_content_record_not_an_analysis(audit):
    """Same content selection as the zip's audit_report.html: no generated aggregates."""
    _, payload = _render(audit, "auditor", profile="attestation")
    sections = payload["sections"]
    for generated in ("summary", "charts", "drifts", "categories", "controls"):
        assert generated not in sections, (
            f"{generated} is derived, not recorded content"
        )
    for recorded in ("requirements", "answers", "commitments", "tasks"):
        assert recorded in sections
    assert payload["charts"] == []


@pytest.mark.django_db
def test_requirement_rows_carry_questions_and_answers(audit):
    _, payload = _render(audit, "auditor", profile="attestation")
    assert all("answers" in ra for ra in payload["requirement_assessments"]), (
        "the respondent's input is what the countersigned copy records"
    )


@pytest.mark.django_db
def test_disclosure_never_overrides_a_framework_wide_hide(audit):
    """A field hidden from the auditor too is hidden for a reason the attestation
    must not second-guess — the external copy can never show more than the internal."""
    audit.field_visibility = {"result": {"auditor": "hidden", "respondent": "hidden"}}
    audit.save()

    _, att = _render(audit, "auditor", profile="attestation")
    assert "result" in att["hidden_fields"]
    for ra in att["requirement_assessments"]:
        assert "result" not in ra


@pytest.mark.django_db
def test_counterparty_block_is_absent_for_a_plain_internal_audit(audit):
    """An audit not reached through an entity assessment identifies no counterparty."""
    _, payload = _render(audit, "auditor", profile="attestation")
    assert payload["counterparty"] is None


@pytest.mark.django_db
def test_requirement_rows_carry_evidences_and_opted_in_tasks(audit):
    """`evidences` is visible by default; `task_templates` is HIDDEN until the audit
    opts in (third-party questionnaires do, via THIRD_PARTY_VISIBILITY)."""
    _, default_payload = _render(audit, "auditor", profile="full")
    for ra in default_payload["requirement_assessments"]:
        assert "evidences" in ra
        assert "task_templates" not in ra

    audit.field_visibility = {
        "task_templates": {"auditor": "edit", "respondent": "edit"}
    }
    audit.save()

    _, opted_in = _render(audit, "auditor", profile="full")
    for ra in opted_in["requirement_assessments"]:
        assert "task_templates" in ra


@pytest.mark.django_db
def test_hiding_result_drops_the_aggregates_derived_from_it(audit):
    """Redacting rows is not enough: totals and charts recompute the same thing."""
    audit.field_visibility = {"result": {"auditor": "hidden", "respondent": "hidden"}}
    audit.save()

    _, payload = _render(audit, "auditor", profile="full")
    assert "result" in payload["hidden_fields"]
    assert "req" not in payload, "the counts disclose the result distribution"
    assert "drifts_per_domain" not in payload
    for chart in ("compliance_donut.png", "compliance_radar.png", "completion_bar.png"):
        assert chart not in payload["charts"]
    for ra in payload["requirement_assessments"]:
        assert "result_key" not in ra, "the raw value must follow its label"


@pytest.mark.django_db
def test_long_observations_are_not_silently_dropped(audit):
    """A non-breakable block discards overflow without any visible marker."""
    marker = "TAILSENTINEL"
    for ra in RequirementAssessment.objects.filter(compliance_assessment=audit):
        ra.observation = ("Observation text that runs on and on. " * 240) + marker
        ra.save()

    pdf, _ = _render(audit, "auditor", profile="attestation")
    text = "".join(page.get_text() for page in pymupdf.open(stream=pdf, filetype="pdf"))
    assert text.count(marker) >= 1, "the end of a long observation was clipped"


@pytest.mark.django_db
def test_scoping_helper_matches_the_interactive_endpoint(
    admin_client, audit, django_user_model
):
    """The PDF and `requirements_list` must scope rows the same way; an auditor with
    no respondent folders sees every assessment."""
    user = django_user_model.objects.filter(is_superuser=True).first()
    assert user is not None, "without a superuser the scoping contract is not exercised"
    assessments, hidden_urns = scoped_requirement_assessments(audit, user)
    total = audit.get_requirement_assessments(include_non_assessable=True).count()
    assert len(assessments) == total
    assert hidden_urns == set() or isinstance(hidden_urns, (set, frozenset))


@pytest.mark.django_db
@pytest.mark.parametrize("lang", ["en", "fr"])
def test_every_locale_template_renders(audit, lang):
    pdf, _ = _render(audit, "auditor", profile="attestation", lang=lang)
    assert pdf[:5] == b"%PDF-"


@pytest.mark.django_db
def test_locale_templates_do_not_drift(audit):
    """Self-contained templates are twins: a change to one must reach the other.

    Same page count and the same headings for the same payload; the strings differ
    but the structure must not.
    """
    en_pdf, _ = _render(audit, "auditor", profile="attestation", lang="en")
    fr_pdf, _ = _render(audit, "auditor", profile="attestation", lang="fr")

    en_doc = pymupdf.open(stream=en_pdf, filetype="pdf")
    fr_doc = pymupdf.open(stream=fr_pdf, filetype="pdf")
    assert en_doc.page_count == fr_doc.page_count

    fr_text = "".join(page.get_text() for page in fr_doc)
    for english_only in ("Detailed results", "Signatures", "Assessed entity"):
        if english_only == "Signatures":
            continue  # spelled the same in French
        assert english_only not in fr_text, (
            "the French template still has English chrome"
        )


def test_unknown_locale_falls_back_whole():
    """No half-translated documents: an unauthored locale falls back entirely."""
    for stem in ("audit_report", "attestation"):
        assert localized_template(stem, "de") == f"{stem}_en.typ"
        assert localized_template(stem, "fr") == f"{stem}_fr.typ"
        assert localized_template(stem, "fr-CA") == f"{stem}_fr.typ"
        assert localized_template(stem, None) == f"{stem}_en.typ"


@pytest.mark.django_db
def test_french_result_badges_are_singular(audit):
    """One badge qualifies one requirement. `i18n_dict` carries plurals because it
    was written for chart legends and aggregate counts, so the badge must not use it."""
    for ra in RequirementAssessment.objects.filter(compliance_assessment=audit):
        ra.result = "compliant"
        ra.save()

    pdf, _ = _render(audit, "auditor", profile="attestation", lang="fr")
    text = "".join(page.get_text() for page in pymupdf.open(stream=pdf, filetype="pdf"))
    assert "Conforme" in text
    assert "Conformes" not in text, "badge picked up the plural aggregate label"


@pytest.mark.django_db
def test_charts_are_not_rendered_when_the_profile_drops_them(audit):
    """Matplotlib is ~99% of the context phase; a profile without charts must not
    pay for images it then discards."""
    from unittest.mock import patch

    user = _report_user()
    with patch("core.generators.plot_donut") as donut:
        gen_audit_context(str(audit.id), _tree(audit), "en", charts=False, user=user)
    donut.assert_not_called()

    with patch("core.generators.plot_donut", wraps=None) as donut:
        gen_audit_context(str(audit.id), _tree(audit), "en", charts=True, user=user)
    assert donut.called


@pytest.mark.django_db
def test_cover_carries_generation_timestamp_and_document_id(audit):
    pdf, payload = _render(audit, "auditor", profile="attestation")
    assert payload["generated_at"], "traceability needs a full timestamp"
    text = pymupdf.open(stream=pdf, filetype="pdf")[0].get_text()
    assert str(audit.id) in text, "the audit uuid identifies the render"


@pytest.mark.django_db
def test_undertakings_follow_the_scoped_assessments(audit):
    """Commitments and tasks must obey the same row-level scope as the rows: a
    respondent must not see undertakings hanging off unassigned requirements."""
    from core.generators import audit_undertakings

    scoped = list(RequirementAssessment.objects.filter(compliance_assessment=audit))[:1]
    user = _report_user()
    all_commitments, all_tasks = audit_undertakings(audit, "en", user=user)
    scoped_commitments, scoped_tasks = audit_undertakings(
        audit, "en", scoped, user=user
    )

    assert len(scoped_commitments) <= len(all_commitments)
    assert len(scoped_tasks) <= len(all_tasks)


@pytest.mark.django_db
def test_hidden_categories_drop_their_undertakings(audit):
    """`applied_controls` hidden means no control commitments reach the payload."""
    from core.generators import audit_undertakings

    user = _report_user()
    commitments, _ = audit_undertakings(
        audit,
        "en",
        None,
        hidden={"applied_controls", "task_templates"},
        user=user,
    )
    assert commitments == []
