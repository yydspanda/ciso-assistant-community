from django.core.exceptions import (
    MultipleObjectsReturned,
    ObjectDoesNotExist,
    ValidationError as DjangoValidationError,
)
from django.db import transaction
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from rest_framework.decorators import action
from rest_framework.exceptions import NotFound, ValidationError
from rest_framework.response import Response

from core.views import BaseModelViewSet as AbstractBaseModelViewSet
from iam.models import Folder
from tprm.models import Entity

from .models import RegulatoryDocument
from .serializers import (
    RegulatoryApplicabilityDecisionReadSerializer,
    RegulatoryApplicabilityReviewDispositionReadSerializer,
    RegulatoryDocumentDetailSerializer,
    RegulatoryDocumentReadSerializer,
)
from .services import (
    get_regulatory_applicability,
    get_regulatory_applicability_review,
)
from .services.records import (
    RegulatoryRecordedStateUnavailable,
    regulatory_document_recorded_floor,
    select_regulatory_chain_at,
)


class RegulatoryDocumentViewSet(AbstractBaseModelViewSet):
    """IAM-filtered, read-only Phase 1 regulatory register."""

    # BaseModelViewSet carries generic mutation/cascade helper actions. They are
    # intentionally absent from this bounded read contract, not merely blocked
    # by HTTP method filtering.
    batch_action = None
    cascade_info = None
    object = None

    model = RegulatoryDocument
    http_method_names = ["get", "head", "options"]
    search_fields = ["record_id", "title_zh", "title_en", "issuer"]
    filterset_fields = ["folder", "authority_level", "coverage_stage"]

    def get_serializer_class(self, **kwargs):
        if getattr(self, "action", None) == "retrieve":
            return RegulatoryDocumentDetailSerializer
        return RegulatoryDocumentReadSerializer

    def _selection_time(self, recorded_floor=None):
        cached = getattr(self, "_recorded_time_selection", None)
        if cached is not None:
            return cached

        values = self.request.query_params.getlist("recorded_as_of")
        wall_time = timezone.now()
        request_time = (
            max(wall_time, recorded_floor) if recorded_floor is not None else wall_time
        )
        if getattr(self, "action", None) not in {
            "retrieve",
            "applicability",
            "applicability_review",
        }:
            if values:
                raise ValidationError(
                    {
                        "recorded_as_of": (
                            "Recorded-time selection is available only on detail."
                        )
                    }
                )
            selection = (request_time, None)
        elif not values:
            selection = (request_time, None)
        else:
            if len(values) != 1 or not values[0].strip():
                raise ValidationError(
                    {"recorded_as_of": "Provide one non-empty timestamp."}
                )
            parsed = parse_datetime(values[0])
            if parsed is None or timezone.is_naive(parsed):
                raise ValidationError(
                    {"recorded_as_of": ("Use a timezone-aware RFC 3339 date-time.")}
                )
            if parsed > request_time:
                raise ValidationError(
                    {"recorded_as_of": "A future recorded-time query is not allowed."}
                )
            selection = (parsed, parsed)
        self._recorded_time_selection = selection
        return selection

    def get_queryset(self):
        if getattr(self, "action", None) not in {
            "retrieve",
            "applicability",
            "applicability_review",
        } and self.request.query_params.getlist("recorded_as_of"):
            self._selection_time()
        return super().get_queryset()

    def get_serializer_context(self):
        context = super().get_serializer_context()
        _, requested = self._selection_time()
        context["requested_recorded_as_of"] = requested
        return context

    @transaction.atomic
    def retrieve(self, request, *args, **kwargs):
        document = self.get_object()
        folder = Folder.objects.select_for_update().get(pk=document.folder_id)
        recorded_floor = regulatory_document_recorded_floor(
            document=document,
            folder=folder,
        )
        selection_time, _ = self._selection_time(recorded_floor)
        try:
            chain = select_regulatory_chain_at(
                document=document,
                folder=folder,
                recorded_as_of=selection_time,
            )
            document.selected_versions = [chain.document_version]
        except DjangoValidationError as exc:
            raise NotFound(
                "No complete regulatory chain exists at the requested recorded time."
            ) from exc
        serializer = self.get_serializer(document)
        data = serializer.data
        field_models = self._get_fieldsrelated_map(serializer)
        if field_models:
            allowed_ids = self._get_accessible_ids_map(set(field_models.values()))
            data = self._filter_related_fields(data, field_models, allowed_ids)
        return Response(data)

    def _applicability_scope_and_time(self, request):
        """Validate the shared, explicit entity and recorded-time query scope."""

        entity_values = request.query_params.getlist("entity")
        if len(entity_values) != 1 or not entity_values[0].strip():
            raise ValidationError(
                {"entity": "Provide exactly one non-empty entity UUID."}
            )
        try:
            entity = Entity.objects.get(pk=entity_values[0])
        except (DjangoValidationError, ObjectDoesNotExist) as exc:
            raise NotFound("The requested applicability scope is unavailable.") from exc

        recorded_values = request.query_params.getlist("recorded_as_of")
        requested_recorded_as_of = None
        if recorded_values:
            if len(recorded_values) != 1 or not recorded_values[0].strip():
                raise ValidationError(
                    {"recorded_as_of": "Provide one non-empty timestamp."}
                )
            requested_recorded_as_of = parse_datetime(recorded_values[0])
            if requested_recorded_as_of is None or timezone.is_naive(
                requested_recorded_as_of
            ):
                raise ValidationError(
                    {"recorded_as_of": ("Use a timezone-aware RFC 3339 date-time.")}
                )
        return entity, requested_recorded_as_of

    @action(detail=True, methods=["get"], url_path="applicability")
    def applicability(self, request, *args, **kwargs):
        """Read one explicitly entity-scoped, non-binding applicability result."""

        document = self.get_object()
        entity, requested_recorded_as_of = self._applicability_scope_and_time(request)

        try:
            selection = get_regulatory_applicability(
                actor=request.user,
                entity=entity,
                document_id=document.id,
                recorded_as_of=requested_recorded_as_of,
            )
        except RegulatoryRecordedStateUnavailable as exc:
            raise NotFound(
                "No coherent applicability state exists for this scope and time."
            ) from exc
        except DjangoValidationError as exc:
            if hasattr(exc, "message_dict") and "recorded_as_of" in exc.message_dict:
                raise ValidationError(exc.message_dict) from exc
            raise NotFound(
                "No coherent applicability state exists for this scope and time."
            ) from exc
        except (ObjectDoesNotExist, MultipleObjectsReturned) as exc:
            raise NotFound(
                "No coherent applicability state exists for this scope and time."
            ) from exc

        decision_data = None
        if selection.decision is not None:
            decision_data = RegulatoryApplicabilityDecisionReadSerializer(
                selection.decision,
                context={"request": request},
            ).data
        return Response(
            {
                "contract_status": "draft",
                "legal_conclusion": False,
                "is_binding": False,
                "scope": {
                    "type": "legal_entity",
                    "id": str(entity.id),
                },
                "document_id": str(document.id),
                "obligation_id": selection.chain.obligation.record_id,
                "obligation_revision": selection.chain.obligation.revision,
                "recorded_as_of": (
                    requested_recorded_as_of.isoformat()
                    if requested_recorded_as_of is not None
                    else None
                ),
                "selected_recorded_at": selection.recorded_as_of.isoformat(),
                "evaluation_status": (
                    "evaluated" if selection.decision is not None else "not_evaluated"
                ),
                "non_binding_result": (
                    selection.decision.result
                    if selection.decision is not None
                    else "needs_review"
                ),
                "reason_code": (
                    selection.decision.rationale_code
                    if selection.decision is not None
                    else "no_decision_for_selected_obligation_revision"
                ),
                "decision": decision_data,
            }
        )

    @action(detail=True, methods=["get"], url_path="applicability-review")
    def applicability_review(self, request, *args, **kwargs):
        """Read the human disposition of one exact non-binding decision revision."""

        document = self.get_object()
        entity, requested_recorded_as_of = self._applicability_scope_and_time(request)
        try:
            selection = get_regulatory_applicability_review(
                actor=request.user,
                entity=entity,
                document_id=document.id,
                recorded_as_of=requested_recorded_as_of,
            )
        except RegulatoryRecordedStateUnavailable as exc:
            raise NotFound(
                "No coherent applicability review state exists for this scope and time."
            ) from exc
        except DjangoValidationError as exc:
            if hasattr(exc, "message_dict") and "recorded_as_of" in exc.message_dict:
                raise ValidationError(exc.message_dict) from exc
            raise NotFound(
                "No coherent applicability review state exists for this scope and time."
            ) from exc
        except (ObjectDoesNotExist, MultipleObjectsReturned) as exc:
            raise NotFound(
                "No coherent applicability review state exists for this scope and time."
            ) from exc

        applicability = selection.applicability
        decision_data = None
        if applicability.decision is not None:
            decision_data = RegulatoryApplicabilityDecisionReadSerializer(
                applicability.decision,
                context={"request": request},
            ).data

        disposition_data = None
        if selection.disposition is not None:
            disposition_data = RegulatoryApplicabilityReviewDispositionReadSerializer(
                selection.disposition,
                context={
                    "request": request,
                    "reviewer_reference": selection.reviewer,
                },
            ).data

        return Response(
            {
                "contract_status": "draft",
                "legal_conclusion": False,
                "is_binding": False,
                "scope": {
                    "type": "legal_entity",
                    "id": str(entity.id),
                },
                "document_id": str(document.id),
                "obligation_id": applicability.chain.obligation.record_id,
                "obligation_revision": applicability.chain.obligation.revision,
                "recorded_as_of": (
                    requested_recorded_as_of.isoformat()
                    if requested_recorded_as_of is not None
                    else None
                ),
                "selected_recorded_at": applicability.recorded_as_of.isoformat(),
                "evaluation_status": (
                    "evaluated"
                    if applicability.decision is not None
                    else "not_evaluated"
                ),
                "computed_non_binding_result": (
                    applicability.decision.result
                    if applicability.decision is not None
                    else "needs_review"
                ),
                "decision": decision_data,
                "review_state": selection.review_state,
                "workflow_attention": selection.workflow_attention,
                "latest_disposition": disposition_data,
            }
        )
