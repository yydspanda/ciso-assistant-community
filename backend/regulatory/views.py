from django.core.exceptions import ValidationError as DjangoValidationError
from django.db import transaction
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from rest_framework.exceptions import NotFound, ValidationError
from rest_framework.response import Response

from core.views import BaseModelViewSet as AbstractBaseModelViewSet
from iam.models import Folder

from .models import RegulatoryDocument
from .serializers import (
    RegulatoryDocumentDetailSerializer,
    RegulatoryDocumentReadSerializer,
)
from .services.records import (
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
        if getattr(self, "action", None) != "retrieve":
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
        if getattr(
            self, "action", None
        ) != "retrieve" and self.request.query_params.getlist("recorded_as_of"):
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
