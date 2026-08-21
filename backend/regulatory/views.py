from django.db.models import Prefetch

from core.views import BaseModelViewSet as AbstractBaseModelViewSet

from .models import (
    RegulatoryDocument,
    RegulatoryDocumentVersion,
    RegulatoryObligation,
    RegulatoryObligationReviewEvent,
    RegulatoryProvision,
)
from .serializers import (
    RegulatoryDocumentDetailSerializer,
    RegulatoryDocumentReadSerializer,
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

    def get_queryset(self):
        queryset = super().get_queryset()
        if getattr(self, "action", None) != "retrieve":
            return queryset

        review_events = RegulatoryObligationReviewEvent.objects.select_related("actor")
        current_provisions = RegulatoryProvision.objects.filter(
            recorded_to__isnull=True
        )
        current_obligations = RegulatoryObligation.objects.filter(
            recorded_to__isnull=True
        ).prefetch_related(
            Prefetch(
                "review_events",
                queryset=review_events,
                to_attr="prefetched_review_events",
            ),
            Prefetch(
                "provisions",
                queryset=current_provisions,
                to_attr="current_source_provisions",
            ),
        )
        current_provisions = current_provisions.prefetch_related(
            Prefetch(
                "obligations",
                queryset=current_obligations,
                to_attr="current_obligations",
            )
        )
        current_versions = RegulatoryDocumentVersion.objects.filter(
            recorded_to__isnull=True
        ).prefetch_related(
            Prefetch(
                "provisions",
                queryset=current_provisions,
                to_attr="current_provisions",
            ),
        )
        return queryset.prefetch_related(
            Prefetch(
                "versions",
                queryset=current_versions,
                to_attr="current_versions",
            )
        )
