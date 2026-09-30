"""Bounded read branch for the upstream QuickFormResponse answer owner.

The response endpoint owns regular folder IAM; respondent membership is not a
read grant. Its form definition supplies the questions/choices as it does on
the response content endpoint. This scope does not authorize mutations, which
still require Answer IAM and the existing requester/state validation.
"""

from dataclasses import dataclass

from django.db.models import F, Q, QuerySet
from iam.models import RoleAssignment, User

from core.models import QuickFormResponse


@dataclass(frozen=True)
class QuickFormAnswerVisibility:
    response_ids: QuerySet

    @classmethod
    def for_user(cls, user: User):
        return cls(
            response_ids=RoleAssignment.get_viewable_object_ids(user, QuickFormResponse)
        )

    def answer_filter(self) -> Q:
        """One existing response owner and a question from exactly its form."""
        return Q(
            requirement_assessment__isnull=True,
            response_id__in=self.response_ids,
            question__requirement_node__isnull=True,
            question__page__quick_form_id=F("response__quick_form_id"),
        )

    def choice_filter(self) -> Q:
        """Choices of definitions supplied by an IAM-readable response only.

        The Answer serializer additionally verifies each selected choice's
        exact question, so a corrupt cross-question M2M row cannot be retained.
        """
        return Q(
            question__requirement_node__isnull=True,
            question__page__quick_form__responses__id__in=self.response_ids,
        )
