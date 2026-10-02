"""Bounded read and write authority for QuickFormResponse answers.

The response endpoint owns regular folder IAM; respondent membership is not a
read grant. Its form definition supplies the questions/choices as it does on
the response content endpoint. Writes additionally require the exact Answer
action on the response's current folder. Requester/state rules remain business
validation and are intentionally evaluated only after these authority proofs.
"""

from dataclasses import dataclass
from typing import Literal

from django.contrib.auth.models import Permission
from django.db.models import F, Q, QuerySet
from iam.models import RoleAssignment, User

from core.models import Answer, QuickFormResponse

AnswerMutationAction = Literal["add", "change", "delete"]


class QuickFormAnswerAuthorityUnavailable(Exception):
    """A quick-form Answer parent or required grant is not caller-visible."""


@dataclass(frozen=True)
class LockedQuickFormAnswerMutation:
    """Rows locked in the shared Response-before-Answer order."""

    response: QuickFormResponse
    answer: Answer | None


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
            folder_id=F("response__folder_id"),
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


@dataclass(frozen=True)
class QuickFormAnswerAuthority:
    """Request-scoped QF Answer authority with deterministic parent ownership."""

    user: User

    @classmethod
    def for_user(cls, user: User) -> "QuickFormAnswerAuthority":
        if not (
            isinstance(user, User)
            and user.is_authenticated
            and getattr(user, "is_active", False)
        ):
            raise QuickFormAnswerAuthorityUnavailable
        return cls(user=user)

    @staticmethod
    def _answer_permission(action: AnswerMutationAction) -> Permission:
        return Permission.objects.get(
            content_type__app_label="core",
            content_type__model="answer",
            codename=f"{action}_answer",
        )

    def _visible_response(self, response_id) -> QuickFormResponse | None:
        return (
            QuickFormResponse.objects.select_related("folder", "quick_form")
            .filter(
                id=response_id,
                id__in=RoleAssignment.get_viewable_object_ids(
                    self.user, QuickFormResponse
                ),
            )
            .first()
        )

    def _assert_answer_action(
        self, response: QuickFormResponse, action: AnswerMutationAction
    ) -> None:
        if not RoleAssignment.is_access_allowed(
            user=self.user,
            perm=self._answer_permission(action),
            folder=response.folder,
        ):
            raise QuickFormAnswerAuthorityUnavailable

    def resolve_response(
        self, response_id, *, action: AnswerMutationAction
    ) -> QuickFormResponse:
        """Resolve a parent only inside QFR view IAM plus its Answer action."""

        try:
            response = self._visible_response(response_id)
            if response is None:
                raise QuickFormAnswerAuthorityUnavailable
            self._assert_answer_action(response, action)
        except (NotImplementedError, Permission.DoesNotExist) as exc:
            raise QuickFormAnswerAuthorityUnavailable from exc
        return response

    def resolve_existing_response(
        self,
        response_id,
        *,
        answer_id,
        action: Literal["change", "delete"],
    ) -> QuickFormResponse:
        """Pre-authorize an existing Answer before definition field lookup."""

        response = self.resolve_response(response_id, action=action)
        try:
            answer_identity = (
                Answer.objects.filter(
                    id=answer_id,
                    id__in=RoleAssignment.get_viewable_object_ids(self.user, Answer),
                )
                .values("response_id", "folder_id")
                .first()
            )
        except (NotImplementedError, Permission.DoesNotExist) as exc:
            raise QuickFormAnswerAuthorityUnavailable from exc
        if answer_identity is None or (
            answer_identity["response_id"] != response.id
            or answer_identity["folder_id"] != response.folder_id
        ):
            raise QuickFormAnswerAuthorityUnavailable
        return response

    def lock_mutation(
        self,
        response_id,
        *,
        action: AnswerMutationAction,
        answer_id=None,
        expected_folder_id=None,
        expected_quick_form_id=None,
    ) -> LockedQuickFormAnswerMutation:
        """Lock and re-prove current authority in Response-before-Answer order.

        Callers must already be inside ``transaction.atomic()``. This protocol
        serializes Answer writers that use it. QuickFormResponse status writers
        do not yet share the protocol, so it does not claim to close that wider
        submit-versus-answer race.
        """

        try:
            response = (
                QuickFormResponse.objects.select_for_update(of=("self",))
                .select_related("folder", "quick_form")
                .filter(
                    id=response_id,
                    id__in=RoleAssignment.get_viewable_object_ids(
                        self.user, QuickFormResponse
                    ),
                )
                .first()
            )
            if response is None:
                raise QuickFormAnswerAuthorityUnavailable
            self._assert_answer_action(response, action)
            if (
                expected_folder_id is not None
                and response.folder_id != expected_folder_id
            ) or (
                expected_quick_form_id is not None
                and response.quick_form_id != expected_quick_form_id
            ):
                raise QuickFormAnswerAuthorityUnavailable

            answer = None
            if answer_id is not None:
                answer = (
                    Answer.objects.select_for_update()
                    .filter(
                        id=answer_id,
                        id__in=RoleAssignment.get_viewable_object_ids(
                            self.user, Answer
                        ),
                    )
                    .first()
                )
                if answer is None or (
                    answer.response_id != response.id
                    or answer.folder_id != response.folder_id
                ):
                    raise QuickFormAnswerAuthorityUnavailable
        except (NotImplementedError, Permission.DoesNotExist) as exc:
            raise QuickFormAnswerAuthorityUnavailable from exc
        return LockedQuickFormAnswerMutation(response=response, answer=answer)
