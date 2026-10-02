"""Request-scoped, batched IAM projection for questionnaire API reads."""

from dataclasses import dataclass, field
from typing import Any

from django.db.models import F, Prefetch
from django.utils.translation import get_language
from iam.models import RoleAssignment

from core.models import (
    Answer,
    Framework,
    Question,
    QuestionChoice,
    RequirementAssessment,
    RequirementNode,
)
from core.utils import _is_question_visible, resolve_compute_result

REDACTED_DEPENDENCY = {
    "question": "__iam_unavailable_question__",
    "answers": [],
    "condition": "any",
}


def project_question_dependency(
    depends_on,
    *,
    visible_question_urns,
    visible_choice_urns_by_question,
    choice_question_urns,
):
    """Project one dependency through both Question and QuestionChoice IAM.

    The boolean indicates whether retaining the dependency preserves its
    semantics.  In particular, an ``all`` dependency cannot lose even one
    hidden expected choice, while an ``any`` dependency remains usable when at
    least one expected choice is visible.
    """
    if not isinstance(depends_on, dict):
        return depends_on, True
    dependency_urn = depends_on.get("question")
    if not dependency_urn:
        return depends_on, True
    if dependency_urn not in visible_question_urns:
        return None, False
    if dependency_urn not in choice_question_urns:
        return depends_on, True
    expected = depends_on.get("answers")
    if not isinstance(expected, list):
        return depends_on, True
    allowed = visible_choice_urns_by_question.get(dependency_urn, frozenset())
    projected = [value for value in expected if value in allowed]
    condition = depends_on.get("condition", "any")
    if (condition == "any" and not projected) or (
        condition == "all" and len(projected) != len(expected)
    ):
        return None, False
    result = dict(depends_on)
    result["answers"] = projected
    return result, True


def project_questionnaire_payload(
    questions,
    *,
    visible_question_urns,
    visible_choice_urns_by_question,
    choice_question_urns,
):
    """Apply the established IAM projection without weakening dependencies."""

    effective_question_urns = set(visible_question_urns).intersection(questions)
    while True:
        retained = {
            urn
            for urn in effective_question_urns
            if project_question_dependency(
                questions[urn].get("depends_on"),
                visible_question_urns=effective_question_urns,
                visible_choice_urns_by_question=visible_choice_urns_by_question,
                choice_question_urns=choice_question_urns,
            )[1]
        }
        if retained == effective_question_urns:
            break
        effective_question_urns = retained

    projected_questions = {}
    for question_urn, question_data in questions.items():
        if question_urn not in effective_question_urns:
            continue
        question_data = dict(question_data)
        depends_on = question_data.get("depends_on")
        dependency, dependency_is_safe = project_question_dependency(
            depends_on,
            visible_question_urns=effective_question_urns,
            visible_choice_urns_by_question=visible_choice_urns_by_question,
            choice_question_urns=choice_question_urns,
        )
        if not dependency_is_safe:
            continue
        if isinstance(depends_on, dict):
            question_data["depends_on"] = dependency
        if isinstance(question_data.get("choices"), list):
            allowed = visible_choice_urns_by_question.get(question_urn, frozenset())
            question_data["choices"] = [
                choice
                for choice in question_data["choices"]
                if choice.get("urn") in allowed
            ]
            if not question_data["choices"]:
                question_data.pop("choices")
        projected_questions[question_urn] = question_data
    return projected_questions or None


@dataclass(frozen=True)
class DirectQuestionVisibilityContext:
    """Caller-bound IAM projection for one direct Question response page."""

    request: Any = field(repr=False, compare=False)
    user_id: Any
    question_ids: frozenset
    choices_by_question_id: dict = field(repr=False, compare=False)
    dependencies_by_question_id: dict = field(repr=False, compare=False)

    @classmethod
    def build(cls, *, request, questions):
        questions = tuple(questions)
        question_ids = frozenset(
            question.id for question in questions if getattr(question, "id", None)
        )
        user = getattr(request, "user", None)
        user_id = getattr(user, "pk", None)
        if user_id is None or not getattr(user, "is_authenticated", False):
            return cls(
                request=request,
                user_id=user_id,
                question_ids=question_ids,
                choices_by_question_id={},
                dependencies_by_question_id={
                    question.id: dict(REDACTED_DEPENDENCY)
                    for question in questions
                    if question.depends_on
                },
            )

        dependency_urns = {
            dependency.get("question")
            for question in questions
            if isinstance((dependency := question.depends_on), dict)
            and dependency.get("question")
        }
        visible_question_ids = RoleAssignment.get_viewable_object_ids(user, Question)
        visible_requirement_node_ids = RoleAssignment.get_viewable_object_ids(
            user, RequirementNode
        )
        visible_framework_ids = RoleAssignment.get_viewable_object_ids(user, Framework)
        dependency_questions = list(
            Question.objects.filter(
                urn__in=dependency_urns,
                id__in=visible_question_ids,
                requirement_node_id__in=visible_requirement_node_ids,
                requirement_node__framework_id__in=visible_framework_ids,
            ).only("id", "urn", "type")
        )
        visible_dependency_urns = frozenset(
            question.urn for question in dependency_questions
        )
        choice_dependency_urns = frozenset(
            question.urn
            for question in dependency_questions
            if question.type
            in (Question.Type.UNIQUE_CHOICE, Question.Type.MULTIPLE_CHOICE)
        )
        scoped_question_ids = question_ids.union(
            question.id for question in dependency_questions
        )
        visible_choice_ids = RoleAssignment.get_viewable_object_ids(
            user, QuestionChoice
        )
        visible_choices = list(
            QuestionChoice.objects.filter(
                question_id__in=scoped_question_ids,
                id__in=visible_choice_ids,
                question__requirement_node_id__in=visible_requirement_node_ids,
                question__requirement_node__framework_id__in=visible_framework_ids,
            )
            .filter(question_id__in=visible_question_ids)
            .order_by("question_id", "order")
        )
        choices_by_question_id = {}
        visible_choice_urns_by_dependency = {}
        dependency_urn_by_id = {
            question.id: question.urn for question in dependency_questions
        }
        for choice in visible_choices:
            if choice.question_id in question_ids:
                choices_by_question_id.setdefault(choice.question_id, []).append(choice)
            dependency_urn = dependency_urn_by_id.get(choice.question_id)
            if dependency_urn:
                visible_choice_urns_by_dependency.setdefault(dependency_urn, set()).add(
                    choice.urn
                )

        dependencies_by_question_id = {}
        for question in questions:
            dependency = question.depends_on
            if not dependency:
                dependencies_by_question_id[question.id] = dependency
                continue
            projected, is_safe = project_question_dependency(
                dependency,
                visible_question_urns=visible_dependency_urns,
                visible_choice_urns_by_question=(visible_choice_urns_by_dependency),
                choice_question_urns=choice_dependency_urns,
            )
            dependencies_by_question_id[question.id] = (
                projected if is_safe else dict(REDACTED_DEPENDENCY)
            )

        return cls(
            request=request,
            user_id=user_id,
            question_ids=question_ids,
            choices_by_question_id={
                key: tuple(rows) for key, rows in choices_by_question_id.items()
            },
            dependencies_by_question_id=dependencies_by_question_id,
        )

    def _covers(self, request, question) -> bool:
        user = getattr(request, "user", None)
        return (
            request is self.request
            and getattr(user, "is_authenticated", False)
            and getattr(user, "pk", None) == self.user_id
            and getattr(question, "id", None) in self.question_ids
        )

    def covers_question(self, request, question) -> bool:
        return self._covers(request, question)

    def choices_for(self, request, question):
        if not self._covers(request, question):
            return ()
        return self.choices_by_question_id.get(question.id, ())

    def dependency_for(self, request, question):
        if not self._covers(request, question):
            return dict(REDACTED_DEPENDENCY) if question.depends_on else None
        return self.dependencies_by_question_id.get(question.id)


def _translate_questions(questions):
    """Render the established questionnaire JSON from explicit authorized rows."""
    questions = tuple(questions)
    if not questions:
        return None
    current_lang = get_language()

    def translate_choice(choice):
        translation = (choice.translations or {}).get(current_lang, {})
        data = {
            "urn": choice.urn,
            "value": translation.get("value", choice.value or ""),
        }
        description = translation.get("description", choice.description)
        if description:
            data["description"] = description
        if choice.add_score is not None:
            data["add_score"] = choice.add_score
        if choice.compute_result is not None:
            resolved = resolve_compute_result(choice.compute_result)
            if resolved is not None:
                data["compute_result"] = resolved
        if choice.color:
            data["color"] = choice.color
        if choice.select_implementation_groups:
            data["select_implementation_groups"] = choice.select_implementation_groups
        if choice.annotation:
            data["annotation"] = choice.annotation
        return data

    result = {}
    for question in questions:
        translation = (question.translations or {}).get(current_lang, {})
        data = {
            "type": question.type,
            "text": translation.get("text", question.text or ""),
            "weight": question.weight,
        }
        if question.annotation:
            data["annotation"] = question.annotation
        if question.config is not None:
            data["config"] = question.config
        choices = [
            translate_choice(choice)
            for choice in question.questionnaire_visible_choices
        ]
        if choices:
            data["choices"] = choices
        if question.depends_on:
            data["depends_on"] = question.depends_on
        result[question.urn] = data
    return result or None


@dataclass(frozen=True)
class QuestionnaireVisibilityContext:
    """Authorized questionnaire rows bounded to one request and response scope."""

    request: Any = field(repr=False, compare=False)
    user_id: Any
    requirement_assessment_ids: frozenset
    requirement_node_ids: frozenset
    requirement_id_by_assessment_id: dict = field(repr=False, compare=False)
    questions_by_requirement_id: dict = field(repr=False, compare=False)
    answer_values_by_requirement_assessment_id: dict = field(repr=False, compare=False)
    answered_question_ids_by_requirement_assessment_id: dict = field(
        repr=False, compare=False
    )
    visible_question_urns: frozenset
    visible_choice_urns_by_question: dict = field(repr=False, compare=False)
    choice_question_urns: frozenset

    @classmethod
    def build(
        cls,
        *,
        request,
        requirement_assessments=(),
        requirement_nodes=(),
    ):
        requirement_assessments = tuple(requirement_assessments)
        requirement_nodes = tuple(requirement_nodes)
        ra_ids = frozenset(
            ra.id for ra in requirement_assessments if getattr(ra, "id", None)
        )
        requirement_id_by_assessment_id = {
            ra.id: ra.requirement_id
            for ra in requirement_assessments
            if getattr(ra, "id", None) and getattr(ra, "requirement_id", None)
        }
        requirement_ids = {
            ra.requirement_id
            for ra in requirement_assessments
            if getattr(ra, "requirement_id", None)
        }
        requirement_ids.update(
            node.id for node in requirement_nodes if getattr(node, "id", None)
        )
        requirement_ids = frozenset(requirement_ids)

        user = getattr(request, "user", None)
        user_id = getattr(user, "pk", None)
        if (
            user_id is None
            or not getattr(user, "is_authenticated", False)
            or not requirement_ids
        ):
            return cls(
                request=request,
                user_id=user_id,
                requirement_assessment_ids=ra_ids,
                requirement_node_ids=requirement_ids,
                requirement_id_by_assessment_id=requirement_id_by_assessment_id,
                questions_by_requirement_id={},
                answer_values_by_requirement_assessment_id={},
                answered_question_ids_by_requirement_assessment_id={},
                visible_question_urns=frozenset(),
                visible_choice_urns_by_question={},
                choice_question_urns=frozenset(),
            )

        visible_question_ids = RoleAssignment.get_viewable_object_ids(user, Question)
        visible_requirement_node_ids = RoleAssignment.get_viewable_object_ids(
            user, RequirementNode
        )
        visible_framework_ids = RoleAssignment.get_viewable_object_ids(user, Framework)
        visible_choice_ids = RoleAssignment.get_viewable_object_ids(
            user, QuestionChoice
        )
        visible_answer_ids = RoleAssignment.get_viewable_object_ids(user, Answer)

        authorized_requirement_ids = frozenset(
            RequirementNode.objects.filter(
                id__in=requirement_ids,
                framework_id__in=visible_framework_ids,
            )
            .filter(id__in=visible_requirement_node_ids)
            .values_list("id", flat=True)
        )
        valid_ra_pairs = dict(
            RequirementAssessment.objects.filter(
                id__in=ra_ids,
                requirement_id__in=authorized_requirement_ids,
                compliance_assessment__framework_id__in=visible_framework_ids,
                requirement__framework_id=F("compliance_assessment__framework_id"),
            ).values_list("id", "requirement_id")
        )
        ra_ids = frozenset(valid_ra_pairs)
        requirement_id_by_assessment_id = valid_ra_pairs
        requirement_ids = authorized_requirement_ids

        visible_choices = QuestionChoice.objects.filter(
            id__in=visible_choice_ids,
            question_id__in=visible_question_ids,
            question__requirement_node_id__in=requirement_ids,
            question__requirement_node__framework_id__in=visible_framework_ids,
        ).filter(question__requirement_node_id__in=visible_requirement_node_ids)
        questions = list(
            Question.objects.filter(
                requirement_node_id__in=requirement_ids,
                id__in=visible_question_ids,
                requirement_node__framework_id__in=visible_framework_ids,
            )
            .filter(requirement_node_id__in=visible_requirement_node_ids)
            .prefetch_related(
                Prefetch(
                    "choices",
                    queryset=visible_choices.all(),
                    to_attr="questionnaire_visible_choices",
                )
            )
            .order_by("requirement_node_id", "order")
        )
        visible_choice_urns_by_question = {
            question.urn: frozenset(
                choice.urn for choice in question.questionnaire_visible_choices
            )
            for question in questions
        }
        question_ids = {question.id for question in questions}
        answers = (
            list(
                Answer.objects.filter(
                    requirement_assessment_id__in=ra_ids,
                    question_id__in=question_ids,
                    id__in=visible_answer_ids,
                    question__requirement_node_id=F(
                        "requirement_assessment__requirement_id"
                    ),
                    requirement_assessment__requirement_id__in=requirement_ids,
                    requirement_assessment__requirement__framework_id=F(
                        "requirement_assessment__compliance_assessment__framework_id"
                    ),
                    requirement_assessment__compliance_assessment__framework_id__in=(
                        visible_framework_ids
                    ),
                )
                .select_related("question")
                .prefetch_related(
                    Prefetch(
                        "selected_choices",
                        queryset=visible_choices.filter(question_id__in=question_ids),
                        to_attr="questionnaire_visible_choices",
                    )
                )
            )
            if ra_ids and question_ids
            else []
        )
        answer_values_by_requirement_assessment_id = {}
        answered_question_ids_by_requirement_assessment_id = {}
        for answer in answers:
            choices = [
                choice
                for choice in answer.questionnaire_visible_choices
                if choice.question_id == answer.question_id
            ]
            if answer.question.type == Question.Type.UNIQUE_CHOICE:
                value = choices[0].urn if choices else None
                is_answered = bool(choices)
            elif answer.question.type == Question.Type.MULTIPLE_CHOICE:
                value = [choice.urn for choice in choices]
                is_answered = bool(choices)
            else:
                value = answer.value
                is_answered = value is not None and value != ""
            if answer.question.urn:
                answer_values_by_requirement_assessment_id.setdefault(
                    answer.requirement_assessment_id, {}
                )[answer.question.urn] = value
            if is_answered:
                answered_question_ids_by_requirement_assessment_id.setdefault(
                    answer.requirement_assessment_id, set()
                ).add(answer.question_id)

        questions_by_requirement_id = {}
        for question in questions:
            questions_by_requirement_id.setdefault(
                question.requirement_node_id, []
            ).append(question)
        return cls(
            request=request,
            user_id=user_id,
            requirement_assessment_ids=ra_ids,
            requirement_node_ids=requirement_ids,
            requirement_id_by_assessment_id=requirement_id_by_assessment_id,
            questions_by_requirement_id={
                key: tuple(rows) for key, rows in questions_by_requirement_id.items()
            },
            answer_values_by_requirement_assessment_id=(
                answer_values_by_requirement_assessment_id
            ),
            answered_question_ids_by_requirement_assessment_id={
                key: frozenset(question_ids)
                for key, question_ids in (
                    answered_question_ids_by_requirement_assessment_id.items()
                )
            },
            visible_question_urns=frozenset(question.urn for question in questions),
            visible_choice_urns_by_question=visible_choice_urns_by_question,
            choice_question_urns=frozenset(
                question.urn
                for question in questions
                if question.type
                in (Question.Type.UNIQUE_CHOICE, Question.Type.MULTIPLE_CHOICE)
            ),
        )

    def _matches_request(self, request) -> bool:
        user = getattr(request, "user", None)
        return (
            request is self.request
            and getattr(user, "is_authenticated", False)
            and getattr(user, "pk", None) == self.user_id
        )

    def covers_requirement_assessments(self, request, assessments) -> bool:
        return self._matches_request(request) and all(
            getattr(assessment, "id", None) in self.requirement_assessment_ids
            and self.requirement_id_by_assessment_id.get(assessment.id)
            == getattr(assessment, "requirement_id", None)
            for assessment in assessments
        )

    def questions_for(self, request, requirement):
        if (
            not self._matches_request(request)
            or getattr(requirement, "id", None) not in self.requirement_node_ids
        ):
            return ()
        return self.questions_by_requirement_id.get(requirement.id, ())

    def translated_questions_for(self, request, requirement):
        return _translate_questions(self.questions_for(request, requirement))

    def answer_values_for(self, request, requirement_assessment):
        if not self.covers_requirement_assessments(request, (requirement_assessment,)):
            return {}
        return self.answer_values_by_requirement_assessment_id.get(
            requirement_assessment.id, {}
        )

    def counts_for(self, request, requirement_assessment) -> tuple[int, int]:
        if not self.covers_requirement_assessments(request, (requirement_assessment,)):
            return 0, 0
        questions = self.questions_by_requirement_id.get(
            requirement_assessment.requirement_id, ()
        )
        answers_by_urn = self.answer_values_by_requirement_assessment_id.get(
            requirement_assessment.id, {}
        )
        answered_question_ids = (
            self.answered_question_ids_by_requirement_assessment_id.get(
                requirement_assessment.id, frozenset()
            )
        )
        questions_by_urn = {question.urn: question for question in questions}
        visible = answered = 0
        for question in questions:
            if not _is_question_visible(question, answers_by_urn, questions_by_urn):
                continue
            visible += 1
            answered += question.id in answered_question_ids
        return visible, answered
