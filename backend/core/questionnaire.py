"""Deterministic questionnaire answer validation shared by API write paths."""

import math
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import date
from typing import Any
from uuid import UUID


class QuestionnaireAnswerError(ValueError):
    """Raised when a raw questionnaire answer does not match its question."""


@dataclass(frozen=True, slots=True)
class NormalizedQuestionAnswer:
    """A validated answer in database and visibility-context forms."""

    value: Any
    choices: tuple[Any, ...]
    context_value: Any


def _question_value(question: Any, field_name: str) -> Any:
    """Read a visibility field from either a model object or legacy mapping."""

    if isinstance(question, Mapping):
        return question.get(field_name)
    return getattr(question, field_name, None)


def _is_dependency_scalar(value: Any) -> bool:
    """Return whether a dependency value has deterministic JSON scalar semantics."""

    return (
        value is None
        or isinstance(value, (str, int, bool))
        or (isinstance(value, float) and math.isfinite(value))
    )


def _dependency_spec(question: Any) -> tuple[str, str, list[Any]] | None | bool:
    """Return a valid dependency tuple, ``None`` for unconditional, else False."""

    depends_on = _question_value(question, "depends_on")
    if depends_on is None or depends_on == {}:
        return None
    if not isinstance(depends_on, dict):
        return False

    dependency_urn = depends_on.get("question")
    condition = depends_on.get("condition", "any")
    expected_answers = depends_on.get("answers")
    if (
        not isinstance(dependency_urn, str)
        or not dependency_urn
        or not isinstance(condition, str)
        or condition not in {"any", "all"}
        or not isinstance(expected_answers, list)
        or not expected_answers
        or any(not _is_dependency_scalar(value) for value in expected_answers)
    ):
        return False
    return dependency_urn, condition, expected_answers


def _choice_urns(question: Any) -> set[str] | None:
    """Return the exact projected choice URNs, or ``None`` when unavailable."""

    if isinstance(question, Mapping):
        choices = question.get("choices")
        if not isinstance(choices, list):
            return None
    else:
        manager = getattr(question, "choices", None)
        if manager is None:
            return None
        choices = manager.all()

    urns: set[str] = set()
    for choice in choices:
        urn = (
            choice.get("urn")
            if isinstance(choice, Mapping)
            else getattr(choice, "urn", None)
        )
        if isinstance(urn, str) and urn:
            urns.add(urn)
    return urns


def _expected_answers_match_parent(parent_question: Any, values: list[Any]) -> bool:
    """Validate dependency literals against the projected parent type."""

    question_type = _question_value(parent_question, "type")
    if question_type in {"unique_choice", "multiple_choice"}:
        allowed_urns = _choice_urns(parent_question)
        return allowed_urns is not None and all(
            isinstance(value, str) and value in allowed_urns for value in values
        )
    if question_type == "text":
        return all(isinstance(value, str) for value in values)
    if question_type == "number":
        return all(
            not isinstance(value, bool)
            and isinstance(value, (int, float))
            and (not isinstance(value, float) or math.isfinite(value))
            for value in values
        )
    if question_type == "boolean":
        return all(isinstance(value, bool) for value in values)
    if question_type == "date":
        for value in values:
            if not isinstance(value, str):
                return False
            try:
                parsed = date.fromisoformat(value)
            except ValueError:
                return False
            if parsed.isoformat() != value:
                return False
        return True
    return False


def _dependency_values_equal(actual: Any, expected: Any) -> bool:
    """Compare JSON scalar values without Python's ``True == 1`` coercion."""

    if isinstance(actual, bool) or isinstance(expected, bool):
        return (
            isinstance(actual, bool)
            and isinstance(expected, bool)
            and actual == expected
        )
    if isinstance(actual, (int, float)) and isinstance(expected, (int, float)):
        return actual == expected
    return type(actual) is type(expected) and actual == expected


def is_question_dependency_valid_strict(
    question: Any,
    questions_by_urn: Mapping[str, Any] | None,
    visited: frozenset[str] | None = None,
) -> bool:
    """Validate one bounded, acyclic conditional-question declaration."""

    spec = _dependency_spec(question)
    if spec is None:
        return True
    if spec is False or questions_by_urn is None:
        return False

    question_urn = _question_value(question, "urn")
    if not isinstance(question_urn, str) or not question_urn:
        return False
    visited = visited or frozenset()
    if question_urn in visited:
        return False

    dependency_urn, _condition, expected_answers = spec
    parent_question = questions_by_urn.get(dependency_urn)
    if parent_question is None:
        return False
    if not _expected_answers_match_parent(parent_question, expected_answers):
        return False
    return is_question_dependency_valid_strict(
        parent_question,
        questions_by_urn,
        visited | {question_urn},
    )


def is_question_visible_strict(
    question: Any,
    answers_by_urn: Mapping[str, Any],
    questions_by_urn: Mapping[str, Any] | None,
    visited: frozenset[str] | None = None,
) -> bool:
    """Resolve conditional visibility with one fail-closed implementation.

    ``None`` and an empty object mean an unconditional question.  Every other
    declaration must name an in-scope parent, use ``any`` or ``all``, provide a
    non-empty list of scalar expected answers, and form an acyclic dependency
    graph.  Malformed or incomplete declarations are hidden instead of being
    interpreted permissively or raising a runtime ``TypeError``.
    """

    spec = _dependency_spec(question)
    if spec is None:
        return True
    if spec is False:
        return False
    dependency_urn, condition, expected_answers = spec

    question_urn = _question_value(question, "urn")
    if not isinstance(question_urn, str) or not question_urn:
        return False
    visited = visited or frozenset()
    if question_urn in visited:
        return False

    if not is_question_dependency_valid_strict(
        question,
        questions_by_urn,
        visited,
    ):
        return False
    assert questions_by_urn is not None
    parent_question = questions_by_urn.get(dependency_urn)
    assert parent_question is not None
    if not is_question_visible_strict(
        parent_question,
        answers_by_urn,
        questions_by_urn,
        visited | {question_urn},
    ):
        return False

    if dependency_urn not in answers_by_urn:
        return False
    target_answer = answers_by_urn[dependency_urn]
    if target_answer is None or target_answer == "":
        return False
    if isinstance(target_answer, list):
        if not target_answer or any(
            not _is_dependency_scalar(value) for value in target_answer
        ):
            return False
        if condition == "any":
            return any(
                _dependency_values_equal(value, expected)
                for value in target_answer
                for expected in expected_answers
            )
        return all(
            any(_dependency_values_equal(value, expected) for value in target_answer)
            for expected in expected_answers
        )
    if not _is_dependency_scalar(target_answer):
        return False
    if condition == "any":
        return any(
            _dependency_values_equal(target_answer, expected)
            for expected in expected_answers
        )
    return len(expected_answers) == 1 and _dependency_values_equal(
        target_answer, expected_answers[0]
    )


def normalize_question_answer(
    question,
    raw_value: Any,
    *,
    allowed_choice_ids: Iterable[UUID],
) -> NormalizedQuestionAnswer:
    """Validate and normalize one legacy JSON answer value.

    Choice answers use choice URNs on the wire.  The returned ``choices`` are
    exact model objects ready for an M2M update; non-choice answers use
    ``value``.  No caller-supplied identifier is accepted outside the supplied
    capability set.
    """

    from core.models import Question

    allowed_choice_ids = set(allowed_choice_ids)
    choices_by_urn = {}
    if question.type in {
        Question.Type.UNIQUE_CHOICE,
        Question.Type.MULTIPLE_CHOICE,
    }:
        choices = [
            choice
            for choice in question.choices.all()
            if choice.id in allowed_choice_ids
        ]
        choices_by_urn = {choice.urn: choice for choice in choices if choice.urn}

    if question.type == Question.Type.UNIQUE_CHOICE:
        if raw_value in (None, ""):
            return NormalizedQuestionAnswer(None, (), None)
        if not isinstance(raw_value, str):
            raise QuestionnaireAnswerError(
                "Single-choice answers must be a choice URN string."
            )
        choice = choices_by_urn.get(raw_value)
        if choice is None:
            raise QuestionnaireAnswerError(
                "The selected choice is unavailable for this question."
            )
        return NormalizedQuestionAnswer(None, (choice,), choice.urn)

    if question.type == Question.Type.MULTIPLE_CHOICE:
        if raw_value is None:
            raw_value = []
        if not isinstance(raw_value, list) or any(
            not isinstance(item, str) for item in raw_value
        ):
            raise QuestionnaireAnswerError(
                "Multiple-choice answers must be a list of choice URN strings."
            )
        requested = set(raw_value)
        if len(requested) != len(raw_value):
            raise QuestionnaireAnswerError(
                "Multiple-choice answers cannot contain duplicate choices."
            )
        missing = requested - set(choices_by_urn)
        if missing:
            raise QuestionnaireAnswerError(
                "One or more selected choices are unavailable for this question."
            )
        selected = tuple(choices_by_urn[item] for item in raw_value)
        return NormalizedQuestionAnswer(
            None,
            selected,
            [choice.urn for choice in selected],
        )

    if question.type == Question.Type.TEXT:
        if raw_value is not None and not isinstance(raw_value, str):
            raise QuestionnaireAnswerError("Text answers must be a string.")
    elif question.type == Question.Type.NUMBER:
        if raw_value is not None and (
            isinstance(raw_value, bool)
            or not isinstance(raw_value, (int, float))
            or (isinstance(raw_value, float) and not math.isfinite(raw_value))
        ):
            raise QuestionnaireAnswerError(
                "Number answers must be a finite numeric value."
            )
    elif question.type == Question.Type.BOOLEAN:
        if raw_value is not None and not isinstance(raw_value, bool):
            raise QuestionnaireAnswerError("Boolean answers must be true or false.")
    elif question.type == Question.Type.DATE and raw_value is not None:
        if not isinstance(raw_value, str):
            raise QuestionnaireAnswerError(
                "Date answers must be a string in YYYY-MM-DD format."
            )
        try:
            parsed = date.fromisoformat(raw_value)
        except ValueError as exc:
            raise QuestionnaireAnswerError(
                "Date answers must be in YYYY-MM-DD format."
            ) from exc
        if parsed.isoformat() != raw_value:
            raise QuestionnaireAnswerError("Date answers must be in YYYY-MM-DD format.")
    elif question.type not in set(Question.Type.values):
        raise QuestionnaireAnswerError("The question type is unsupported.")

    return NormalizedQuestionAnswer(raw_value, (), raw_value)
