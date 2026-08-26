import copy
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools.china_financial_grc import validate_artifacts as validator


class ArtifactValidationMutationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.foundation = Path(self.temporary_directory.name) / "foundation"
        shutil.copytree(validator.FOUNDATION_DIR, self.foundation)
        self.catalogs = self.foundation / "catalogs"
        self.example = self.foundation / "examples" / "regulatory-record.example.json"
        self.patchers = [
            mock.patch.object(
                validator,
                "SCHEMA_PATH",
                self.foundation / "schemas" / "regulatory-record.schema.json",
            ),
            mock.patch.object(
                validator,
                "FACT_SCHEMA_PATH",
                self.foundation / "schemas" / "applicability-fact.schema.json",
            ),
            mock.patch.object(
                validator,
                "PACK_INDEX_SCHEMA_PATH",
                self.foundation / "schemas" / "regulatory-pack-index.schema.json",
            ),
            mock.patch.object(validator, "CATALOGS_DIR", self.catalogs),
            mock.patch.object(
                validator,
                "CORE_CATALOG_PATH",
                self.catalogs / "regulatory-sources.json",
            ),
            mock.patch.object(
                validator,
                "FACT_CATALOG_PATH",
                self.catalogs / "applicability-facts.json",
            ),
            mock.patch.object(
                validator,
                "PACK_INDEX_PATH",
                self.catalogs / "regulatory-pack-index.json",
            ),
            mock.patch.object(validator, "EXAMPLE_PATH", self.example),
        ]
        for patcher in self.patchers:
            patcher.start()
        self.control_urns = validator.validate_ciso_libraries()
        self.applicability_facts = validator.validate_applicability_facts()

    def tearDown(self) -> None:
        for patcher in reversed(self.patchers):
            patcher.stop()
        self.temporary_directory.cleanup()

    @staticmethod
    def read_json(path: Path) -> dict:
        with path.open(encoding="utf-8") as stream:
            return json.load(stream)

    @staticmethod
    def write_json(path: Path, payload: dict) -> None:
        path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )

    def validate(self) -> tuple[int, int]:
        return validator.validate_regulatory_records(
            self.control_urns, self.applicability_facts
        )

    def complete_approval_record(self) -> dict:
        record = self.read_json(self.example)
        decided_at = "2026-08-20T00:00:00+08:00"
        checker = "example:human-checker"
        version = record["document_versions"][0]
        version["legal_review_status"] = "reviewed"
        version["legal_reviewed_by"] = checker
        version["legal_reviewed_at"] = decided_at
        record["obligations"][0]["review_status"] = "approved"
        record["applicability_rules"][0]["review_status"] = "approved"
        record["applicability_decisions"][0]["review_status"] = "confirmed"
        record["applicability_decisions"][0]["confirmed_by"] = checker
        record["applicability_decisions"][0]["confirmed_at"] = decided_at
        record["control_mappings"][0]["review_status"] = "approved"

        subjects = [
            ("document_version", version),
            ("provision", record["provisions"][0]),
            ("obligation", record["obligations"][0]),
            ("applicability_rule", record["applicability_rules"][0]),
            ("applicability_decision", record["applicability_decisions"][0]),
            ("control_mapping", record["control_mappings"][0]),
        ]
        record["decision_records"] = []
        for position, (subject_type, subject) in enumerate(subjects, start=1):
            record["decision_records"].append(
                {
                    "id": f"DEC-EXAMPLE-APPROVAL-{position:02d}",
                    "subject_type": subject_type,
                    "subject_id": subject["id"],
                    "decision": "approve",
                    "decided_at": decided_at,
                    "decided_by": checker,
                    "decided_by_kind": "human",
                    "role": "Example accountable reviewer",
                    "rationale": "Mutation fixture for a complete approval dependency chain.",
                    "conditions": [],
                    "expires_at": None,
                    "payload_sha256": validator.canonical_subject_digest(
                        record["schema_version"], subject_type, subject
                    ),
                    "payload_digest_profile": validator.PAYLOAD_DIGEST_PROFILE,
                }
            )
        return record

    @staticmethod
    def refresh_approval_digests(record: dict) -> None:
        subjects = {
            "document_version": {
                item["id"]: item for item in record["document_versions"]
            },
            "provision": {item["id"]: item for item in record["provisions"]},
            "obligation": {item["id"]: item for item in record["obligations"]},
            "applicability_rule": {
                item["id"]: item for item in record["applicability_rules"]
            },
            "applicability_decision": {
                item["id"]: item for item in record["applicability_decisions"]
            },
            "control_mapping": {
                item["id"]: item for item in record["control_mappings"]
            },
        }
        for decision in record["decision_records"]:
            subject_type = decision["subject_type"]
            subject = subjects[subject_type][decision["subject_id"]]
            decision["payload_sha256"] = validator.canonical_subject_digest(
                record["schema_version"], subject_type, subject
            )

    def test_repository_records_pass(self) -> None:
        validator.validate_regulatory_pack_index()
        self.assertEqual(self.validate(), (76, 76))

    def test_pack_digest_detects_an_unreviewed_catalog_change(self) -> None:
        banking_path = self.catalogs / "banking-regulatory-sources.json"
        record = self.read_json(banking_path)
        record["description"] += " changed"
        self.write_json(banking_path, record)
        with self.assertRaisesRegex(
            validator.ValidationFailure, "catalog digest mismatch"
        ):
            validator.validate_regulatory_pack_index()

    def test_pack_ids_are_bound_to_specific_catalogs(self) -> None:
        index = self.read_json(self.catalogs / "regulatory-pack-index.json")
        banking = next(pack for pack in index["packs"] if pack["id"] == "banking")
        insurance = next(pack for pack in index["packs"] if pack["id"] == "insurance")
        banking["catalog_file"], insurance["catalog_file"] = (
            insurance["catalog_file"],
            banking["catalog_file"],
        )
        self.write_json(self.catalogs / "regulatory-pack-index.json", index)
        with self.assertRaisesRegex(
            validator.ValidationFailure, "pack IDs are not bound"
        ):
            validator.validate_regulatory_pack_index()

    def test_unindexed_source_catalog_is_rejected(self) -> None:
        shutil.copyfile(
            self.catalogs / "banking-regulatory-sources.json",
            self.catalogs / "unreviewed-sources.json",
        )
        with self.assertRaisesRegex(
            validator.ValidationFailure, "actual source catalogs do not exactly match"
        ):
            validator.validate_regulatory_pack_index()

    def test_duplicate_json_key_is_rejected(self) -> None:
        duplicate = Path(self.temporary_directory.name) / "duplicate.json"
        duplicate.write_text('{"id": 1, "id": 2}\n', encoding="utf-8")
        with self.assertRaisesRegex(validator.ValidationFailure, "duplicate JSON key"):
            validator.load_json(duplicate)

    def test_non_json_number_is_rejected(self) -> None:
        invalid = Path(self.temporary_directory.name) / "nan.json"
        invalid.write_text('{"value": NaN}\n', encoding="utf-8")
        with self.assertRaisesRegex(
            validator.ValidationFailure, "non-JSON numeric constant"
        ):
            validator.load_json(invalid)

    def test_applicability_result_is_recomputed(self) -> None:
        record = self.read_json(self.example)
        decision = record["applicability_decisions"][0]
        decision["facts"][2] = {
            "fact": "technology.customer_rights_impact",
            "known": True,
            "value": False,
            "source_refs": ["example:customer-impact-review"],
            "observed_at": "2026-08-20T00:00:00+08:00",
        }
        decision["result"] = "applicable"
        self.write_json(self.example, record)
        with self.assertRaisesRegex(
            validator.ValidationFailure, "result must be not_applicable"
        ):
            self.validate()

    def test_three_value_short_circuit_is_deterministic(self) -> None:
        self.assertIs(validator.kleene_and([False, None]), False)
        self.assertIs(validator.kleene_or([True, None]), True)

    def test_condition_operand_type_is_enforced(self) -> None:
        record = self.read_json(self.example)
        record["applicability_rules"][0]["all"][0]["value"] = "true"
        self.write_json(self.example, record)
        with self.assertRaisesRegex(validator.ValidationFailure, "expected a boolean"):
            self.validate()

    def test_known_fact_without_evidence_is_rejected(self) -> None:
        record = self.read_json(self.example)
        record["applicability_decisions"][0]["facts"][0]["source_refs"] = []
        self.write_json(self.example, record)
        with self.assertRaisesRegex(validator.ValidationFailure, "Schema validation"):
            self.validate()

    def test_coverage_stage_requires_downstream_records(self) -> None:
        banking_path = self.catalogs / "banking-regulatory-sources.json"
        record = self.read_json(banking_path)
        record["documents"][0]["coverage_stage"] = "obligations_reviewed"
        self.write_json(banking_path, record)
        with self.assertRaisesRegex(
            validator.ValidationFailure, "needs reviewed downstream records"
        ):
            self.validate()

    def test_known_fact_whitespace_source_reference_is_rejected(self) -> None:
        record = self.read_json(self.example)
        record["applicability_decisions"][0]["facts"][0]["source_refs"] = [" \t "]
        self.write_json(self.example, record)
        with self.assertRaisesRegex(
            validator.ValidationFailure, "known fact .* needs evidence"
        ):
            self.validate()

    def test_obligation_interval_must_fit_every_source_version(self) -> None:
        record = self.read_json(self.example)
        record["obligations"][0]["valid_from"] = "2021-10-31"
        self.write_json(self.example, record)
        with self.assertRaisesRegex(
            validator.ValidationFailure, "obligation .* source version"
        ):
            self.validate()

    def test_rule_interval_must_fit_its_obligation(self) -> None:
        record = self.read_json(self.example)
        record["obligations"][0]["valid_to"] = "2026-09-01"
        record["applicability_rules"][0]["valid_to"] = "2026-09-02"
        self.write_json(self.example, record)
        with self.assertRaisesRegex(
            validator.ValidationFailure, "applicability rule .* obligation"
        ):
            self.validate()

    def test_applicability_decision_interval_must_fit_rule_and_obligation(self) -> None:
        record = self.read_json(self.example)
        record["obligations"][0]["valid_to"] = "2026-09-01"
        record["applicability_rules"][0]["valid_to"] = "2026-09-01"
        self.assertIsNone(record["applicability_decisions"][0]["valid_to"])
        self.write_json(self.example, record)
        with self.assertRaisesRegex(
            validator.ValidationFailure, "applicability decision .* rule"
        ):
            self.validate()

    def test_mapping_interval_must_fit_its_obligation(self) -> None:
        record = self.read_json(self.example)
        record["obligations"][0]["valid_to"] = "2026-09-01"
        record["applicability_rules"][0]["valid_to"] = "2026-09-01"
        record["applicability_decisions"][0]["valid_to"] = "2026-09-01"
        record["control_mappings"][0]["valid_to"] = "2026-09-02"
        self.write_json(self.example, record)
        with self.assertRaisesRegex(
            validator.ValidationFailure, "control mapping .* obligation"
        ):
            self.validate()

    def test_arbitrary_approval_digest_is_rejected(self) -> None:
        record = self.read_json(self.example)
        decision = record["decision_records"][0]
        decision["decision"] = "approve"
        decision["decided_by_kind"] = "human"
        decision["payload_digest_profile"] = validator.PAYLOAD_DIGEST_PROFILE
        decision["payload_sha256"] = "f" * 64
        self.write_json(self.example, record)
        with self.assertRaisesRegex(validator.ValidationFailure, "digest mismatch"):
            self.validate()

    def test_self_approval_is_rejected_after_valid_digest(self) -> None:
        record = self.read_json(self.example)
        subject = record["applicability_decisions"][0]
        decision = record["decision_records"][0]
        decision["decision"] = "approve"
        decision["decided_by"] = subject["provenance"]["created_by"]
        decision["decided_by_kind"] = "human"
        decision["payload_digest_profile"] = validator.PAYLOAD_DIGEST_PROFILE
        decision["payload_sha256"] = validator.canonical_subject_digest(
            record["schema_version"], "applicability_decision", subject
        )
        self.write_json(self.example, record)
        with self.assertRaisesRegex(
            validator.ValidationFailure, "maker-checker separation"
        ):
            self.validate()

    def test_binding_decision_text_fields_must_not_be_whitespace(self) -> None:
        for field in ("decided_by", "role", "rationale"):
            with self.subTest(field=field):
                record = self.complete_approval_record()
                record["decision_records"][0][field] = " \t "
                self.write_json(self.example, record)
                with self.assertRaisesRegex(
                    validator.ValidationFailure,
                    f"needs a non-empty {field}",
                ):
                    self.validate()

    def test_binding_decision_maker_identity_must_not_be_whitespace(self) -> None:
        record = self.complete_approval_record()
        record["document_versions"][0]["provenance"]["created_by"] = " \t "
        self.refresh_approval_digests(record)
        self.write_json(self.example, record)
        with self.assertRaisesRegex(
            validator.ValidationFailure, "needs a non-empty maker identity"
        ):
            self.validate()

    def test_approved_obligation_rejects_draft_and_unknown_sources(self) -> None:
        for status in ("draft", "unknown"):
            with self.subTest(status=status):
                record = self.complete_approval_record()
                record["document_versions"][0]["status"] = status
                self.refresh_approval_digests(record)
                self.write_json(self.example, record)
                with self.assertRaisesRegex(
                    validator.ValidationFailure, "draft or unknown source version"
                ):
                    self.validate()

    def test_approved_obligation_rejects_source_not_yet_effective(self) -> None:
        record = self.complete_approval_record()
        version = record["document_versions"][0]
        version["status"] = "published_future_effective"
        version["effective_date"] = "2026-08-21"
        version["valid_from"] = "2026-08-21"
        record["obligations"][0]["valid_from"] = "2026-08-21"
        record["applicability_rules"][0]["valid_from"] = "2026-08-21"
        record["applicability_decisions"][0]["valid_from"] = "2026-08-21"
        record["control_mappings"][0]["valid_from"] = "2026-08-21"
        self.refresh_approval_digests(record)
        self.write_json(self.example, record)
        with self.assertRaisesRegex(
            validator.ValidationFailure, "source version that is not yet effective"
        ):
            self.validate()

    def test_provision_approval_requires_prior_source_version_approval(self) -> None:
        record = self.complete_approval_record()
        version = record["document_versions"][0]
        version["legal_review_status"] = "unreviewed"
        version["legal_reviewed_by"] = None
        version["legal_reviewed_at"] = None
        record["decision_records"] = [
            decision
            for decision in record["decision_records"]
            if decision["subject_type"] != "document_version"
        ]
        self.write_json(self.example, record)
        with self.assertRaisesRegex(
            validator.ValidationFailure,
            "provision .* missing active prerequisite approval",
        ):
            self.validate()

    def test_terminal_review_state_requires_matching_disposition(self) -> None:
        baseline = self.read_json(self.example)
        cases = (
            ("obligations", "rejected", "reject"),
            ("obligations", "superseded", "revoke"),
            ("applicability_rules", "retired", "revoke"),
            ("applicability_decisions", "rejected", "reject"),
            ("applicability_decisions", "superseded", "revoke"),
            ("control_mappings", "rejected", "reject"),
            ("control_mappings", "retired", "revoke"),
        )
        for collection, status, disposition in cases:
            with self.subTest(collection=collection, status=status):
                record = copy.deepcopy(baseline)
                record[collection][0]["review_status"] = status
                self.write_json(self.example, record)
                with self.assertRaisesRegex(
                    validator.ValidationFailure,
                    f"requires latest {disposition} disposition",
                ):
                    self.validate()

    def test_complete_approval_chain_passes(self) -> None:
        record = self.complete_approval_record()
        self.write_json(self.example, record)
        self.assertEqual(self.validate(), (76, 76))


if __name__ == "__main__":
    unittest.main()
