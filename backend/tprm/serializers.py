import structlog
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.db import IntegrityError, transaction
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers
from rest_framework.exceptions import PermissionDenied

from core.assignment_access import (
    ComplianceAssessmentRelocationError,
    relocate_compliance_assessment_tree,
)
from core.models import (
    Actor,
    ComplianceAssessment,
    Evidence,
    Framework,
    Perimeter,
    RequirementAssessment,
    RequirementAssignment,
    ValidationFlow,
)
from core.relation_locking import lock_rows_in_global_model_order
from core.reserved_iam import (
    MANAGED_TPRM_RESPONDENT_IAM_ERROR,
    ManagedTprmRespondentIamError,
    lock_and_assert_no_tprm_idp_group_inheritance,
)
from core.serializer_fields import FieldsRelatedField, HashSlugRelatedField
from core.serializers import BaseModelSerializer
from core.utils import (
    RoleCodename,
    UserGroupCodename,
    has_full_view_compliance_assessment,
    is_field_editable_by,
)
from iam.models import Folder, Role, RoleAssignment, UserGroup
from pmbok.models import GenericCollection
from tprm.models import (
    Contract,
    Entity,
    EntityAssessment,
    Representative,
    Solution,
    SolutionSubcontractor,
)

logger = structlog.get_logger(__name__)


# Sentinel used to distinguish "client omitted this field" from "client sent an
# empty array" in nested chain writes. Must be a unique object — not None, [],
# or any value a client could legitimately send.
_CHAIN_UNSET = object()

User = get_user_model()


class EntityReadSerializer(BaseModelSerializer):
    folder = FieldsRelatedField()
    owned_folders = FieldsRelatedField(many=True)
    parent_entity = FieldsRelatedField()
    branches = FieldsRelatedField(many=True)
    relationship = FieldsRelatedField(many=True)
    contracts = FieldsRelatedField(many=True)
    legal_identifiers = serializers.SerializerMethodField()
    default_criticality = serializers.ReadOnlyField()
    filtering_labels = FieldsRelatedField(many=True)
    subcontracts_count = serializers.SerializerMethodField()
    subcontracts_usage = serializers.SerializerMethodField()

    def get_legal_identifiers(self, obj):
        """Format legal identifiers as a readable string for display"""
        if not obj.legal_identifiers:
            return ""
        return "\n".join(
            [f"{key}: {value}" for key, value in obj.legal_identifiers.items()]
        )

    def get_subcontracts_count(self, obj):
        """Number of solutions where this entity is declared as a subcontractor.

        Powers the Entity detail view's "Used as subcontractor in N solutions"
        panel and the disabled-delete-button tooltip. Skipped on the list
        endpoint to avoid one COUNT per row (N+1); computed everywhere else
        (detail, direct serializer use, exports, tests).
        """
        if self.context.get("action") == "list":
            return 0
        return obj.subcontracts.count()

    def get_subcontracts_usage(self, obj):
        """Up to 50 solutions blocking deletion, with parent contract.

        Skipped on the list endpoint to avoid a per-row N+1; computed
        everywhere else.
        """
        if self.context.get("action") == "list":
            return []
        rows = obj.subcontracts.select_related("solution").order_by("solution__name")[
            :50
        ]
        return [
            {
                "id": str(row.id),
                "solution_id": str(row.solution_id),
                "solution_name": row.solution.name,
            }
            for row in rows
        ]

    class Meta:
        model = Entity
        exclude = []


class EntityWriteSerializer(BaseModelSerializer):
    # The default "Main" entity is created built-in (so it can't be deleted) but
    # is user-owned and fully editable — e.g. renamed to the org's name.
    BUILTIN_EDITABLE_FIELDS = "__all__"

    class Meta:
        model = Entity
        exclude = ["owned_folders"]

    def to_internal_value(self, data):
        """Convert None to empty string for CharField DORA fields before validation"""
        dora_char_fields = [
            "country",
            "currency",
            "dora_entity_type",
            "dora_entity_hierarchy",
            "dora_provider_person_type",
        ]
        for field in dora_char_fields:
            if field in data and data[field] is None:
                data[field] = ""
        return super().to_internal_value(data)

    def validate_legal_identifiers(self, value):
        """
        Validate legal identifiers, ensuring LEI is exactly 20 characters if provided.
        """
        if value and isinstance(value, dict):
            lei = value.get("LEI", "")
            # Strip whitespace and check if LEI exists
            if lei:
                lei_stripped = lei.strip()
                if lei_stripped and len(lei_stripped) != 20:
                    raise serializers.ValidationError(_("leiLengthError"))
        return value

    def validate_parent_entity(self, value):
        """
        Validate that an entity cannot be set as its own parent.
        """
        if value and self.instance and value.id == self.instance.id:
            raise serializers.ValidationError(
                _("An entity cannot be set as its own parent")
            )
        return value


class EntityImportExportSerializer(BaseModelSerializer):
    folder = HashSlugRelatedField(slug_field="pk", read_only=True)
    owned_folders = HashSlugRelatedField(slug_field="pk", many=True, read_only=True)
    parent_entity = HashSlugRelatedField(slug_field="pk", read_only=True)
    relationship = serializers.SlugRelatedField(
        slug_field="name", read_only=True, many=True
    )

    class Meta:
        model = Entity
        fields = [
            "ref_id",
            "name",
            "description",
            "folder",
            "is_active",
            "mission",
            "reference_link",
            "owned_folders",
            "parent_entity",
            "default_dependency",
            "default_penetration",
            "default_maturity",
            "default_trust",
            "legal_identifiers",
            "country",
            "currency",
            "dora_entity_type",
            "dora_entity_hierarchy",
            "dora_assets_value",
            "dora_competent_authority",
            "dora_provider_person_type",
            "created_at",
            "updated_at",
            "relationship",
        ]


class EntityAssessmentImportExportSerializer(BaseModelSerializer):
    folder = HashSlugRelatedField(slug_field="pk", read_only=True)
    perimeter = HashSlugRelatedField(slug_field="pk", read_only=True)
    entity = HashSlugRelatedField(slug_field="pk", read_only=True)
    compliance_assessment = HashSlugRelatedField(slug_field="pk", read_only=True)
    evidence = HashSlugRelatedField(slug_field="pk", read_only=True)
    solutions = HashSlugRelatedField(slug_field="pk", many=True, read_only=True)

    class Meta:
        model = EntityAssessment
        # authors / reviewers / representatives are User/Actor relations that
        # are not part of a domain export, so they are intentionally omitted.
        fields = [
            "name",
            "description",
            "folder",
            "perimeter",
            "version",
            "status",
            "observation",
            "eta",
            "due_date",
            "criticality",
            "penetration",
            "dependency",
            "maturity",
            "trust",
            "conclusion",
            "reference_link",
            "entity",
            "compliance_assessment",
            "evidence",
            "solutions",
            "created_at",
            "updated_at",
        ]


class RepresentativeImportExportSerializer(BaseModelSerializer):
    entity = HashSlugRelatedField(slug_field="pk", read_only=True)
    email = serializers.EmailField(validators=[], required=False, allow_blank=True)

    class Meta:
        model = Representative
        # user (FK to iam.User) is intentionally omitted: users are not exported.
        fields = [
            "ref_id",
            "entity",
            "email",
            "first_name",
            "last_name",
            "phone",
            "role",
            "description",
            "created_at",
            "updated_at",
        ]


class SolutionImportExportSerializer(BaseModelSerializer):
    provider_entity = HashSlugRelatedField(slug_field="pk", read_only=True)
    recipient_entity = HashSlugRelatedField(slug_field="pk", read_only=True)
    assets = HashSlugRelatedField(slug_field="pk", many=True, read_only=True)

    class Meta:
        model = Solution
        # owner (M2M to core.Actor) is intentionally omitted.
        fields = [
            "ref_id",
            "name",
            "description",
            "provider_entity",
            "recipient_entity",
            "is_active",
            "reference_link",
            "criticality",
            "assets",
            "dora_ict_service_type",
            "storage_of_data",
            "data_location_storage",
            "data_location_processing",
            "dora_data_sensitiveness",
            "dora_reliance_level",
            "dora_substitutability",
            "dora_non_substitutability_reason",
            "dora_has_exit_plan",
            "dora_reintegration_possibility",
            "dora_discontinuing_impact",
            "dora_alternative_providers_identified",
            "dora_alternative_providers",
            "created_at",
            "updated_at",
        ]


class SolutionSubcontractorImportExportSerializer(BaseModelSerializer):
    solution = HashSlugRelatedField(slug_field="pk", read_only=True)
    subcontractor = HashSlugRelatedField(slug_field="pk", read_only=True)
    recipient = HashSlugRelatedField(slug_field="pk", read_only=True)

    class Meta:
        model = SolutionSubcontractor
        fields = [
            "solution",
            "subcontractor",
            "recipient",
            "created_at",
            "updated_at",
        ]


class ContractImportExportSerializer(BaseModelSerializer):
    folder = HashSlugRelatedField(slug_field="pk", read_only=True)
    provider_entity = HashSlugRelatedField(slug_field="pk", read_only=True)
    beneficiary_entity = HashSlugRelatedField(slug_field="pk", read_only=True)
    overarching_contract = HashSlugRelatedField(slug_field="pk", read_only=True)
    evidences = HashSlugRelatedField(slug_field="pk", many=True, read_only=True)
    solutions = HashSlugRelatedField(slug_field="pk", many=True, read_only=True)

    class Meta:
        model = Contract
        # owner (M2M to core.Actor) is intentionally omitted.
        fields = [
            "ref_id",
            "name",
            "description",
            "folder",
            "provider_entity",
            "beneficiary_entity",
            "overarching_contract",
            "evidences",
            "solutions",
            "status",
            "start_date",
            "end_date",
            "dora_contractual_arrangement",
            "currency",
            "annual_expense",
            "termination_reason",
            "is_intragroup",
            "dora_exclude",
            "governing_law_country",
            "notice_period_entity",
            "notice_period_provider",
            "created_at",
            "updated_at",
        ]


class EntityAssessmentCollectionProjectionMixin:
    """Read-only, IAM-filtered reverse GenericCollection projection."""

    def get_genericcollection(self, obj):
        request = self.context.get("request")
        user = getattr(request, "user", None)
        if user is None or not getattr(user, "is_authenticated", False):
            return []
        try:
            visible_ids = set(
                RoleAssignment.get_viewable_object_ids(user, GenericCollection)
            )
        except (NotImplementedError, Permission.DoesNotExist):
            return []
        return list(
            obj.genericcollection_set.filter(id__in=visible_ids)
            .order_by("id")
            .values_list("id", flat=True)
        )


class EntityAssessmentReadSerializer(
    EntityAssessmentCollectionProjectionMixin, BaseModelSerializer
):
    genericcollection = serializers.SerializerMethodField()
    compliance_assessment = FieldsRelatedField(fields=["id", "name"])
    evidence = FieldsRelatedField()
    perimeter = FieldsRelatedField()
    entity = FieldsRelatedField()
    folder = FieldsRelatedField()
    solutions = FieldsRelatedField(many=True)
    representatives = FieldsRelatedField(many=True)
    authors = FieldsRelatedField(many=True)
    reviewers = FieldsRelatedField(many=True)
    validation_flows = serializers.SerializerMethodField()

    def get_validation_flows(self, obj):
        request = self.context.get("request")
        user = getattr(request, "user", None)
        if user is None or not getattr(user, "is_authenticated", False):
            return []
        try:
            visible_flow_ids = set(
                RoleAssignment.get_viewable_object_ids(user, ValidationFlow)
            )
            visible_user_ids = set(RoleAssignment.get_viewable_object_ids(user, User))
        except (NotImplementedError, Permission.DoesNotExist):
            return []
        rows = []
        for flow in (
            obj.validationflow_set.filter(id__in=visible_flow_ids)
            .select_related("approver")
            .order_by("id")
        ):
            row = {
                "id": flow.id,
                "ref_id": flow.ref_id,
                "status": flow.status,
            }
            # Hidden and absent approvers deliberately have the same wire
            # representation.  Omitting the key only for a hidden identity
            # exposes one bit of otherwise protected relationship state.
            row["approver"] = None
            if flow.approver_id in visible_user_ids:
                row["approver"] = {
                    "id": flow.approver.id,
                    "email": flow.approver.email,
                    "first_name": flow.approver.first_name,
                    "last_name": flow.approver.last_name,
                }
            rows.append(row)
        return rows

    class Meta:
        model = EntityAssessment
        exclude = ["penetration", "dependency", "maturity", "trust"]


class EntityAssessmentWriteSerializer(
    EntityAssessmentCollectionProjectionMixin, BaseModelSerializer
):
    genericcollection = serializers.SerializerMethodField()
    # The model FK is deliberately not a general write surface. Creating or
    # relocating an audit must pass through the governed create_audit/link_audit
    # flows below so their locks, full-view checks, and target-folder IAM run.
    compliance_assessment = serializers.PrimaryKeyRelatedField(read_only=True)
    create_audit = serializers.BooleanField(default=False)
    framework = serializers.PrimaryKeyRelatedField(
        queryset=Framework.objects.all(), required=False
    )
    selected_implementation_groups = serializers.ListField(
        child=serializers.CharField(), required=False
    )
    link_audit = serializers.PrimaryKeyRelatedField(
        queryset=ComplianceAssessment.objects.all(), required=False, allow_null=True
    )

    def _extract_audit_data(self, validated_data):
        audit_data = {
            "create_audit": validated_data.pop("create_audit", False),
            "framework": validated_data.pop("framework", None),
            "selected_implementation_groups": validated_data.pop(
                "selected_implementation_groups", None
            ),
            "link_audit": validated_data.pop("link_audit", None),
        }
        return audit_data

    def _lock_instance_without_audit(self, instance, field_name):
        locked = EntityAssessment.objects.select_for_update().get(pk=instance.pk)
        if getattr(locked, "compliance_assessment_id", None):
            raise serializers.ValidationError(
                {field_name: [_("An audit already exists for this assessment")]}
            )
        return locked

    @staticmethod
    def _assert_audit_owner_coherence(
        entity_assessment,
        audit,
        *,
        require_link=True,
    ):
        """Reject legacy or concurrent audit ownership outside one enclave."""

        folder = getattr(audit, "folder", None)
        if (
            folder is None
            or folder.content_type != Folder.ContentType.ENCLAVE
            or folder.parent_folder_id != entity_assessment.folder_id
        ):
            raise PermissionDenied("The linked audit owner is inconsistent.")
        audit_rows = ComplianceAssessment.objects.filter(folder_id=folder.id).order_by(
            "id"
        )
        linked_rows = EntityAssessment.objects.filter(
            compliance_assessment_id=audit.id
        ).order_by("id")
        if transaction.get_connection().in_atomic_block:
            audit_rows = audit_rows.select_for_update(of=("self",))
            linked_rows = linked_rows.select_for_update(of=("self",))
        if set(audit_rows.values_list("id", flat=True)) != {audit.id}:
            raise PermissionDenied("The audit enclave is not exclusive.")
        linked_ids = set(linked_rows.values_list("id", flat=True))
        expected_linked_ids = {entity_assessment.id} if require_link else set()
        if require_link and linked_ids != expected_linked_ids:
            raise PermissionDenied("The audit is linked to another entity assessment.")
        if not require_link and linked_ids - {entity_assessment.id}:
            raise PermissionDenied("The audit is linked to another entity assessment.")
        if require_link and entity_assessment.compliance_assessment_id != audit.id:
            raise PermissionDenied("The linked audit owner is inconsistent.")

    def _lock_existing_audit_tree_authority(
        self,
        audit,
        *,
        fields,
        assignment_sync_required=False,
        assignment_create_required=False,
    ):
        """Lock and authorize an existing audit before identity/owner changes."""

        request = self.context.get("request")
        if request is None:
            raise PermissionDenied("Complete audit data is unavailable.")
        if audit.folder_id is None:
            raise PermissionDenied("The audit owner is unavailable.")
        audit.folder = Folder.objects.select_for_update().get(id=audit.folder_id)
        if not has_full_view_compliance_assessment(request.user, audit):
            raise PermissionDenied("Complete audit data is unavailable.")
        if audit.is_locked or audit.status == ComplianceAssessment.Status.IN_REVIEW:
            raise PermissionDenied("The audit is not editable.")
        if not all(
            is_field_editable_by(audit, field_name, "auditor") for field_name in fields
        ):
            raise PermissionDenied("The audit is not editable.")
        self._check_object_perm(audit, "change", model=ComplianceAssessment)

        assignments = list(
            RequirementAssignment.objects.select_for_update(of=("self",))
            .filter(compliance_assessment_id=audit.id)
            .order_by("id")
        )
        if len(assignments) > 1 or any(
            assignment.folder_id != audit.folder_id for assignment in assignments
        ):
            raise PermissionDenied("The audit assignment owner is inconsistent.")
        if assignment_sync_required and assignments:
            assignment = assignments[0]
            if assignment.status not in {
                RequirementAssignment.Status.DRAFT,
                RequirementAssignment.Status.IN_PROGRESS,
            }:
                raise PermissionDenied("The audit assignment is not editable.")
            if assignment.id not in set(
                RoleAssignment.get_viewable_object_ids(
                    request.user, RequirementAssignment
                )
            ):
                raise PermissionDenied("The audit assignment is unavailable.")
            self._check_object_perm(assignment, "change", model=RequirementAssignment)
        elif assignment_create_required:
            self._check_object_perm(
                {},
                "add",
                folder=audit.folder,
                model=RequirementAssignment,
            )

        requirement_assessments = list(
            RequirementAssessment.objects.select_for_update(of=("self",))
            .filter(compliance_assessment_id=audit.id)
            .order_by("id")
        )
        if any(
            requirement_assessment.folder_id != audit.folder_id
            for requirement_assessment in requirement_assessments
        ):
            raise PermissionDenied(
                "A requirement assessment has an inconsistent audit folder."
            )
        audit_requirement_assessment_ids = {
            requirement_assessment.id
            for requirement_assessment in requirement_assessments
        }
        for assignment in assignments:
            assigned_ids = set(
                assignment.requirement_assessments.values_list("id", flat=True)
            )
            if not assigned_ids.issubset(audit_requirement_assessment_ids):
                raise PermissionDenied("The audit assignment scope is inconsistent.")

        from core.views import ComplianceAssessmentViewSet

        ComplianceAssessmentViewSet._assert_complete_assessment_read_access(
            request.user, audit
        )
        return assignments, requirement_assessments

    @staticmethod
    def _m2m_snapshot(instance, field_name):
        field = instance._meta.get_field(field_name)
        source_name = field.m2m_field_name()
        target_name = field.m2m_reverse_field_name()
        through = field.remote_field.through
        row_filter = {f"{source_name}_id": instance.id}
        ids = set(
            through.objects.filter(**row_filter).values_list(
                f"{target_name}_id", flat=True
            )
        )
        return through, row_filter, target_name, ids

    def _lock_existing_audit_identity_rows(
        self,
        *,
        audit,
        entity_assessment,
        assignments,
        validated_data,
        identity_fields,
    ):
        """Lock every identity carrier and reject partial hidden rewrites."""

        request = self.context.get("request")
        identity_fields = set(identity_fields)
        requested_reviewers = (
            list(validated_data.get("reviewers", entity_assessment.reviewers.all()))
            if "reviewers" in identity_fields
            else []
        )
        requested_representatives = (
            list(
                validated_data.get(
                    "representatives", entity_assessment.representatives.all()
                )
            )
            if "representatives" in identity_fields
            else []
        )
        snapshots = []
        if "reviewers" in identity_fields:
            owners = [entity_assessment]
            if audit is not None:
                owners.append(audit)
            for owner in owners:
                snapshots.append(
                    (owner, "reviewers", self._m2m_snapshot(owner, "reviewers"))
                )
        if "representatives" in identity_fields:
            snapshots.append(
                (
                    entity_assessment,
                    "representatives",
                    self._m2m_snapshot(entity_assessment, "representatives"),
                )
            )
            if audit is not None:
                snapshots.append(
                    (audit, "authors", self._m2m_snapshot(audit, "authors"))
                )
                for assignment in assignments:
                    snapshots.append(
                        (
                            assignment,
                            "actor",
                            self._m2m_snapshot(assignment, "actor"),
                        )
                    )
                    snapshots.append(
                        (
                            assignment,
                            "requirement_assessments",
                            self._m2m_snapshot(assignment, "requirement_assessments"),
                        )
                    )

        user_ids = {user.id for user in requested_representatives}
        actor_ids = {actor.id for actor in requested_reviewers}
        for _owner, field_name, (_through, _row_filter, _target_name, ids) in snapshots:
            if field_name == "representatives":
                user_ids.update(ids)
            elif field_name != "requirement_assessments":
                actor_ids.update(ids)
        representative_actor_ids = set(
            Actor.objects.filter(user_id__in=user_ids).values_list("id", flat=True)
        )
        actor_ids.update(representative_actor_ids)
        lock_rows_in_global_model_order({User: user_ids, Actor: actor_ids})

        for _owner, _field_name, (
            through,
            row_filter,
            target_name,
            expected,
        ) in snapshots:
            list(
                through.objects.select_for_update().filter(**row_filter).order_by("pk")
            )
            current = set(
                through.objects.filter(**row_filter).values_list(
                    f"{target_name}_id", flat=True
                )
            )
            if current != expected:
                raise PermissionDenied(
                    "Audit identity links changed concurrently; retry."
                )

        if request is None:
            raise PermissionDenied("Audit identity authority is unavailable.")
        visible_user_ids = set(
            RoleAssignment.get_viewable_object_ids(request.user, User)
        )
        visible_actor_ids = set(
            RoleAssignment.get_viewable_object_ids(request.user, Actor)
        )
        if user_ids - visible_user_ids or actor_ids - visible_actor_ids:
            raise PermissionDenied("One or more audit identities are unavailable.")

    def _lock_existing_audit_relation_owners(self, audit):
        """Freeze reverse owners before relocating an existing audit.

        Moving a ComplianceAssessment changes the governing folder observed by
        every collection/workflow that links it, even though Django only writes
        the assessment row.  Treat those reverse links as authority-bearing:
        GenericCollection may consent through independent view + change IAM;
        ValidationFlow must be explicitly unlinked by its governed workflow.
        """

        request = self.context.get("request")
        if request is None or not getattr(request.user, "is_authenticated", False):
            raise PermissionDenied("Audit relationship authority is unavailable.")

        snapshots = []
        owner_ids_by_model = {}
        for owner_model, field_name in (
            (GenericCollection, "compliance_assessments"),
            (ValidationFlow, "compliance_assessments"),
        ):
            field = owner_model._meta.get_field(field_name)
            through = field.remote_field.through
            source_name = field.m2m_field_name()
            target_name = field.m2m_reverse_field_name()
            row_filter = {f"{target_name}_id": audit.id}
            owner_ids = set(
                through.objects.filter(**row_filter).values_list(
                    f"{source_name}_id", flat=True
                )
            )
            snapshots.append((through, row_filter, source_name, owner_model, owner_ids))
            owner_ids_by_model[owner_model] = owner_ids

        folder_snapshots = {}
        folder_ids = set()
        for owner_model, owner_ids in owner_ids_by_model.items():
            folder_by_owner = dict(
                owner_model.objects.filter(id__in=owner_ids).values_list(
                    "id", "folder_id"
                )
            )
            if set(folder_by_owner) != owner_ids or any(
                folder_id is None for folder_id in folder_by_owner.values()
            ):
                raise PermissionDenied("An audit relationship owner is unavailable.")
            folder_snapshots[owner_model] = folder_by_owner
            folder_ids.update(folder_by_owner.values())

        locked_folders = {
            folder.id: folder
            for folder in Folder.objects.select_for_update(of=("self",))
            .filter(id__in=folder_ids)
            .order_by("id")
        }
        if set(locked_folders) != folder_ids:
            raise PermissionDenied("An audit relationship owner is unavailable.")

        locked_owners = {}
        for owner_model in sorted(
            owner_ids_by_model, key=lambda model: model._meta.label_lower
        ):
            owner_ids = owner_ids_by_model[owner_model]
            owners = {
                owner.id: owner
                for owner in owner_model.objects.select_for_update(of=("self",))
                .filter(id__in=owner_ids)
                .order_by("id")
            }
            if set(owners) != owner_ids or any(
                owner.folder_id != folder_snapshots[owner_model][owner.id]
                for owner in owners.values()
            ):
                raise PermissionDenied("An audit relationship owner changed; retry.")
            locked_owners[owner_model] = owners

        for through, row_filter, source_name, _owner_model, expected in sorted(
            snapshots, key=lambda item: item[0]._meta.db_table
        ):
            list(
                through.objects.select_for_update(of=("self",))
                .filter(**row_filter)
                .order_by("pk")
            )
            current = set(
                through.objects.filter(**row_filter).values_list(
                    f"{source_name}_id", flat=True
                )
            )
            if current != expected:
                raise PermissionDenied("Audit relationships changed; retry.")

        flow_ids = owner_ids_by_model[ValidationFlow]
        if flow_ids:
            raise PermissionDenied(
                "The audit is linked to a validation flow; unlink it through "
                "the validation workflow before relocation."
            )

        collection_ids = owner_ids_by_model[GenericCollection]
        if collection_ids:
            visible_collection_ids = set(
                RoleAssignment.get_viewable_object_ids(request.user, GenericCollection)
            )
            if not collection_ids.issubset(visible_collection_ids):
                raise PermissionDenied("One or more audit collections are unavailable.")
            for collection in locked_owners[GenericCollection].values():
                collection.folder = locked_folders[collection.folder_id]
                self._check_object_perm(
                    collection,
                    "change",
                    model=GenericCollection,
                )

    def _lock_entity_assessment_relation_owners(self, assessment):
        """Authorize owners affected by an EA perimeter/folder relocation.

        A reverse collection or validation-flow link does not change rows when
        the assessment moves, but its governed target does.  Freeze the exact
        owner/link set and require independent collection authority.  A
        ValidationFlow must be explicitly unlinked through its workflow.
        """

        request = self.context.get("request")
        if request is None or not getattr(request.user, "is_authenticated", False):
            raise PermissionDenied("Assessment relationship authority is unavailable.")

        snapshots = []
        owner_ids_by_model = {}
        for owner_model, field_name in (
            (GenericCollection, "entity_assessments"),
            (ValidationFlow, "entity_assessments"),
        ):
            field = owner_model._meta.get_field(field_name)
            through = field.remote_field.through
            source_name = field.m2m_field_name()
            target_name = field.m2m_reverse_field_name()
            row_filter = {f"{target_name}_id": assessment.id}
            owner_ids = set(
                through.objects.filter(**row_filter).values_list(
                    f"{source_name}_id", flat=True
                )
            )
            snapshots.append((through, row_filter, source_name, owner_model, owner_ids))
            owner_ids_by_model[owner_model] = owner_ids

        owner_folder_ids = {}
        folder_ids = set()
        for owner_model, owner_ids in owner_ids_by_model.items():
            folder_by_owner = dict(
                owner_model.objects.filter(id__in=owner_ids).values_list(
                    "id", "folder_id"
                )
            )
            if set(folder_by_owner) != owner_ids or any(
                folder_id is None for folder_id in folder_by_owner.values()
            ):
                raise PermissionDenied(
                    "An assessment relationship owner is unavailable."
                )
            owner_folder_ids[owner_model] = folder_by_owner
            folder_ids.update(folder_by_owner.values())

        locked_folders = {
            folder.id: folder
            for folder in Folder.objects.select_for_update(of=("self",))
            .filter(id__in=folder_ids)
            .order_by("id")
        }
        if set(locked_folders) != folder_ids:
            raise PermissionDenied("An assessment relationship owner is unavailable.")

        locked_owners = {}
        for owner_model in sorted(
            owner_ids_by_model, key=lambda model: model._meta.label_lower
        ):
            owner_ids = owner_ids_by_model[owner_model]
            owners = {
                owner.id: owner
                for owner in owner_model.objects.select_for_update(of=("self",))
                .filter(id__in=owner_ids)
                .order_by("id")
            }
            if set(owners) != owner_ids or any(
                owner.folder_id != owner_folder_ids[owner_model][owner.id]
                for owner in owners.values()
            ):
                raise PermissionDenied(
                    "An assessment relationship owner changed; retry."
                )
            locked_owners[owner_model] = owners

        for through, row_filter, source_name, _owner_model, expected in sorted(
            snapshots, key=lambda item: item[0]._meta.db_table
        ):
            list(
                through.objects.select_for_update().filter(**row_filter).order_by("pk")
            )
            current = set(
                through.objects.filter(**row_filter).values_list(
                    f"{source_name}_id", flat=True
                )
            )
            if current != expected:
                raise PermissionDenied(
                    "Assessment relationships changed concurrently; retry."
                )

        if owner_ids_by_model[ValidationFlow]:
            raise PermissionDenied(
                "The assessment is linked to a validation flow; unlink it "
                "through the validation workflow before relocation."
            )

        collection_ids = owner_ids_by_model[GenericCollection]
        if collection_ids:
            try:
                visible_collection_ids = set(
                    RoleAssignment.get_viewable_object_ids(
                        request.user, GenericCollection
                    )
                )
            except (NotImplementedError, Permission.DoesNotExist) as exc:
                raise PermissionDenied(
                    "One or more assessment collections are unavailable."
                ) from exc
            if not collection_ids.issubset(visible_collection_ids):
                raise PermissionDenied(
                    "One or more assessment collections are unavailable."
                )
            for collection in locked_owners[GenericCollection].values():
                collection.folder = locked_folders[collection.folder_id]
                self._check_object_perm(
                    collection,
                    "change",
                    model=GenericCollection,
                )

    def _lock_and_validate_entity_relations(
        self,
        *,
        instance,
        validated_data,
        validate_representatives=False,
        validate_reviewers=False,
        validate_solutions=False,
    ):
        """Lock, re-read and authorize every relation used by an EA write.

        Base serializer validation happens before the write transaction and only
        checks non-empty submitted M2M values.  This transaction-time proof also
        covers empty replacements, hidden existing members, reverse generic
        collections, FK targets, and the entity-specific respondent binding.
        """

        request = self.context.get("request")
        if request is None or not getattr(request.user, "is_authenticated", False):
            raise PermissionDenied("Entity assessment authority is unavailable.")

        relation_specs = {
            "reviewers": (Actor, "reviewers"),
            "authors": (Actor, "authors"),
            "representatives": (User, "representatives"),
            "solutions": (Solution, "solutions"),
        }
        target_ids_by_model = {}
        requested_ids_by_field = {}
        snapshots = []

        def add_ids(model, values):
            target_ids_by_model.setdefault(model, set()).update(values)

        for data_key, (model, model_field_name) in relation_specs.items():
            force_existing = (
                data_key == "representatives" and validate_representatives
            ) or (data_key == "reviewers" and validate_reviewers)
            if data_key not in validated_data and not force_existing:
                continue
            requested = list(
                validated_data.get(
                    data_key,
                    getattr(instance, model_field_name).all()
                    if instance is not None and model_field_name is not None
                    else (),
                )
            )
            requested_ids = [item.id for item in requested]
            requested_ids_by_field[data_key] = requested_ids
            add_ids(model, requested_ids)
            if instance is not None:
                snapshot = self._m2m_snapshot(instance, model_field_name)
                snapshots.append(snapshot)
                add_ids(model, snapshot[3])

        entity = validated_data.get("entity")
        if entity is None and instance is not None:
            entity = instance.entity
        if entity is None:
            raise PermissionDenied("The assessed entity is unavailable.")
        if (
            instance is not None
            and "entity" in validated_data
            and entity.id != instance.entity_id
        ):
            raise PermissionDenied({"entity": "This field is immutable"})
        entity_id = entity.id
        add_ids(Entity, {entity_id})

        for data_key, model in (("perimeter", Perimeter), ("evidence", Evidence)):
            include_current_for_folder = (
                data_key == "perimeter"
                and instance is not None
                and "folder" in validated_data
            )
            if data_key not in validated_data and not include_current_for_folder:
                continue
            requested = validated_data.get(data_key)
            ids = {requested.id} if requested is not None else set()
            if instance is not None:
                current_id = getattr(instance, f"{data_key}_id")
                if current_id is not None:
                    ids.add(current_id)
            add_ids(model, ids)

        if "folder" in validated_data:
            requested_folder = validated_data["folder"]
            folder_ids = (
                {requested_folder.id} if requested_folder is not None else set()
            )
            if instance is not None and instance.folder_id is not None:
                folder_ids.add(instance.folder_id)
            add_ids(Folder, folder_ids)

        final_representatives = list(
            validated_data.get(
                "representatives",
                instance.representatives.all() if instance is not None else (),
            )
        )
        final_solutions = list(
            validated_data.get(
                "solutions", instance.solutions.all() if instance is not None else ()
            )
        )
        representative_ids = (
            {user.id for user in final_representatives}
            if validate_representatives
            else set()
        )
        solution_ids = (
            {solution.id for solution in final_solutions}
            if validate_solutions
            else set()
        )
        add_ids(User, representative_ids)
        add_ids(Solution, solution_ids)

        representative_actor_ids = set(
            Actor.objects.filter(user_id__in=representative_ids).values_list(
                "id", flat=True
            )
        )
        representative_row_ids = set(
            Representative.objects.filter(
                entity_id=entity_id,
                user_id__in=representative_ids,
            ).values_list("id", flat=True)
        )
        add_ids(Actor, representative_actor_ids)
        add_ids(Representative, representative_row_ids)

        locked = lock_rows_in_global_model_order(target_ids_by_model)

        for through, row_filter, target_name, expected in snapshots:
            list(
                through.objects.select_for_update().filter(**row_filter).order_by("pk")
            )
            current = set(
                through.objects.filter(**row_filter).values_list(
                    f"{target_name}_id", flat=True
                )
            )
            if current != expected:
                raise PermissionDenied(
                    "Entity assessment relations changed concurrently; retry."
                )

        for model, row_ids in target_ids_by_model.items():
            if row_ids and not row_ids.issubset(
                set(RoleAssignment.get_viewable_object_ids(request.user, model))
            ):
                raise PermissionDenied(
                    "One or more entity assessment relations are unavailable."
                )

        locked_entity = locked[Entity][entity_id]
        locked_users = locked.get(User, {})
        locked_solutions = locked.get(Solution, {})
        if validate_solutions and any(
            solution.provider_entity_id != entity_id
            for solution in (locked_solutions[item_id] for item_id in solution_ids)
        ):
            raise PermissionDenied("Every solution must belong to the assessed entity.")

        locked_actors = locked.get(Actor, {})
        locked_representative_rows = locked.get(Representative, {})
        actor_user_ids = {
            actor.user_id
            for actor_id, actor in locked_actors.items()
            if actor_id in representative_actor_ids and actor.user_id is not None
        }
        bound_user_ids = {
            representative.user_id
            for representative in locked_representative_rows.values()
            if representative.entity_id == entity_id
            and representative.user_id is not None
        }
        if validate_representatives and (
            actor_user_ids != representative_ids
            or bound_user_ids != representative_ids
            or any(
                not locked_users[user_id].is_active
                or not locked_users[user_id].is_third_party
                for user_id in representative_ids
            )
        ):
            raise PermissionDenied(
                "Every representative must be an active third-party contact for this entity."
            )

        for data_key, (model, _model_field_name) in relation_specs.items():
            if data_key in requested_ids_by_field:
                validated_data[data_key] = [
                    locked[model][item_id]
                    for item_id in requested_ids_by_field[data_key]
                ]
        if instance is None or "entity" in validated_data:
            validated_data["entity"] = locked_entity
        for data_key, model in (("perimeter", Perimeter), ("evidence", Evidence)):
            value = validated_data.get(data_key)
            if data_key in validated_data and value is not None:
                validated_data[data_key] = locked[model][value.id]
        if "folder" in validated_data and validated_data["folder"] is not None:
            validated_data["folder"] = locked[Folder][validated_data["folder"].id]

        return {
            "entity": locked_entity,
            "representatives": (
                [locked_users[user.id] for user in final_representatives]
                if validate_representatives
                else final_representatives
            ),
            "solutions": (
                [locked_solutions[solution.id] for solution in final_solutions]
                if validate_solutions
                else final_solutions
            ),
        }

    def _make_enclave_folder(self, instance):
        return Folder.objects.create(
            content_type=Folder.ContentType.ENCLAVE,
            name=f"{instance.entity.name}/{instance.name}",
            parent_folder=instance.folder,
        )

    def _finalize_linked_audit(self, instance, audit):
        """Shared tail for create/link."""
        self._assert_audit_owner_coherence(instance, audit, require_link=False)
        assignment = audit.requirement_assignments.first()
        representatives = list(instance.representatives.all())
        if assignment is not None or representatives:
            self._check_object_perm(
                assignment or {},
                "change" if assignment is not None else "add",
                folder=audit.folder,
                model=RequirementAssignment,
            )
        audit.reviewers.set(instance.reviewers.all())
        audit.authors.set(
            [rep.actor for rep in representatives if hasattr(rep, "actor")]
        )
        self._create_requirement_assignment(audit, representatives)
        instance.compliance_assessment = audit
        instance.save()
        self._assert_audit_owner_coherence(instance, audit)
        return instance

    def _create_audit(self, instance, audit_data):
        if not audit_data.get("framework"):
            raise serializers.ValidationError({"framework": [_("Framework required")]})

        with transaction.atomic():
            locked = self._lock_instance_without_audit(instance, "create_audit")
            from core.utils import build_initial_field_visibility

            framework = Framework.objects.select_for_update().get(
                id=audit_data["framework"].id
            )
            request = self.context.get("request")
            if request is None or framework.id not in set(
                RoleAssignment.get_viewable_object_ids(request.user, Framework)
            ):
                raise PermissionDenied(
                    {"framework": [_("The framework is unavailable.")]}
                )

            enclave = self._make_enclave_folder(locked)
            self._check_object_perm(
                {},
                "add",
                folder=enclave,
                model=ComplianceAssessment,
            )
            # Enclave audits carry no perimeter: the enclave folder, not the
            # entity assessment's perimeter, governs their placement.
            audit = ComplianceAssessment.objects.create(
                name=locked.name,
                framework=framework,
                selected_implementation_groups=audit_data[
                    "selected_implementation_groups"
                ],
                field_visibility=build_initial_field_visibility(framework),
                folder=enclave,
            )

            audit.create_requirement_assessments()
            return self._finalize_linked_audit(locked, audit)

    def _link_existing_audit(self, instance, audit_data):
        with transaction.atomic():
            # Stabilize folder ancestry before any object/owner lock.  Every
            # IAM decision below is derived from that hierarchy, including the
            # independent GenericCollection owner check.
            Folder._lock_folder_tree()
            locked = self._lock_instance_without_audit(instance, "link_audit")
            source_audit = ComplianceAssessment.objects.select_for_update().get(
                pk=audit_data["link_audit"].pk
            )
            if source_audit.folder_id is not None:
                source_audit.folder = Folder.objects.select_for_update().get(
                    id=source_audit.folder_id
                )
            request = self.context.get("request")
            if request is None or not has_full_view_compliance_assessment(
                request.user, source_audit
            ):
                raise PermissionDenied(
                    {"link_audit": [_("Complete audit data is unavailable.")]}
                )
            if source_audit.is_locked or (
                source_audit.status == ComplianceAssessment.Status.IN_REVIEW
            ):
                raise PermissionDenied(
                    {"link_audit": [_("The audit is not editable.")]}
                )
            if not all(
                is_field_editable_by(source_audit, field_name, "auditor")
                for field_name in ("authors", "reviewers", "perimeter")
            ):
                raise PermissionDenied(
                    {"link_audit": [_("The audit is not editable.")]}
                )
            # Reuse the complete-audit projection gate rather than treating a
            # generic CA change permission as authority over hidden child rows.
            from core.views import ComplianceAssessmentViewSet

            ComplianceAssessmentViewSet._assert_complete_assessment_read_access(
                request.user, source_audit
            )
            # Linking relocates the audit itself, so the user needs
            # change_complianceassessment in the audit's current folder —
            # not this serializer's own change_entityassessment.
            self._check_object_perm(source_audit, "change", model=ComplianceAssessment)
            assignments, _requirement_assessments = (
                self._lock_existing_audit_tree_authority(
                    source_audit,
                    fields=("authors", "reviewers", "perimeter"),
                    assignment_sync_required=True,
                    assignment_create_required=locked.representatives.exists(),
                )
            )
            self._lock_existing_audit_identity_rows(
                audit=source_audit,
                entity_assessment=locked,
                assignments=assignments,
                validated_data={},
                identity_fields=("reviewers", "representatives"),
            )
            self._lock_existing_audit_relation_owners(source_audit)
            if (
                EntityAssessment.objects.filter(compliance_assessment=source_audit)
                .exclude(pk=instance.pk)
                .exists()
            ):
                # i18n key resolved by the frontend (safeTranslate / messages/*.json)
                raise serializers.ValidationError(
                    {"link_audit": ["auditAlreadyLinkedToEntityAssessment"]}
                )

            enclave = self._make_enclave_folder(locked)
            self._check_object_perm(
                source_audit,
                "add",
                folder=enclave,
                model=ComplianceAssessment,
            )

            audit = source_audit
            source_folder_id = audit.folder_id
            audit.folder = enclave
            # Enclave audits carry no perimeter — drop the one it had in its
            # previous domain.
            audit.perimeter = None
            audit.save()
            try:
                relocate_compliance_assessment_tree(
                    audit,
                    source_folder_id=source_folder_id,
                )
            except ComplianceAssessmentRelocationError as exc:
                raise serializers.ValidationError({"link_audit": [str(exc)]}) from exc

            return self._finalize_linked_audit(locked, audit)

    def _create_or_update_audit(
        self,
        instance,
        audit_data,
        *,
        identity_fields=(),
        locked_audit=None,
    ):
        if audit_data["create_audit"]:
            return self._create_audit(instance, audit_data)
        elif audit_data.get("link_audit"):
            return self._link_existing_audit(instance, audit_data)
        elif identity_fields:
            audit = locked_audit
            if audit is not None:
                if "reviewers" in identity_fields:
                    audit.reviewers.set(instance.reviewers.all())
                if "representatives" in identity_fields:
                    representatives = instance.representatives.all()
                    audit.authors.set(
                        [rep.actor for rep in representatives if hasattr(rep, "actor")]
                    )
                    self._sync_requirement_assignment(audit, representatives)
        return instance

    def _sync_requirement_assignment(self, audit, representatives):
        """Create or update the RequirementAssignment so its actors match the representatives."""
        actors = [rep.actor for rep in representatives if hasattr(rep, "actor")]
        assignment = audit.requirement_assignments.first()
        if assignment is None:
            if not actors:
                return
            requirement_assessments = audit.requirement_assessments.all()
            if not requirement_assessments.exists():
                return
            assignment = RequirementAssignment.objects.create(
                compliance_assessment=audit,
                folder=audit.folder,
            )
            assignment.actor.set(actors)
            assignment.requirement_assessments.set(requirement_assessments)
        else:
            assignment.actor.set(actors)

    def _create_requirement_assignment(self, audit, representatives):
        self._sync_requirement_assignment(audit, representatives)

    def _assign_third_party_respondents(
        self,
        instance: EntityAssessment,
        third_party_users: set[User],
        old_third_party_users: set[User] | None = None,
        *,
        allow_create: bool = False,
    ):
        # Callers already hold transaction.atomic() and Folder's root mutex.
        # Keep the unused legacy argument for internal call compatibility while
        # replacing the old incremental add/remove behavior with one exact set.
        del old_third_party_users
        if instance.compliance_assessment:
            audit = instance.compliance_assessment
            self._assert_audit_owner_coherence(instance, audit)
            enclave = audit.folder
            try:
                lock_and_assert_no_tprm_idp_group_inheritance(
                    enclave_folder_ids=(enclave.id,)
                )
            except ManagedTprmRespondentIamError as exc:
                raise PermissionDenied(MANAGED_TPRM_RESPONDENT_IAM_ERROR) from exc
            final_user_ids = set(instance.representatives.values_list("id", flat=True))
            supplied_user_ids = {user.id for user in third_party_users}
            if final_user_ids != supplied_user_ids:
                raise PermissionDenied(
                    "The representative set changed concurrently; retry."
                )
            request = self.context.get("request")
            if request is None or not getattr(request.user, "is_authenticated", False):
                raise PermissionDenied("Respondent identity authority is unavailable.")

            group_name = str(UserGroupCodename.THIRD_PARTY_RESPONDENT)
            role_name = str(RoleCodename.THIRD_PARTY_RESPONDENT)
            root_folder_id = Folder.get_root_folder_id()
            roles = list(
                Role.objects.select_for_update(of=("self",))
                .filter(name=role_name)
                .order_by("id")
            )
            if (
                root_folder_id is None
                or len(roles) != 1
                or not roles[0].builtin
                or roles[0].folder_id != root_folder_id
            ):
                raise PermissionDenied(
                    "The respondent IAM role is unavailable or inconsistent."
                )
            respondent_role = roles[0]

            enclave_groups = list(
                UserGroup.objects.select_for_update(of=("self",))
                .filter(folder_id=enclave.id)
                .order_by("id")
            )
            if not enclave_groups:
                if not allow_create:
                    raise PermissionDenied("The respondent IAM scaffold is missing.")
                respondents = UserGroup.objects.create(
                    name=group_name,
                    folder=enclave,
                    builtin=True,
                )
                enclave_groups = [respondents]
            elif (
                len(enclave_groups) != 1
                or enclave_groups[0].name != group_name
                or not enclave_groups[0].builtin
            ):
                raise PermissionDenied("The respondent IAM scaffold is inconsistent.")
            else:
                respondents = enclave_groups[0]

            perimeter_field = RoleAssignment._meta.get_field("perimeter_folders")
            perimeter_through = perimeter_field.remote_field.through
            perimeter_source = perimeter_field.m2m_field_name()
            perimeter_target = perimeter_field.m2m_reverse_field_name()
            reverse_assignment_ids = set(
                perimeter_through.objects.filter(
                    **{f"{perimeter_target}_id": enclave.id}
                ).values_list(f"{perimeter_source}_id", flat=True)
            )
            assignment_ids = set(
                RoleAssignment.objects.filter(folder_id=enclave.id).values_list(
                    "id", flat=True
                )
            )
            assignment_ids.update(
                RoleAssignment.objects.filter(user_group_id=respondents.id).values_list(
                    "id", flat=True
                )
            )
            assignment_ids.update(reverse_assignment_ids)
            assignments = list(
                RoleAssignment.objects.select_for_update(of=("self",))
                .filter(id__in=assignment_ids)
                .select_related("role", "user_group")
                .order_by("id")
            )
            if {assignment.id for assignment in assignments} != assignment_ids:
                raise PermissionDenied(
                    "The respondent IAM scaffold changed concurrently; retry."
                )

            assignment_created = False
            if not assignments:
                if not allow_create:
                    raise PermissionDenied("The respondent IAM scaffold is missing.")
                role_assignment = RoleAssignment.objects.create(
                    user_group=respondents,
                    role=respondent_role,
                    builtin=True,
                    folder=enclave,
                    is_recursive=True,
                )
                assignments = [role_assignment]
                assignment_ids = {role_assignment.id}
                assignment_created = True
            else:
                role_assignment = assignments[0]

            membership_field = User._meta.get_field("user_groups")
            membership_through = membership_field.remote_field.through
            membership_source = membership_field.m2m_field_name()
            membership_target = membership_field.m2m_reverse_field_name()
            membership_filter = {f"{membership_target}_id": respondents.id}
            membership_rows = list(
                membership_through.objects.select_for_update()
                .filter(**membership_filter)
                .order_by("pk")
            )
            existing_member_ids = {
                getattr(row, f"{membership_source}_id") for row in membership_rows
            }

            perimeter_rows = list(
                perimeter_through.objects.select_for_update()
                .filter(**{f"{perimeter_source}_id__in": assignment_ids})
                .order_by("pk")
            )
            assignment_perimeter_ids = {
                getattr(row, f"{perimeter_target}_id")
                for row in perimeter_rows
                if getattr(row, f"{perimeter_source}_id") == role_assignment.id
            }
            enclave_assignment_ids = {
                getattr(row, f"{perimeter_source}_id")
                for row in perimeter_rows
                if getattr(row, f"{perimeter_target}_id") == enclave.id
            }

            if (
                len(assignments) != 1
                or role_assignment.folder_id != enclave.id
                or role_assignment.user_id is not None
                or role_assignment.user_group_id != respondents.id
                or role_assignment.role_id != respondent_role.id
                or not role_assignment.builtin
                or not role_assignment.is_recursive
                or (not assignment_created and assignment_perimeter_ids != {enclave.id})
                or enclave_assignment_ids - {role_assignment.id}
            ):
                raise PermissionDenied("The respondent IAM scaffold is inconsistent.")

            protected_user_ids = existing_member_ids | supplied_user_ids
            locked_users = {
                user.id: user
                for user in User.objects.select_for_update(of=("self",))
                .filter(id__in=protected_user_ids)
                .order_by("id")
            }
            if set(locked_users) != protected_user_ids:
                raise PermissionDenied(
                    "One or more respondent identities are unavailable."
                )
            try:
                visible_user_ids = set(
                    RoleAssignment.get_viewable_object_ids(request.user, User)
                )
            except (NotImplementedError, Permission.DoesNotExist):
                visible_user_ids = set()
            if not protected_user_ids.issubset(visible_user_ids):
                raise PermissionDenied(
                    "One or more respondent identities are unavailable."
                )

            locked_representatives = list(
                Representative.objects.select_for_update(of=("self",))
                .filter(
                    entity_id=instance.entity_id,
                    user_id__in=supplied_user_ids,
                )
                .order_by("id")
            )
            bound_user_ids = {
                representative.user_id
                for representative in locked_representatives
                if representative.entity_id == instance.entity_id
            }
            if bound_user_ids != supplied_user_ids or any(
                not locked_users[user_id].is_active
                or not locked_users[user_id].is_third_party
                for user_id in supplied_user_ids
            ):
                raise PermissionDenied(
                    "Every representative must be an active third-party contact for this entity."
                )

            # Exact replacements prevent stale (including formerly hidden)
            # memberships or perimeter links from surviving a successful sync.
            respondents.user_set.set(
                [locked_users[user_id] for user_id in sorted(supplied_user_ids)]
            )
            role_assignment.perimeter_folders.set([enclave])

            final_member_ids = set(
                membership_through.objects.filter(**membership_filter).values_list(
                    f"{membership_source}_id", flat=True
                )
            )
            final_perimeter_ids = set(
                perimeter_through.objects.filter(
                    **{f"{perimeter_source}_id": role_assignment.id}
                ).values_list(f"{perimeter_target}_id", flat=True)
            )
            if final_member_ids != supplied_user_ids or final_perimeter_ids != {
                enclave.id
            }:
                raise PermissionDenied(
                    "The respondent IAM scaffold could not be synchronized."
                )

    def create(self, validated_data):
        audit_data = self._extract_audit_data(validated_data)
        with transaction.atomic():
            Folder._lock_folder_tree()
            self._lock_and_validate_entity_relations(
                instance=None,
                validated_data=validated_data,
                validate_representatives=(
                    "representatives" in validated_data
                    or audit_data["create_audit"]
                    or bool(audit_data.get("link_audit"))
                ),
                validate_reviewers=(
                    "reviewers" in validated_data
                    or audit_data["create_audit"]
                    or bool(audit_data.get("link_audit"))
                ),
                validate_solutions="solutions" in validated_data,
            )
            perimeter = validated_data.get("perimeter")
            if perimeter is not None:
                if perimeter.folder_id is None:
                    raise PermissionDenied("The perimeter owner is unavailable.")
                target_folder = Folder.objects.select_for_update().get(
                    id=perimeter.folder_id
                )
                supplied_folder = validated_data.get("folder")
                if (
                    supplied_folder is not None
                    and supplied_folder.id != target_folder.id
                ):
                    raise serializers.ValidationError(
                        {"folder": [_("The folder must match the perimeter owner.")]}
                    )
                self._check_object_perm(
                    validated_data,
                    "add",
                    folder=target_folder,
                    model=EntityAssessment,
                )
                validated_data["folder"] = target_folder
            instance = super().create(validated_data)
            instance = self._create_or_update_audit(instance, audit_data)
            self._assign_third_party_respondents(
                instance,
                set(instance.representatives.all()),
                allow_create=True,
            )
        return instance

    def update(self, instance: EntityAssessment, validated_data):
        audit_data = self._extract_audit_data(validated_data)
        identity_fields = {"reviewers", "representatives"} & set(validated_data)
        identity_sync_requested = bool(identity_fields)
        representatives_supplied = "representatives" in validated_data
        expected_folder_id = instance.folder_id
        expected_audit_id = instance.compliance_assessment_id

        with transaction.atomic():
            Folder._lock_folder_tree()
            locked_audit = None
            locked_assignments = []
            if expected_audit_id is not None:
                locked_audit = ComplianceAssessment.objects.select_for_update().get(
                    id=expected_audit_id
                )
            if audit_data.get("link_audit") is not None:
                # Establish CA -> EntityAssessment ordering before the nested
                # link routine reuses these locks.
                ComplianceAssessment.objects.select_for_update().get(
                    id=audit_data["link_audit"].id
                )
            locked_instance = EntityAssessment.objects.select_for_update().get(
                pk=instance.pk
            )
            if (
                locked_instance.folder_id != expected_folder_id
                or locked_instance.compliance_assessment_id != expected_audit_id
            ):
                raise serializers.ValidationError(
                    {"detail": [_("The assessment owner changed; retry.")]}
                )

            if locked_audit is not None:
                if locked_audit.folder_id is None:
                    raise PermissionDenied("The linked audit owner is unavailable.")
                locked_audit.folder = Folder.objects.select_for_update().get(
                    id=locked_audit.folder_id
                )
                self._assert_audit_owner_coherence(locked_instance, locked_audit)

                if (
                    "folder" in validated_data
                    and getattr(validated_data["folder"], "id", None)
                    != locked_instance.folder_id
                ):
                    raise PermissionDenied(
                        {"folder": "A linked assessment owner is immutable"}
                    )
                if "perimeter" in validated_data:
                    requested_perimeter = validated_data["perimeter"]
                    requested_folder_id = (
                        requested_perimeter.folder_id
                        if requested_perimeter is not None
                        else locked_instance.folder_id
                    )
                    if requested_folder_id != locked_instance.folder_id:
                        raise PermissionDenied(
                            {"perimeter": "A linked assessment owner is immutable"}
                        )

            relation_write_requested = bool(
                {
                    "entity",
                    "perimeter",
                    "evidence",
                    "folder",
                    "authors",
                    "reviewers",
                    "representatives",
                    "solutions",
                }
                & set(validated_data)
            )
            if (
                relation_write_requested
                or audit_data["create_audit"]
                or audit_data.get("link_audit")
            ):
                self._lock_and_validate_entity_relations(
                    instance=locked_instance,
                    validated_data=validated_data,
                    validate_representatives=(
                        representatives_supplied
                        or audit_data["create_audit"]
                        or bool(audit_data.get("link_audit"))
                    ),
                    validate_reviewers=(
                        "reviewers" in validated_data
                        or audit_data["create_audit"]
                        or bool(audit_data.get("link_audit"))
                    ),
                    validate_solutions="solutions" in validated_data,
                )

            if (
                locked_audit is not None
                and identity_sync_requested
                and not audit_data["create_audit"]
                and not audit_data.get("link_audit")
            ):
                locked_assignments, _locked_requirement_assessments = (
                    self._lock_existing_audit_tree_authority(
                        locked_audit,
                        fields=tuple(
                            field_name
                            for field_name, source_name in (
                                ("authors", "representatives"),
                                ("reviewers", "reviewers"),
                            )
                            if source_name in identity_fields
                        ),
                        assignment_sync_required=("representatives" in identity_fields),
                        assignment_create_required=(
                            "representatives" in identity_fields
                            and bool(validated_data.get("representatives"))
                        ),
                    )
                )

            # Perimeter owns the EntityAssessment folder. Re-resolve it only
            # after the global folder mutex so a concurrent perimeter move
            # cannot leave the assessment attached to a stale folder object.
            if "perimeter" in validated_data:
                new_perimeter = validated_data["perimeter"]
                if new_perimeter is not None:
                    new_perimeter = (
                        type(new_perimeter)
                        .objects.select_for_update()
                        .get(id=new_perimeter.id)
                    )
                    request = self.context.get("request")
                    if request is None or new_perimeter.id not in set(
                        RoleAssignment.get_viewable_object_ids(
                            request.user, type(new_perimeter)
                        )
                    ):
                        raise PermissionDenied(
                            {"perimeter": [_("The perimeter is unavailable.")]}
                        )
                    validated_data["perimeter"] = new_perimeter
                    if new_perimeter.folder_id is not None:
                        target_folder = Folder.objects.select_for_update().get(
                            id=new_perimeter.folder_id
                        )
                        supplied_folder = validated_data.get("folder")
                        if (
                            supplied_folder is not None
                            and supplied_folder.id != target_folder.id
                        ):
                            raise serializers.ValidationError(
                                {
                                    "folder": [
                                        _("The folder must match the perimeter owner.")
                                    ]
                                }
                            )
                        if target_folder.id != locked_instance.folder_id:
                            self._check_object_perm(
                                locked_instance,
                                "add",
                                folder=target_folder,
                                model=EntityAssessment,
                            )
                        validated_data["folder"] = target_folder
            elif "folder" in validated_data and locked_instance.perimeter_id:
                current_perimeter = Perimeter.objects.select_for_update().get(
                    id=locked_instance.perimeter_id
                )
                if validated_data["folder"].id != current_perimeter.folder_id:
                    raise serializers.ValidationError(
                        {"folder": [_("The folder must match the perimeter owner.")]}
                    )
                if validated_data["folder"].id != locked_instance.folder_id:
                    self._check_object_perm(
                        locked_instance,
                        "add",
                        folder=validated_data["folder"],
                        model=EntityAssessment,
                    )

            final_folder = validated_data.get("folder")
            final_folder_id = getattr(final_folder, "id", locked_instance.folder_id)
            final_perimeter = validated_data.get("perimeter")
            final_perimeter_id = (
                getattr(final_perimeter, "id", None)
                if "perimeter" in validated_data
                else locked_instance.perimeter_id
            )
            if (
                final_folder_id != locked_instance.folder_id
                or final_perimeter_id != locked_instance.perimeter_id
            ):
                self._lock_entity_assessment_relation_owners(locked_instance)

            if locked_audit is not None and identity_sync_requested:
                self._lock_existing_audit_identity_rows(
                    audit=locked_audit,
                    entity_assessment=locked_instance,
                    assignments=locked_assignments,
                    validated_data=validated_data,
                    identity_fields=identity_fields,
                )
            requested_representatives = set(
                validated_data.get(
                    "representatives", locked_instance.representatives.all()
                )
            )
            old_representatives = (
                set(locked_instance.representatives.all()) - requested_representatives
            )
            self.instance = locked_instance
            instance = super().update(locked_instance, validated_data)
            instance = self._create_or_update_audit(
                instance,
                audit_data,
                identity_fields=identity_fields,
                locked_audit=locked_audit,
            )
            if (
                representatives_supplied
                or audit_data["create_audit"]
                or audit_data.get("link_audit")
            ):
                self._assign_third_party_respondents(
                    instance,
                    set(instance.representatives.all()),
                    old_representatives,
                    allow_create=(
                        audit_data["create_audit"] or bool(audit_data.get("link_audit"))
                    ),
                )
        return instance

    def to_representation(self, instance):
        data = super().to_representation(instance)
        return self._filter_writable_related_representation(data)

    class Meta:
        model = EntityAssessment
        exclude = []


class RepresentativeReadSerializer(BaseModelSerializer):
    entity = FieldsRelatedField()
    user = FieldsRelatedField()
    filtering_labels = FieldsRelatedField(many=True)
    # Governing folder, derived the same way as backend enforcement
    # (Folder.get_folder path: entity.folder) so the frontend can scope checks.
    folder = FieldsRelatedField(source="entity.folder")

    class Meta:
        model = Representative
        exclude = []


class RepresentativeWriteSerializer(BaseModelSerializer):
    create_user = serializers.BooleanField(default=False)

    def validate_entity(self, value):
        self._ensure_immutable("entity", value)
        return value

    def _create_or_update_user(self, instance, user):
        if not user:
            return
        user = User.objects.filter(
            email=instance.email,
        ).first()
        if not user:
            send_mail = settings.EMAIL_HOST or settings.EMAIL_HOST_RESCUE
            try:
                user = User.objects.create_user(
                    email=instance.email,
                    first_name=instance.first_name,
                    last_name=instance.last_name,
                    is_third_party=True,
                    keep_local_login=True,
                )
            except Exception as e:
                logger.error(e)
                user = User.objects.filter(email=instance.email).first()
                if user and send_mail:
                    if not user.is_third_party:
                        raise serializers.ValidationError(
                            {"email": "errorUserAlreadyExistsAsInternal"}
                        )
                    user.keep_local_login = True
                    user.save()
                    instance.user = user
                    instance.save()
                    logger.warning("mailing failed")
                    raise serializers.ValidationError(
                        {
                            "warning": [
                                "User created successfully but an error occurred while sending the email"
                            ]
                        }
                    )
                else:
                    raise serializers.ValidationError(
                        {"error": ["An error occurred while creating the user"]}
                    )
        if not user.is_third_party:
            raise serializers.ValidationError(
                {"email": "errorUserAlreadyExistsAsInternal"}
            )
        user.keep_local_login = True
        user.save()
        instance.user = user
        instance.save()

    def create(self, validated_data):
        user = validated_data.pop("create_user", False)
        instance = super().create(validated_data)
        self._create_or_update_user(instance, user)
        return instance

    def update(self, instance, validated_data):
        user = validated_data.pop("create_user", False)
        instance = super().update(instance, validated_data)
        self._create_or_update_user(instance, user)
        return instance

    class Meta:
        model = Representative
        exclude = []


class SolutionSubcontractorReadSerializer(BaseModelSerializer):
    """Nested rows inside SolutionReadSerializer.subcontracting_chain."""

    subcontractor = FieldsRelatedField()
    recipient = FieldsRelatedField()

    class Meta:
        model = SolutionSubcontractor
        fields = ["id", "subcontractor", "recipient"]


class SolutionSubcontractorWriteSerializer(serializers.Serializer):
    """
    Write shape for nested chain rows. Deliberately NOT a ModelSerializer —
    `solution` is set by the parent SolutionWriteSerializer from URL context,
    not accepted from the client. `id` is also ignored; the chain is fully
    replaced on each PATCH.

    `recipient` is optional — null means "direct provider" (the common case
    for fan-out entries directly under the provider).
    """

    subcontractor = serializers.PrimaryKeyRelatedField(queryset=Entity.objects.all())
    recipient = serializers.PrimaryKeyRelatedField(
        queryset=Entity.objects.all(), required=False, allow_null=True, default=None
    )


class SolutionReadSerializer(BaseModelSerializer):
    provider_entity = FieldsRelatedField()
    recipient_entity = FieldsRelatedField()
    # Governing folder, derived the same way as backend enforcement
    # (Folder.get_folder path: provider_entity.folder) so the frontend can scope checks.
    folder = FieldsRelatedField(source="provider_entity.folder")
    assets = FieldsRelatedField(many=True)
    contracts = FieldsRelatedField(many=True)
    owner = FieldsRelatedField(many=True)
    filtering_labels = FieldsRelatedField(many=True)
    subcontracting_chain = SolutionSubcontractorReadSerializer(
        many=True, read_only=True
    )
    # Raw EBA code (e.g. "eba_TA:S02"), not the display label.
    # So the frontend can map to translation via safeTranslate.
    dora_ict_service_type = serializers.CharField(default="")
    data_location_storage = serializers.CharField(
        source="get_data_location_storage_display", default=""
    )
    data_location_processing = serializers.CharField(
        source="get_data_location_processing_display", default=""
    )
    dora_data_sensitiveness = serializers.CharField(
        source="get_dora_data_sensitiveness_display", default=""
    )
    dora_reliance_level = serializers.CharField(
        source="get_dora_reliance_level_display", default=""
    )
    dora_substitutability = serializers.CharField(
        source="get_dora_substitutability_display", default=""
    )
    dora_non_substitutability_reason = serializers.CharField(
        source="get_dora_non_substitutability_reason_display", default=""
    )
    dora_has_exit_plan = serializers.CharField(
        source="get_dora_has_exit_plan_display", default=""
    )
    dora_reintegration_possibility = serializers.CharField(
        source="get_dora_reintegration_possibility_display", default=""
    )
    dora_discontinuing_impact = serializers.CharField(
        source="get_dora_discontinuing_impact_display", default=""
    )
    dora_alternative_providers_identified = serializers.CharField(
        source="get_dora_alternative_providers_identified_display", default=""
    )

    class Meta:
        model = Solution
        exclude = []


class SolutionWriteSerializer(BaseModelSerializer):
    # The chain is handled manually in create()/update() below. Declared here
    # so that `initial_data.get("subcontracting_chain")` is the surface we
    # inspect.
    subcontracting_chain = SolutionSubcontractorWriteSerializer(
        many=True, required=False
    )

    def validate_provider_entity(self, value):
        self._ensure_immutable("provider_entity", value)
        return value

    def validate_subcontracting_chain(self, value):
        """
        Ensure client-side invariants before hitting the DB:
          - No duplicate subcontractor within a single write.
          - Subcontractor != recipient (self-loop).
          - Every recipient must be one of the submitted subcontractors.
          - No cycles in the recipient graph.
          - Subcontractor != direct provider (checked in update/create since
            only then do we have the bound Solution).
        """
        subs = [entry["subcontractor"] for entry in value]
        sub_ids = {s.id for s in subs}
        if len(subs) != len(sub_ids):
            raise serializers.ValidationError(
                _("A subcontractor cannot appear twice in the same chain.")
            )

        # Build directed graph: subcontractor_id → recipient_id
        graph = {}
        for entry in value:
            recipient = entry.get("recipient")
            sub_id = entry["subcontractor"].id
            if recipient:
                if sub_id == recipient.id:
                    raise serializers.ValidationError(
                        _("A subcontractor cannot be its own recipient.")
                    )
                if recipient.id not in sub_ids:
                    raise serializers.ValidationError(
                        _(
                            "Recipient must be one of the submitted "
                            "subcontractors in the chain."
                        )
                    )
                graph[sub_id] = recipient.id

        # Cycle detection via DFS on the recipient graph.
        WHITE, GRAY, BLACK = 0, 1, 2
        color = {sid: WHITE for sid in sub_ids}
        for start in sub_ids:
            if color[start] != WHITE:
                continue
            stack = [start]
            while stack:
                node = stack[-1]
                if color[node] == WHITE:
                    color[node] = GRAY
                    nxt = graph.get(node)
                    if nxt is not None:
                        if color[nxt] == GRAY:
                            raise serializers.ValidationError(
                                _("The subcontracting chain contains a cycle.")
                            )
                        if color[nxt] == WHITE:
                            stack.append(nxt)
                            continue
                color[node] = BLACK
                stack.pop()

        return value

    def _resolve_direct_provider(self, validated_data, instance):
        """Pull the direct provider id from the write data, falling back to instance."""
        provider = validated_data.get("provider_entity")
        if provider is not None:
            return provider.id if hasattr(provider, "id") else provider
        if instance is not None and instance.provider_entity_id is not None:
            return instance.provider_entity_id
        return None

    def _replace_chain(self, solution, chain_data, direct_provider_id):
        """
        Delete all existing SolutionSubcontractor rows for this solution and
        bulk-create the new set inside a single atomic transaction.

        Enforces the self-loop rule here (subcontractor != direct provider)
        because we need the bound solution to resolve it.
        """
        for entry in chain_data:
            if (
                direct_provider_id is not None
                and entry["subcontractor"].id == direct_provider_id
            ):
                raise serializers.ValidationError(
                    {
                        "subcontracting_chain": [
                            _(
                                "A subcontractor cannot be the solution's "
                                "direct provider (rank 1 is implicit)."
                            )
                        ]
                    }
                )

        with transaction.atomic():
            SolutionSubcontractor.objects.filter(solution=solution).delete()
            if chain_data:
                try:
                    SolutionSubcontractor.objects.bulk_create(
                        [
                            SolutionSubcontractor(
                                solution=solution,
                                subcontractor=entry["subcontractor"],
                                recipient=entry.get("recipient"),
                            )
                            for entry in chain_data
                        ]
                    )
                except IntegrityError as exc:
                    raise serializers.ValidationError(
                        {
                            "subcontracting_chain": [
                                _("Chain modified by another user. Refresh and retry.")
                            ],
                        }
                    ) from exc

    def to_internal_value(self, data):
        """Convert None to empty string for CharField DORA fields before validation"""
        dora_char_fields = [
            "dora_ict_service_type",
            "data_location_storage",
            "data_location_processing",
            "dora_data_sensitiveness",
            "dora_reliance_level",
            "dora_substitutability",
            "dora_non_substitutability_reason",
            "dora_has_exit_plan",
            "dora_reintegration_possibility",
            "dora_discontinuing_impact",
            "dora_alternative_providers_identified",
        ]
        for field in dora_char_fields:
            if field in data and data[field] is None:
                data[field] = ""
        return super().to_internal_value(data)

    def create(self, validated_data):
        chain_data = validated_data.pop("subcontracting_chain", _CHAIN_UNSET)
        with transaction.atomic():
            solution = super().create(validated_data)
            if chain_data is not _CHAIN_UNSET:
                self._replace_chain(solution, chain_data, solution.provider_entity_id)
        self._log_chain_event(solution, chain_data, is_create=True)
        return solution

    def update(self, instance, validated_data):
        # Distinguish "omit the field" (leave chain untouched) from "send []"
        # (explicitly clear). `initial_data` preserves the raw presence signal
        # even after validated_data.pop() mutations.
        chain_sent = "subcontracting_chain" in self.initial_data
        chain_data = validated_data.pop("subcontracting_chain", _CHAIN_UNSET)

        with transaction.atomic():
            solution = super().update(instance, validated_data)
            if chain_sent:
                direct_provider_id = self._resolve_direct_provider(
                    validated_data, solution
                )
                self._replace_chain(
                    solution,
                    chain_data if chain_data is not _CHAIN_UNSET else [],
                    direct_provider_id,
                )
        if chain_sent:
            self._log_chain_event(
                solution,
                chain_data if chain_data is not _CHAIN_UNSET else [],
            )
        return solution

    def _log_chain_event(self, solution, chain_data, is_create=False):
        """Emit structured audit log for chain mutations (post-commit)."""
        if chain_data is _CHAIN_UNSET or chain_data is None:
            return
        request = self.context.get("request")
        user_id = getattr(getattr(request, "user", None), "id", None)
        logger.info(
            "solution.subcontracting_chain.updated",
            solution_id=str(solution.id),
            user_id=str(user_id) if user_id else None,
            chain_length=len(chain_data),
            is_create=is_create,
            subcontractor_ids=[str(entry["subcontractor"].id) for entry in chain_data],
        )

    class Meta:
        model = Solution
        exclude = ["recipient_entity"]


class ContractReadSerializer(BaseModelSerializer):
    folder = FieldsRelatedField()
    owner = FieldsRelatedField(many=True)
    provider_entity = FieldsRelatedField()
    beneficiary_entity = FieldsRelatedField()
    evidences = FieldsRelatedField(many=True)
    solutions = FieldsRelatedField(many=True)
    overarching_contract = FieldsRelatedField()
    filtering_labels = FieldsRelatedField(many=True)
    validation_flows = FieldsRelatedField(
        many=True,
        fields=[
            "id",
            "ref_id",
            "status",
            {"approver": ["id", "email", "first_name", "last_name"]},
        ],
        source="validationflow_set",
    )

    class Meta:
        model = Contract
        exclude = []


class ContractWriteSerializer(BaseModelSerializer):
    class Meta:
        model = Contract
        exclude = []

    def validate_overarching_contract(self, value):
        """
        Validate that a contract cannot be set as its own overarching contract.
        """
        if value and self.instance and value.id == self.instance.id:
            raise serializers.ValidationError(
                _("A contract cannot be set as its own overarching contract")
            )
        return value
