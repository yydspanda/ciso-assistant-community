import io
import re

from django.contrib.auth import get_user_model
from django.db import transaction
from django.db.models import ProtectedError
from rest_framework.exceptions import PermissionDenied
from rest_framework.response import Response
from rest_framework.status import (
    HTTP_400_BAD_REQUEST,
    HTTP_403_FORBIDDEN,
    HTTP_409_CONFLICT,
)
from iam.models import Folder, Permission, RoleAssignment, UserGroup
from core.views import (
    BaseModelViewSet as AbstractBaseModelViewSet,
    ExportMixin,
    escape_excel_formula,
)
from core.models import Actor, Asset, ComplianceAssessment, Framework, Team
from tprm.models import Entity, Representative, Solution, EntityAssessment, Contract
from rest_framework.decorators import action
import structlog

from rest_framework.request import Request
from rest_framework.response import Response

from django.utils.formats import date_format
from django.http import HttpResponse
from django.shortcuts import get_object_or_404
from django.db.models import (
    Case,
    F,
    FloatField,
    Prefetch,
    Q,
    Sum,
    TextField,
    Value,
    When,
)
from django.db.models.functions import Cast, Greatest, Coalesce, Round

from core.constants import COUNTRY_CHOICES, CURRENCY_CHOICES
from core.reserved_iam import (
    MANAGED_TPRM_RESPONDENT_IAM_ERROR,
    ManagedTprmRespondentIamError,
    lock_and_assert_no_tprm_idp_group_inheritance,
)
from core.dora import (
    DORA_ENTITY_TYPE_CHOICES,
    DORA_ENTITY_HIERARCHY_CHOICES,
    DORA_CONTRACTUAL_ARRANGEMENT_CHOICES,
    TERMINATION_REASON_CHOICES,
    DORA_ICT_SERVICE_CHOICES,
    DORA_SENSITIVENESS_CHOICES,
    DORA_RELIANCE_CHOICES,
    DORA_PROVIDER_PERSON_TYPE_CHOICES,
    DORA_SUBSTITUTABILITY_CHOICES,
    DORA_NON_SUBSTITUTABILITY_REASON_CHOICES,
    DORA_BINARY_CHOICES,
    DORA_YES_NO_ASSESSMENT_CHOICES,
    DORA_REINTEGRATION_POSSIBILITY_CHOICES,
    DORA_DISCONTINUING_IMPACT_CHOICES,
)

import csv
import io
import uuid
import zipfile
from datetime import datetime

logger = structlog.get_logger(__name__)
User = get_user_model()

# Core models the DORA ROI is built from. Reading the register as a whole
# requires holding these on the root folder, i.e. instance-wide.
DORA_ROI_PERMISSIONS = (
    "view_entity",
    "view_solution",
    "view_asset",
    "view_contract",
)


def has_dora_roi_access(user) -> bool:
    root_folder = Folder.get_root_folder()
    return all(
        RoleAssignment.is_access_allowed(
            user=user,
            perm=Permission.objects.get(codename=codename),
            folder=root_folder,
        )
        for codename in DORA_ROI_PERMISSIONS
    )


class BaseModelViewSet(AbstractBaseModelViewSet):
    serializers_module = "tprm.serializers"


# Create your views here.
class EntityViewSet(ExportMixin, BaseModelViewSet):
    """
    API endpoint that allows entities to be viewed or edited.
    """

    model = Entity
    export_config = {
        "filename": "entities_export",
        "fields": {
            "ref_id": {"source": "ref_id", "label": "ref_id", "escape": True},
            "name": {"source": "name", "label": "name", "escape": True},
            "description": {
                "source": "description",
                "label": "description",
                "escape": True,
            },
            "mission": {"source": "mission", "label": "mission", "escape": True},
            "country": {"source": "country", "label": "country"},
            "currency": {"source": "currency", "label": "currency"},
            "dependency": {"source": "default_dependency", "label": "dependency"},
            "penetration": {"source": "default_penetration", "label": "penetration"},
            "maturity": {"source": "default_maturity", "label": "maturity"},
            "trust": {"source": "default_trust", "label": "trust"},
            "lei": {
                "source": "legal_identifiers",
                "label": "lei",
                "format": lambda v: (v or {}).get("LEI", ""),
            },
            "euid": {
                "source": "legal_identifiers",
                "label": "euid",
                "format": lambda v: (v or {}).get("EUID", ""),
            },
            "duns": {
                "source": "legal_identifiers",
                "label": "duns",
                "format": lambda v: (v or {}).get("DUNS", ""),
            },
            "vat": {
                "source": "legal_identifiers",
                "label": "vat",
                "format": lambda v: (v or {}).get("VAT", ""),
            },
            "parent_entity_ref_id": {
                "source": "parent_entity.ref_id",
                "label": "parent_entity_ref_id",
                "escape": True,
            },
            "domain": {"source": "folder.name", "label": "domain", "escape": True},
        },
        "select_related": ["folder", "parent_entity"],
        "wrap_columns": ["name", "description", "mission"],
    }
    filterset_fields = [
        "name",
        "ref_id",
        "is_active",
        "folder",
        "parent_entity",
        "relationship",
        "relationship__name",
        "contracts",
        "country",
        "currency",
        "dora_entity_type",
        "dora_entity_hierarchy",
        "dora_competent_authority",
        "filtering_labels",
        "default_dependency",
        "default_penetration",
        "default_maturity",
        "default_trust",
    ]
    search_fields = ["name", "description", "legal_identifiers_text"]

    @transaction.atomic
    def perform_destroy(self, instance):
        """Keep Entity CASCADE from bypassing owned EA cleanup authority."""

        from core.views import _assert_object_action_permission

        Folder._lock_folder_tree()
        expected_folder_id = instance.folder_id
        locked_folder = get_object_or_404(
            Folder.objects.select_for_update(of=("self",)),
            id=expected_folder_id,
        )
        locked_instance = get_object_or_404(
            Entity.objects.select_for_update(of=("self",)),
            id=instance.id,
        )
        if locked_instance.folder_id != expected_folder_id:
            raise PermissionDenied("The entity owner changed; retry.")
        locked_instance.folder = locked_folder
        _assert_object_action_permission(
            user=self.request.user,
            instance=locked_instance,
            action="delete",
        )
        dependent_assessments = list(
            EntityAssessment.objects.select_for_update(of=("self",))
            .filter(entity_id=locked_instance.id)
            .order_by("id")
        )
        if dependent_assessments:
            raise PermissionDenied(
                "Delete dependent entity assessments through their owned endpoint first."
            )
        return super().perform_destroy(locked_instance)

    def destroy(self, request, *args, **kwargs):
        """
        Convert Django's ProtectedError into a 409 Conflict with the list of
        blocking references, so the frontend can render "this entity is used
        as a subcontractor/recipient in N solutions" rather than a default 500.

        Both the subcontractor and recipient FKs on SolutionSubcontractor use
        on_delete=PROTECT, so deleting an Entity referenced by either role
        raises ProtectedError. Collect blocking rows for both roles.
        """
        instance = self.get_object()
        try:
            return super().destroy(request, *args, **kwargs)
        except ProtectedError as exc:
            as_subcontractor = instance.subcontracts.select_related("solution")
            as_recipient = instance.subcontract_recipients.select_related("solution")
            total_count = as_subcontractor.count() + as_recipient.count()

            # Combine both querysets, ordered by solution name, capped at 50.
            blocking_rows = []
            for row in as_subcontractor.order_by("solution__name")[:50]:
                blocking_rows.append(
                    {
                        "id": str(row.id),
                        "solution_id": str(row.solution_id),
                        "solution_name": row.solution.name,
                        "role": "subcontractor",
                    }
                )
            remaining = 50 - len(blocking_rows)
            if remaining > 0:
                for row in as_recipient.order_by("solution__name")[:remaining]:
                    blocking_rows.append(
                        {
                            "id": str(row.id),
                            "solution_id": str(row.solution_id),
                            "solution_name": row.solution.name,
                            "role": "recipient",
                        }
                    )

            return Response(
                {
                    "detail": (
                        f"Cannot delete entity '{instance.name}' — it is "
                        f"referenced in {total_count} subcontracting "
                        f"chain row(s). Remove those references first."
                    ),
                    "blocking_subcontracts": blocking_rows,
                },
                status=HTTP_409_CONFLICT,
            )

    def get_queryset(self):
        """Add annotations for default_criticality sorting and legal identifier search."""
        qs = (
            super()
            .get_queryset()
            .select_related(
                "folder",
                "folder__parent_folder",
                "parent_entity",
            )
        )

        # Skip the heavier prefetches on autocomplete (lightweight payload).
        if self.action != "autocomplete":
            # M2Ms / reverse FKs rendered as FieldsRelatedField on
            # EntityReadSerializer — without these every row issues a fresh query.
            qs = qs.prefetch_related(
                "owned_folders",
                "branches",
                "relationship",
                "contracts",
                "filtering_labels",
            )

        # Cast legal_identifiers JSON to text so DRF SearchFilter can icontains on it.
        # Works on both SQLite (JSON stored as text) and PostgreSQL (jsonb → text cast).
        qs = qs.annotate(
            legal_identifiers_text=Cast("legal_identifiers", output_field=TextField()),
        )

        # Annotate with default_criticality calculation
        # Formula: (default_dependency * default_penetration) / (default_maturity * default_trust)
        # Handle division by zero by using Case/When
        # Rounded to 2 decimal places by multiplying by 100, rounding, then dividing by 100
        qs = qs.annotate(
            default_criticality=Cast(
                Round(
                    Case(
                        # If maturity or trust is 0, return 0.0
                        When(default_maturity=0, then=Value(0.0)),
                        When(default_trust=0, then=Value(0.0)),
                        # Otherwise, calculate criticality * 100
                        default=Cast(
                            (F("default_dependency") * F("default_penetration") * 100.0)
                            / (F("default_maturity") * F("default_trust")),
                            output_field=FloatField(),
                        ),
                        output_field=FloatField(),
                    )
                )
                / 100.0,
                output_field=FloatField(),
            )
        )

        return qs

    @action(detail=False, methods=["get"], name="Generate DORA ROI")
    def generate_dora_roi(self, request):
        """
        Generate DORA Register of Information (ROI) as a zip file containing CSV data.

        This generates a comprehensive DORA ROI export containing multiple CSV reports:
        - b_01.01: Main entity information
        - b_01.02: Entity register (main entity + branches)
        - b_01.03: Branches register
        - b_02.01-03: Contractual arrangements
        - b_03.01-03: Signing entities and providers
        - b_04.01: Entities using ICT services
        - b_05.01-02: Provider details and supply chains
        - b_06.01: Critical functions register
        - b_07.01: Assessment of ICT services
        - b_99.01: Aggregation report
        - FilingIndicators.csv: Template inclusion indicators
        - parameters.csv: Report metadata and configuration
        - META-INF/reportPackage.json: XBRL report package metadata
        - reports/report.json: XBRL CSV configuration and taxonomy references
        """
        from tprm import dora_export

        # Get the main entity
        main_entity = Entity.get_main_entity()

        if not main_entity:
            return HttpResponse("No main entity found", status=400)

        # Get accessible objects for the current user
        viewable_entities = RoleAssignment.get_viewable_object_ids(request.user, Entity)
        viewable_contracts = RoleAssignment.get_viewable_object_ids(
            request.user, Contract
        )
        viewable_assets = RoleAssignment.get_viewable_object_ids(request.user, Asset)

        # Prepare entity lists
        # Subsidiaries: entities with main entity as parent AND dora_provider_person_type set (legal person)
        # Branches: entities with main entity as parent AND dora_provider_person_type not set
        subsidiaries = list(
            Entity.objects.filter(
                id__in=viewable_entities,
                parent_entity=main_entity,
                dora_provider_person_type__isnull=False,
            ).exclude(dora_provider_person_type="")
        )
        branches = list(
            Entity.objects.filter(
                id__in=viewable_entities,
                parent_entity=main_entity,
                dora_provider_person_type__isnull=True,
            )
            | Entity.objects.filter(
                id__in=viewable_entities,
                parent_entity=main_entity,
                dora_provider_person_type="",
            )
        )
        # b_01.02 includes only main entity and subsidiaries (not branches)
        entities_for_b_01_02 = [main_entity] + subsidiaries

        # Prepare contract QuerySets
        contracts = (
            Contract.objects.filter(id__in=viewable_contracts)
            .exclude(status=Contract.Status.DRAFT)
            .exclude(dora_exclude=True)
        )

        # Prepare business functions
        business_functions = Asset.objects.filter(
            id__in=viewable_assets, is_business_function=True
        )

        # Collect all assets related to business functions (including child assets)
        # This ensures that solutions linked to child assets are also captured in DORA reports
        business_function_asset_ids = set(
            business_functions.values_list("id", flat=True)
        )
        for business_function in business_functions:
            # Get all descendant (child) assets for each business function
            # Note: get_descendants() returns Asset objects, not IDs
            descendants = business_function.get_descendants()
            business_function_asset_ids.update(asset.id for asset in descendants)

        # Get all solutions related to business functions and their child assets
        # These are the ICT services that support critical business functions
        related_solutions = Solution.objects.filter(
            assets__id__in=business_function_asset_ids
        ).distinct()

        # Filter contracts to only those with solutions related to business functions
        # This subset is used for reports that focus on ICT services supporting critical functions
        # (b_02.02, b_07.01, b_99.01)
        related_solution_ids = set(related_solutions.values_list("id", flat=True))
        business_function_contracts = contracts.filter(
            solutions__id__in=related_solution_ids
        ).distinct()

        # Get export metadata (naming, identifiers)
        identifier_type = request.query_params.get("identifier_type", None)
        level = request.query_params.get("level", "IND")
        naming_convention = request.query_params.get("naming_convention", "nbb")
        try:
            export_meta = dora_export.get_dora_export_metadata(
                main_entity,
                identifier_type=identifier_type,
                level=level,
                naming_convention=naming_convention,
            )
        except ValueError:
            logger.exception("Error generating DORA export metadata")
            return Response(
                {
                    "error": "Error generating DORA export metadata. Please ensure the main entity has the required DORA metadata fields (folder_prefix, entity_id, filename)."
                },
                status=HTTP_400_BAD_REQUEST,
            )

        base_folder_name = export_meta["folder_prefix"]
        entity_id = export_meta["entity_id"]
        filename = export_meta["filename"]

        # Create zip file in memory
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
            # Generate all DORA ROI reports (with folder prefix)
            dora_export.generate_b_01_01_main_entity(
                zip_file, main_entity, base_folder_name
            )
            dora_export.generate_b_01_02_entities(
                zip_file, main_entity, entities_for_b_01_02, base_folder_name
            )
            dora_export.generate_b_01_03_branches(zip_file, branches, base_folder_name)

            dora_export.generate_b_02_01_contracts(
                zip_file, contracts, base_folder_name
            )
            dora_export.generate_b_02_02_ict_services(
                zip_file, contracts, base_folder_name, business_function_asset_ids
            )
            dora_export.generate_b_02_03_intragroup_contracts(
                zip_file, contracts, base_folder_name
            )

            dora_export.generate_b_03_01_signing_entities(
                zip_file, main_entity, contracts, base_folder_name
            )
            dora_export.generate_b_03_02_ict_providers(
                zip_file, contracts, base_folder_name
            )
            dora_export.generate_b_03_03_intragroup_providers(
                zip_file, main_entity, contracts, base_folder_name
            )

            dora_export.generate_b_04_01_service_users(
                zip_file, branches, contracts, base_folder_name
            )

            dora_export.generate_b_05_01_provider_details(
                zip_file, main_entity, contracts, base_folder_name
            )
            dora_export.generate_b_05_02_supply_chains(
                zip_file, contracts, base_folder_name
            )

            dora_export.generate_b_06_01_functions(
                zip_file, main_entity, business_functions, base_folder_name
            )

            dora_export.generate_b_07_01_assessment(
                zip_file, business_function_contracts, base_folder_name
            )

            dora_export.generate_b_99_01_aggregation(
                zip_file,
                business_function_contracts,
                business_functions,
                base_folder_name,
            )

            # Generate FilingIndicators.csv
            dora_export.generate_filing_indicators(zip_file, base_folder_name)

            # Generate parameters.csv
            dora_export.generate_parameters(
                zip_file, main_entity, base_folder_name, entity_id=entity_id
            )

            # Generate JSON metadata files
            dora_export.generate_report_package_json(zip_file, base_folder_name)
            dora_export.generate_report_json(zip_file, base_folder_name)

        # Prepare response
        zip_buffer.seek(0)

        response = HttpResponse(zip_buffer.getvalue(), content_type="application/zip")
        sanitized_filename = re.sub(r"[^\w.\-]", "_", filename)
        response["Content-Disposition"] = f'attachment; filename="{sanitized_filename}"'

        return response

    @action(detail=False, methods=["get"], name="Lint DORA ROI")
    def dora_roi_lint(self, request):
        """
        Validate DORA ROI requirements and return linting results.
        """
        from tprm import dora_linter

        if not has_dora_roi_access(request.user):
            return Response(status=HTTP_403_FORBIDDEN)

        lint_results = dora_linter.lint_dora_roi()
        return Response(lint_results)

    @action(detail=False, methods=["get"], name="Get entities graph")
    def graph(self, request):
        """
        Generate graph data for entities, showing:
        - Entity hierarchy (parent-child relationships)
        - Solutions provided by entities
        - Contracts between entities
        - Assets linked to solutions
        - Asset hierarchy (parent-child asset relationships)
        """
        # Get accessible objects for the current user
        viewable_entities = RoleAssignment.get_viewable_object_ids(request.user, Entity)
        viewable_contracts = RoleAssignment.get_viewable_object_ids(
            request.user, Contract
        )
        viewable_solutions = RoleAssignment.get_viewable_object_ids(
            request.user, Solution
        )
        viewable_assets = RoleAssignment.get_viewable_object_ids(request.user, Asset)

        # Get entities, solutions, contracts, and assets
        entities = Entity.objects.filter(id__in=viewable_entities)
        solutions = Solution.objects.filter(id__in=viewable_solutions).select_related(
            "provider_entity"
        )
        contracts = (
            Contract.objects.filter(id__in=viewable_contracts)
            .select_related("provider_entity", "beneficiary_entity")
            .prefetch_related("solutions")
        )
        assets = Asset.objects.filter(id__in=viewable_assets)

        # Build nodes and links
        nodes = []
        links = []
        categories = []
        category_map = {}
        node_index = 0

        # Create entity nodes
        entity_node_map = {}
        for entity in entities:
            nodes.append(
                {
                    "name": entity.name,
                    "category": 0,  # Entities category
                    "symbol": "roundRect",
                    "symbolSize": 35,
                    "value": f"Entity: {entity.name}",
                }
            )
            entity_node_map[entity.id] = node_index
            node_index += 1

        # Add entity hierarchy links (parent-child relationships)
        for entity in entities:
            if entity.parent_entity and entity.parent_entity.id in entity_node_map:
                links.append(
                    {
                        "source": entity_node_map[entity.parent_entity.id],
                        "target": entity_node_map[entity.id],
                        "value": "parent of",
                    }
                )

        # Create solution nodes
        solution_node_map = {}
        for solution in solutions:
            nodes.append(
                {
                    "name": solution.name,
                    "category": 1,  # Solutions category
                    "symbol": "diamond",
                    "symbolSize": 30,
                    "value": f"Solution: {solution.name}",
                }
            )
            solution_node_map[solution.id] = node_index

            # Link solution to provider entity
            if (
                solution.provider_entity
                and solution.provider_entity.id in entity_node_map
            ):
                links.append(
                    {
                        "source": entity_node_map[solution.provider_entity.id],
                        "target": node_index,
                        "value": "provides",
                    }
                )

            node_index += 1

        # Create contract nodes
        contract_node_map = {}
        for contract in contracts:
            nodes.append(
                {
                    "name": contract.name,
                    "category": 2,  # Contracts category
                    "symbol": "circle",
                    "symbolSize": 25,
                    "value": f"Contract: {contract.name}",
                }
            )
            contract_node_map[contract.id] = node_index

            # Link contract to provider entity
            if (
                contract.provider_entity
                and contract.provider_entity.id in entity_node_map
            ):
                links.append(
                    {
                        "source": entity_node_map[contract.provider_entity.id],
                        "target": node_index,
                        "value": "provider",
                    }
                )

            # Link contract to beneficiary entity
            if (
                contract.beneficiary_entity
                and contract.beneficiary_entity.id in entity_node_map
            ):
                links.append(
                    {
                        "source": node_index,
                        "target": entity_node_map[contract.beneficiary_entity.id],
                        "value": "beneficiary",
                    }
                )

            # Link contract to solutions
            for solution in contract.solutions.all():
                if solution.id in solution_node_map:
                    links.append(
                        {
                            "source": node_index,
                            "target": solution_node_map[solution.id],
                            "value": "frames",
                        }
                    )

            node_index += 1

        # Create asset nodes (only those with connections)
        asset_node_map = {}
        for asset in assets:
            # Check if asset has any connections (to solutions or other assets)
            linked_solutions = solutions.filter(assets=asset)
            parent_assets = asset.parent_assets.filter(id__in=viewable_assets)
            child_assets = assets.filter(parent_assets=asset)

            has_connections = (
                linked_solutions.exists()
                or parent_assets.exists()
                or child_assets.exists()
            )

            # Only create node if asset has connections
            if has_connections:
                nodes.append(
                    {
                        "name": asset.name,
                        "category": 3,  # Assets category
                        "symbol": "triangle",
                        "symbolSize": 20,
                        "value": f"Asset: {asset.name}",
                    }
                )
                asset_node_map[asset.id] = node_index

                # Link asset to solutions
                for solution in linked_solutions:
                    if solution.id in solution_node_map:
                        links.append(
                            {
                                "source": node_index,
                                "target": solution_node_map[solution.id],
                                "value": "uses",
                            }
                        )

                node_index += 1

        # Add asset hierarchy links (parent-child relationships)
        for asset in assets:
            if asset.id in asset_node_map:
                # Get parent assets for this asset
                parent_assets = asset.parent_assets.filter(id__in=viewable_assets)
                for parent_asset in parent_assets:
                    if parent_asset.id in asset_node_map:
                        links.append(
                            {
                                "source": asset_node_map[parent_asset.id],
                                "target": asset_node_map[asset.id],
                                "value": "relies on",
                            }
                        )

        # Define categories
        categories = [
            {"name": "Entities"},
            {"name": "Solutions"},
            {"name": "Contracts"},
            {"name": "Assets"},
        ]

        return Response(
            {
                "nodes": nodes,
                "links": links,
                "categories": categories,
                "meta": {"display_name": "Entities Graph"},
            }
        )

    @action(detail=False, methods=["get"], name="Export TPRM ecosystem")
    def export_ecosystem(self, request):
        """
        Export the TPRM ecosystem as a multi-sheet Excel file with 4 sheets
        (Entities, Solutions, Contracts, Representatives).
        """
        import pandas as pd  # imported lazily: optional/heavy dependency

        viewable_entity_ids = RoleAssignment.get_viewable_object_ids(
            request.user, Entity
        )
        viewable_solution_ids = RoleAssignment.get_viewable_object_ids(
            request.user, Solution
        )
        viewable_contract_ids = RoleAssignment.get_viewable_object_ids(
            request.user, Contract
        )
        viewable_representative_ids = RoleAssignment.get_viewable_object_ids(
            request.user, Representative
        )

        # Honor the filters/search applied on the entities list page so the
        # exported "Entities" sheet matches what the user is viewing.
        # Solutions/Contracts/Representatives stay on the IAM-scoped set, with
        # Representatives further limited to the exported entities.
        entities = self.filter_queryset(
            Entity.objects.filter(id__in=viewable_entity_ids).select_related(
                "folder", "parent_entity"
            )
        )
        solutions = Solution.objects.filter(
            id__in=viewable_solution_ids
        ).select_related("provider_entity")
        contracts = (
            Contract.objects.filter(id__in=viewable_contract_ids)
            .select_related("folder", "provider_entity")
            .prefetch_related(
                Prefetch(
                    "solutions",
                    queryset=Solution.objects.filter(id__in=viewable_solution_ids),
                )
            )
        )
        representatives = Representative.objects.filter(
            id__in=viewable_representative_ids,
            entity__in=entities,
        ).select_related("entity")

        esc = escape_excel_formula

        # --- Entities sheet ---
        entities_rows = []
        for entity in entities:
            legal = entity.legal_identifiers or {}
            entities_rows.append(
                {
                    "ref_id": esc(entity.ref_id),
                    "name": esc(entity.name),
                    "description": esc(entity.description),
                    "mission": esc(entity.mission),
                    "country": esc(entity.country),
                    "currency": esc(entity.currency),
                    "parent_entity_ref_id": (
                        esc(entity.parent_entity.ref_id) if entity.parent_entity else ""
                    ),
                    "dependency": entity.default_dependency,
                    "penetration": entity.default_penetration,
                    "maturity": entity.default_maturity,
                    "trust": entity.default_trust,
                    "domain": esc(entity.folder.name) if entity.folder else "",
                    "lei": esc(legal.get("LEI", "")),
                    "euid": esc(legal.get("EUID", "")),
                    "vat": esc(legal.get("VAT", "")),
                    "duns": esc(legal.get("DUNS", "")),
                }
            )

        # --- Solutions sheet ---
        solutions_rows = []
        for solution in solutions:
            solutions_rows.append(
                {
                    "ref_id": esc(solution.ref_id),
                    "name": esc(solution.name),
                    "description": esc(solution.description),
                    "provider_entity_ref_id": esc(solution.provider_entity.ref_id),
                    "provider": esc(solution.provider_entity.name),
                    "criticality": solution.criticality,
                }
            )

        # --- Contracts sheet ---
        contracts_rows = []
        for contract in contracts:
            contract_solutions = list(contract.solutions.all())
            solution_ref_ids = "\n".join(
                esc(s.ref_id) for s in contract_solutions if s.ref_id
            )
            solution_names = "\n".join(
                esc(s.name) for s in contract_solutions if s.name
            )
            contracts_rows.append(
                {
                    "ref_id": esc(contract.ref_id),
                    "name": esc(contract.name),
                    "description": esc(contract.description),
                    "provider_entity_ref_id": (
                        esc(contract.provider_entity.ref_id)
                        if contract.provider_entity
                        else ""
                    ),
                    "provider": (
                        esc(contract.provider_entity.name)
                        if contract.provider_entity
                        else ""
                    ),
                    "solution_ref_id": solution_ref_ids,
                    "solution": solution_names,
                    "status": contract.status,
                    "start_date": (
                        contract.start_date.isoformat() if contract.start_date else ""
                    ),
                    "end_date": (
                        contract.end_date.isoformat() if contract.end_date else ""
                    ),
                    "annual_expense": (
                        contract.annual_expense
                        if contract.annual_expense is not None
                        else ""
                    ),
                    "currency": esc(contract.currency),
                    "domain": esc(contract.folder.name) if contract.folder else "",
                }
            )

        # --- Representatives sheet ---
        representatives_rows = []
        for representative in representatives:
            representatives_rows.append(
                {
                    "email": esc(representative.email),
                    "first_name": esc(representative.first_name),
                    "last_name": esc(representative.last_name),
                    "description": esc(representative.description),
                    "phone": esc(representative.phone),
                    "role": esc(representative.role),
                    "provider_entity_ref_id": esc(representative.entity.ref_id),
                    "provider": esc(representative.entity.name),
                }
            )

        entity_columns = [
            "ref_id",
            "name",
            "description",
            "mission",
            "country",
            "currency",
            "parent_entity_ref_id",
            "dependency",
            "penetration",
            "maturity",
            "trust",
            "domain",
            "lei",
            "euid",
            "vat",
            "duns",
        ]
        solution_columns = [
            "ref_id",
            "name",
            "description",
            "provider_entity_ref_id",
            "provider",
            "criticality",
        ]
        contract_columns = [
            "ref_id",
            "name",
            "description",
            "provider_entity_ref_id",
            "provider",
            "solution_ref_id",
            "solution",
            "status",
            "start_date",
            "end_date",
            "annual_expense",
            "currency",
            "domain",
        ]

        representative_columns = [
            "email",
            "first_name",
            "last_name",
            "description",
            "phone",
            "role",
            "provider_entity_ref_id",
            "provider",
        ]

        buffer = io.BytesIO()
        with pd.ExcelWriter(buffer, engine="openpyxl") as writer:
            pd.DataFrame(entities_rows, columns=entity_columns).to_excel(
                writer, index=False, sheet_name="Entities"
            )
            pd.DataFrame(solutions_rows, columns=solution_columns).to_excel(
                writer, index=False, sheet_name="Solutions"
            )
            pd.DataFrame(contracts_rows, columns=contract_columns).to_excel(
                writer, index=False, sheet_name="Contracts"
            )
            pd.DataFrame(representatives_rows, columns=representative_columns).to_excel(
                writer, index=False, sheet_name="Representatives"
            )

        buffer.seek(0)
        response = HttpResponse(
            buffer.getvalue(),
            content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )
        response["Content-Disposition"] = (
            'attachment; filename="tprm_ecosystem_export.xlsx"'
        )
        return response

    @action(detail=False, name="Get country choices")
    def country(self, request):
        return Response(dict(COUNTRY_CHOICES))

    @action(detail=False, name="Get currency choices")
    def currency(self, request):
        return Response(dict(CURRENCY_CHOICES))

    @action(detail=False, name="Get DORA entity type choices")
    def dora_entity_type(self, request):
        return Response(dict(DORA_ENTITY_TYPE_CHOICES))

    @action(detail=False, name="Get DORA entity hierarchy choices")
    def dora_entity_hierarchy(self, request):
        return Response(dict(DORA_ENTITY_HIERARCHY_CHOICES))

    @action(detail=False, name="Get DORA provider person type choices")
    def dora_provider_person_type(self, request):
        return Response(dict(DORA_PROVIDER_PERSON_TYPE_CHOICES))

    @action(detail=False, methods=["post"], url_path="batch-create")
    def batch_create(self, request):
        """
        Batch create multiple entities from a text list.
        Expected format:
        {
            "entities_text": "Entity 1\\nEntity 2\\nREF-001:Entity 3",
            "folder": "folder-uuid"
        }
        Lines can optionally have a ref_id prefix (REF-001:Entity Name).
        Entities with the same name in the folder will be skipped.
        """
        from rest_framework import status
        from tprm.serializers import EntityWriteSerializer

        try:
            entities_text = request.data.get("entities_text", "")
            folder_id = request.data.get("folder")

            if not entities_text:
                return Response(
                    {"error": "entities_text is required"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            if not folder_id:
                return Response(
                    {"error": "folder is required"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            try:
                folder = Folder.objects.get(id=uuid.UUID(str(folder_id)))
            except ValueError, AttributeError, Folder.DoesNotExist:
                return Response(
                    {"error": "Folder not found"},
                    status=status.HTTP_404_NOT_FOUND,
                )

            # Parse the entities text
            lines = [line.strip() for line in entities_text.split("\n") if line.strip()]
            created_entities = []
            skipped_entities = []
            errors = []

            for line in lines:
                # Check for ref_id prefix (REF-001:Entity Name)
                ref_id = ""
                entity_name = line

                if ":" in line:
                    parts = line.split(":", 1)
                    if len(parts) == 2 and parts[0].strip():
                        ref_id = parts[0].strip()
                        entity_name = parts[1].strip()

                if not entity_name:
                    errors.append({"line": line, "error": "Empty entity name"})
                    continue

                # Check if entity already exists in the folder
                existing_entity = Entity.objects.filter(
                    name=entity_name, folder=folder
                ).first()

                if existing_entity:
                    # Skip existing entity
                    skipped_entities.append(
                        {
                            "id": str(existing_entity.id),
                            "name": existing_entity.name,
                            "ref_id": existing_entity.ref_id,
                        }
                    )
                    continue

                # Create new entity using the serializer to respect IAM
                entity_data = {
                    "name": entity_name,
                    "folder": str(folder.id),
                }

                if ref_id:
                    entity_data["ref_id"] = ref_id

                serializer = EntityWriteSerializer(
                    data=entity_data, context={"request": request}
                )

                if serializer.is_valid():
                    try:
                        entity = serializer.save()
                    except PermissionDenied as e:
                        return Response(
                            {"error": e.detail},
                            status=status.HTTP_403_FORBIDDEN,
                        )

                    created_entities.append(
                        {
                            "id": str(entity.id),
                            "name": entity.name,
                            "ref_id": entity.ref_id,
                        }
                    )
                else:
                    errors.append(
                        {
                            "line": line,
                            "errors": serializer.errors,
                        }
                    )

            return Response(
                {
                    "created": len(created_entities),
                    "skipped": len(skipped_entities),
                    "entities": created_entities,
                    "skipped_entities": skipped_entities,
                    "errors": errors,
                },
                status=status.HTTP_200_OK,
            )

        except Exception as e:
            logger.error("Error in batch create entities", error=str(e))
            return Response(
                {"error": f"An error occurred: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class EntityAssessmentViewSet(BaseModelViewSet):
    """
    API endpoint that allows entity assessments to be viewed or edited.
    """

    model = EntityAssessment
    filterset_fields = [
        "name",
        "status",
        "perimeter",
        "perimeter__folder",
        "folder",
        "authors",
        "entity",
        "criticality",
        "conclusion",
        "genericcollection",
    ]

    @staticmethod
    def _assert_enclave_contains_only_iam_scaffolding(
        folder, *, expected_respondent_user_ids, user
    ):
        """Fail closed before cascading an otherwise empty owned enclave."""

        from core.utils import RoleCodename, UserGroupCodename

        try:
            lock_and_assert_no_tprm_idp_group_inheritance(
                enclave_folder_ids=(folder.id,)
            )
        except ManagedTprmRespondentIamError as exc:
            raise PermissionDenied(MANAGED_TPRM_RESPONDENT_IAM_ERROR) from exc

        groups = list(
            UserGroup.objects.select_for_update(of=("self",))
            .filter(folder_id=folder.id)
            .order_by("id")
        )
        group_ids = {group.id for group in groups}
        assignments = list(
            RoleAssignment.objects.select_for_update(of=("self",))
            .filter(Q(folder_id=folder.id) | Q(user_group_id__in=group_ids))
            .select_related("role", "user_group")
            .order_by("id")
        )
        if len(groups) > 1 or len(assignments) != len(groups):
            raise PermissionDenied("The audit enclave contains unrelated IAM objects.")
        if groups:
            group = groups[0]
            assignment = assignments[0]
            if (
                not group.builtin
                or group.name != UserGroupCodename.THIRD_PARTY_RESPONDENT.value
                or not assignment.builtin
                or assignment.user_id is not None
                or assignment.user_group_id != group.id
                or assignment.folder_id != folder.id
                or assignment.role.name != RoleCodename.THIRD_PARTY_RESPONDENT.value
                or not assignment.is_recursive
                or set(assignment.perimeter_folders.values_list("id", flat=True))
                != {folder.id}
            ):
                raise PermissionDenied(
                    "The audit enclave contains unrelated IAM objects."
                )

            membership_field = User._meta.get_field("user_groups")
            membership_through = membership_field.remote_field.through
            membership_source = membership_field.m2m_field_name()
            membership_target = membership_field.m2m_reverse_field_name()
            membership_filter = {f"{membership_target}_id": group.id}
            membership_rows = list(
                membership_through.objects.select_for_update()
                .filter(**membership_filter)
                .order_by("pk")
            )
            member_ids = {
                getattr(row, f"{membership_source}_id") for row in membership_rows
            }
            if member_ids != set(expected_respondent_user_ids):
                raise PermissionDenied(
                    "The audit respondent membership is inconsistent."
                )
            locked_user_ids = set(
                User.objects.select_for_update(of=("self",))
                .filter(id__in=member_ids)
                .values_list("id", flat=True)
            )
            try:
                visible_user_ids = set(
                    RoleAssignment.get_viewable_object_ids(user, User)
                )
            except (NotImplementedError, Permission.DoesNotExist):
                visible_user_ids = set()
            if locked_user_ids != member_ids or not member_ids.issubset(
                visible_user_ids
            ):
                raise PermissionDenied(
                    "The audit respondent membership is unavailable."
                )
        elif expected_respondent_user_ids:
            raise PermissionDenied("The audit respondent membership is missing.")

        perimeter_field = RoleAssignment._meta.get_field("perimeter_folders")
        perimeter_through = perimeter_field.remote_field.through
        perimeter_source = perimeter_field.m2m_field_name()
        perimeter_target = perimeter_field.m2m_reverse_field_name()
        perimeter_filter = {f"{perimeter_target}_id": folder.id}
        perimeter_rows = list(
            perimeter_through.objects.select_for_update()
            .filter(**perimeter_filter)
            .order_by("pk")
        )
        perimeter_assignment_ids = {
            getattr(row, f"{perimeter_source}_id") for row in perimeter_rows
        }
        if perimeter_assignment_ids != {assignment.id for assignment in assignments}:
            # In particular, never cascade a Folder merely because an external
            # RoleAssignment happens to point at it through perimeter_folders.
            raise PermissionDenied(
                "The audit enclave has external IAM perimeter links."
            )

        allowed_labels = {"iam.usergroup", "iam.roleassignment"}
        for relation in Folder._meta.related_objects:
            related_model = relation.related_model
            if relation.many_to_many:
                field = relation.field
                relation_key = (related_model._meta.label_lower, field.name)
                if relation_key in {
                    ("iam.folder", "descendants"),
                    ("iam.roleassignment", "perimeter_folders"),
                }:
                    continue
                through = field.remote_field.through
                target_name = field.m2m_reverse_field_name()
                rows = list(
                    through.objects.select_for_update()
                    .filter(**{f"{target_name}_id": folder.id})
                    .order_by("pk")
                )
                if rows:
                    raise PermissionDenied(
                        "The audit enclave has unrelated many-to-many links."
                    )
                continue
            if (
                related_model._meta.auto_created
                or related_model._meta.label_lower in allowed_labels
            ):
                continue
            accessor = relation.get_accessor_name()
            if not accessor:
                continue
            try:
                related = getattr(folder, accessor, None)
            except related_model.DoesNotExist:
                continue
            if related is None:
                continue
            if hasattr(related, "exists"):
                has_rows = related.exists()
            else:
                has_rows = True
            if has_rows:
                raise PermissionDenied(
                    "The audit enclave contains unrelated governed objects."
                )

    @staticmethod
    def _assert_complete_linked_audit_read_access(user, audit):
        """Prove the complete linked-audit projection, not a redacted subset."""

        from core.compliance_deletion import (
            assert_complete_compliance_assessment_deletion_access,
        )

        return assert_complete_compliance_assessment_deletion_access(user, audit)

    @staticmethod
    def _lock_linked_audit_deletion_graph(
        *,
        user,
        audit,
        entity_assessment,
        allowed_reverse_owner_ids_by_relation=None,
    ):
        """Delegate the exact-EA path to the core-owned deletion closure."""

        from core.compliance_deletion import (
            lock_compliance_assessment_deletion_graph,
        )

        return lock_compliance_assessment_deletion_graph(
            user=user,
            audit=audit,
            entity_assessment=entity_assessment,
            allowed_reverse_owner_ids_by_relation=(
                allowed_reverse_owner_ids_by_relation
            ),
            complete_access_check=(
                EntityAssessmentViewSet._assert_complete_linked_audit_read_access
            ),
        )

    @transaction.atomic
    def perform_destroy(self, instance):
        """Delete an EA and its owned enclave through one governed path.

        ``perform_destroy`` is shared by the normal detail endpoint and the
        generic batch endpoint.  Authorization must precede deleting the
        enclave because that folder cascades the linked audit and its children.
        """

        from core.utils import has_full_view_compliance_assessment
        from core.models import ValidationFlow
        from core.views import (
            _assert_assessment_mutation_state,
            _assert_object_action_permission,
            dispatch_webhook_event,
        )
        from pmbok.models import GenericCollection

        Folder._lock_folder_tree()
        expected_folder_id = instance.folder_id
        expected_audit_id = instance.compliance_assessment_id

        expected_audit_folder_id = None
        if expected_audit_id is not None:
            expected_audit_folder_id = (
                ComplianceAssessment.objects.filter(id=expected_audit_id)
                .values_list("folder_id", flat=True)
                .first()
            )
            if expected_audit_folder_id is None:
                raise PermissionDenied("The linked audit is unavailable.")

        def reverse_owner_snapshot(owner_model, field_name, target_id):
            field = owner_model._meta.get_field(field_name)
            through = field.remote_field.through
            source_name = field.m2m_field_name()
            target_name = field.m2m_reverse_field_name()
            row_filter = {f"{target_name}_id": target_id}
            owner_ids = set(
                through.objects.filter(**row_filter).values_list(
                    f"{source_name}_id", flat=True
                )
            )
            return through, row_filter, source_name, owner_ids

        owner_snapshots = [
            (
                GenericCollection,
                reverse_owner_snapshot(
                    GenericCollection, "entity_assessments", instance.id
                ),
            ),
            (
                ValidationFlow,
                reverse_owner_snapshot(
                    ValidationFlow, "entity_assessments", instance.id
                ),
            ),
        ]
        if expected_audit_id is not None:
            owner_snapshots.extend(
                [
                    (
                        GenericCollection,
                        reverse_owner_snapshot(
                            GenericCollection,
                            "compliance_assessments",
                            expected_audit_id,
                        ),
                    ),
                    (
                        ValidationFlow,
                        reverse_owner_snapshot(
                            ValidationFlow,
                            "compliance_assessments",
                            expected_audit_id,
                        ),
                    ),
                ]
            )

        owner_ids_by_model = {GenericCollection: set(), ValidationFlow: set()}
        for owner_model, (_through, _filter, _source, owner_ids) in owner_snapshots:
            owner_ids_by_model[owner_model].update(owner_ids)

        owner_folder_snapshots = {}
        for owner_model, owner_ids in owner_ids_by_model.items():
            folder_by_id = dict(
                owner_model.objects.filter(id__in=owner_ids).values_list(
                    "id", "folder_id"
                )
            )
            if set(folder_by_id) != owner_ids or any(
                folder_id is None for folder_id in folder_by_id.values()
            ):
                raise PermissionDenied(
                    "An assessment relationship owner is unavailable."
                )
            owner_folder_snapshots[owner_model] = folder_by_id

        folder_ids = {expected_folder_id, expected_audit_folder_id}
        for folder_by_id in owner_folder_snapshots.values():
            folder_ids.update(folder_by_id.values())
        folder_ids.discard(None)
        locked_folders = {
            folder.id: folder
            for folder in Folder.objects.select_for_update(of=("self",))
            .filter(id__in=folder_ids)
            .order_by("id")
        }
        if set(locked_folders) != folder_ids:
            raise PermissionDenied("An assessment owner is unavailable.")

        locked_owners = {}
        for owner_model in sorted(
            owner_ids_by_model, key=lambda model: model._meta.label_lower
        ):
            owner_ids = owner_ids_by_model[owner_model]
            rows = {
                row.id: row
                for row in owner_model.objects.select_for_update(of=("self",))
                .filter(id__in=owner_ids)
                .order_by("id")
            }
            if set(rows) != owner_ids or any(
                row.folder_id != owner_folder_snapshots[owner_model][row.id]
                for row in rows.values()
            ):
                raise PermissionDenied(
                    "An assessment relationship owner changed; retry."
                )
            locked_owners[owner_model] = rows

        locked_audit = None
        if expected_audit_id is not None:
            locked_audit = get_object_or_404(
                ComplianceAssessment.objects.select_for_update(of=("self",)),
                id=expected_audit_id,
            )
            if locked_audit.folder_id != expected_audit_folder_id:
                raise PermissionDenied("The linked audit owner changed; retry.")
        locked_instance = get_object_or_404(
            EntityAssessment.objects.select_for_update(of=("self",)),
            id=instance.id,
        )
        if (
            locked_instance.folder_id != expected_folder_id
            or locked_instance.compliance_assessment_id != expected_audit_id
        ):
            raise PermissionDenied("The assessment owner changed; retry.")

        for _owner_model, snapshot in sorted(
            owner_snapshots, key=lambda item: item[1][0]._meta.db_table
        ):
            through, row_filter, source_name, expected_owner_ids = snapshot
            list(
                through.objects.select_for_update().filter(**row_filter).order_by("pk")
            )
            current_owner_ids = set(
                through.objects.filter(**row_filter).values_list(
                    f"{source_name}_id", flat=True
                )
            )
            if current_owner_ids != expected_owner_ids:
                raise PermissionDenied(
                    "Assessment relationship ownership changed; retry."
                )

        generic_collection_ids = owner_ids_by_model[GenericCollection]
        if generic_collection_ids:
            visible_collection_ids = set(
                RoleAssignment.get_viewable_object_ids(
                    self.request.user, GenericCollection
                )
            )
            if not generic_collection_ids.issubset(visible_collection_ids):
                raise PermissionDenied(
                    "One or more assessment collections are unavailable."
                )
            for collection in locked_owners[GenericCollection].values():
                collection.folder = locked_folders[collection.folder_id]
                _assert_object_action_permission(
                    user=self.request.user,
                    instance=collection,
                    action="change",
                )

        if owner_ids_by_model[ValidationFlow]:
            # ValidationFlow owns its status transition and approver history.
            # Deleting an assessment must never silently rewrite that workflow,
            # including terminal/accepted records; unlink it through the
            # governed validation-flow API first.
            raise PermissionDenied(
                "The assessment is linked to a validation flow; unlink it "
                "through the validation workflow before deletion."
            )

        if locked_instance.folder_id not in locked_folders:
            raise PermissionDenied("The assessment owner is unavailable.")
        locked_instance.folder = locked_folders[locked_instance.folder_id]
        _assert_object_action_permission(
            user=self.request.user,
            instance=locked_instance,
            action="delete",
        )
        # EntityAssessment inherits the same authoritative lifecycle fields as
        # ComplianceAssessment.  Reprove its state after acquiring the row
        # lock so both standalone and linked deletion paths fail closed.
        _assert_assessment_mutation_state(locked_instance)

        from tprm.deletion_authority import lock_entity_assessment_deletion_graph

        lock_entity_assessment_deletion_graph(
            user=self.request.user,
            entity_assessment=locked_instance,
            allowed_reverse_owner_ids_by_relation={
                (
                    "pmbok.genericcollection",
                    "entity_assessments",
                ): owner_ids_by_model[GenericCollection],
            },
        )
        expected_respondent_user_ids = set(
            locked_instance.representatives.values_list("id", flat=True)
        )

        if locked_audit is not None:
            if locked_audit.folder_id not in locked_folders:
                raise PermissionDenied("The audit owner is unavailable.")
            locked_audit.folder = locked_folders[locked_audit.folder_id]
            if locked_audit.folder.content_type == Folder.ContentType.ENCLAVE:
                if locked_audit.folder.parent_folder_id != locked_instance.folder_id:
                    raise PermissionDenied("The linked audit owner is inconsistent.")
                enclave_audit_ids = set(
                    ComplianceAssessment.objects.select_for_update(of=("self",))
                    .filter(folder_id=locked_audit.folder_id)
                    .order_by("id")
                    .values_list("id", flat=True)
                )
                if enclave_audit_ids != {locked_audit.id}:
                    raise PermissionDenied("The audit enclave is not exclusive.")
                if (
                    EntityAssessment.objects.filter(
                        compliance_assessment_id=locked_audit.id
                    )
                    .exclude(id=locked_instance.id)
                    .exists()
                ):
                    raise PermissionDenied(
                        "The audit is linked to another entity assessment."
                    )
                if not has_full_view_compliance_assessment(
                    self.request.user, locked_audit
                ):
                    raise PermissionDenied(
                        "Complete audit data is unavailable for this caller."
                    )
                _assert_assessment_mutation_state(locked_audit)
                _assert_object_action_permission(
                    user=self.request.user,
                    instance=locked_audit,
                    action="delete",
                )
                _assert_object_action_permission(
                    user=self.request.user,
                    instance=locked_audit.folder,
                    action="delete",
                )
                self._lock_linked_audit_deletion_graph(
                    user=self.request.user,
                    audit=locked_audit,
                    entity_assessment=locked_instance,
                    allowed_reverse_owner_ids_by_relation={
                        (
                            "tprm.entityassessment",
                            "compliance_assessment",
                        ): {locked_instance.id},
                        (
                            "pmbok.genericcollection",
                            "compliance_assessments",
                        ): owner_ids_by_model[GenericCollection],
                    },
                )
                logger.info(
                    "deleting_compliance_assessment_folder",
                    folder_id=str(locked_audit.folder_id),
                    content_type=str(locked_audit.folder.content_type),
                )
                enclave = locked_audit.folder
                locked_audit.delete()
                serializer_class = self.get_serializer_class(action="destroy")
                serializer = serializer_class(
                    locked_instance,
                    context=self.get_serializer_context(),
                )
                serializer.delete(locked_instance)
                self._assert_enclave_contains_only_iam_scaffolding(
                    enclave,
                    expected_respondent_user_ids=expected_respondent_user_ids,
                    user=self.request.user,
                )
                enclave.delete()
                try:
                    dispatch_webhook_event(locked_instance, "deleted")
                except Exception:
                    logger.error("Webhook dispatch failed on delete", exc_info=True)
                return None
            else:
                raise PermissionDenied("The linked audit owner is inconsistent.")

        return super().perform_destroy(locked_instance)

    def batch_action(self, request):
        if request.data.get("action") in {"add_m2m", "remove_m2m"}:
            return Response(
                {
                    "error": (
                        "Entity assessment relationships require exact "
                        "change_m2m replacement semantics."
                    )
                },
                status=HTTP_400_BAD_REQUEST,
            )
        return super().batch_action(request)

    @action(detail=False, name="Get status choices")
    def status(self, request):
        return Response(dict(EntityAssessment.Status.choices))

    @action(detail=False, name="Get conclusion choices")
    def conclusion(self, request):
        return Response(dict(EntityAssessment.Conclusion.choices))

    @action(detail=False, name="Get TPRM metrics")
    def metrics(self, request):
        def visible_ids(model):
            try:
                return set(RoleAssignment.get_viewable_object_ids(request.user, model))
            except (NotImplementedError, Permission.DoesNotExist):
                return set()

        viewable_items = visible_ids(EntityAssessment)
        visible_entities = visible_ids(Entity)
        visible_folders = visible_ids(Folder)
        visible_solutions = visible_ids(Solution)
        visible_assessments = visible_ids(ComplianceAssessment)
        visible_frameworks = visible_ids(Framework)
        visible_actors = visible_ids(Actor)
        visible_users = visible_ids(User)
        visible_teams = visible_ids(Team)

        queryset = (
            EntityAssessment.objects.filter(id__in=viewable_items)
            .select_related("folder", "entity", "compliance_assessment__framework")
            .prefetch_related(
                "solutions",
                Prefetch(
                    "reviewers",
                    queryset=Actor.objects.select_related("user", "team", "entity"),
                ),
            )
            .order_by("id")
        )
        assessments_data = []
        for ea in queryset:
            folder = ea.folder
            solutions = list(ea.solutions.all())
            solution_ids = {solution.id for solution in solutions}
            reviewers = list(ea.reviewers.all())
            reviewer_ids = {reviewer.id for reviewer in reviewers}

            # This endpoint returns an aggregate row, not a sparse object
            # serializer.  Returning placeholders for hidden relations still
            # reveals that an assessment/audit exists and lets callers compare
            # hidden progress over time.  Admit the row only when every carrier
            # used by the projection is independently visible.
            if (
                folder is None
                or folder.id not in visible_folders
                or ea.entity_id not in visible_entities
                or not solution_ids.issubset(visible_solutions)
            ):
                continue

            audit = ea.compliance_assessment
            complete_audit_visible = False
            if audit is not None:
                if audit.id not in visible_assessments:
                    continue
                try:
                    self._assert_complete_linked_audit_read_access(request.user, audit)
                except (PermissionDenied, NotImplementedError, Permission.DoesNotExist):
                    continue
                else:
                    complete_audit_visible = True

            provider = ea.entity.name
            solution_names = ",".join(solution.name for solution in solutions)
            reviewer_carriers_visible = all(
                (reviewer.user_id is not None and reviewer.user_id in visible_users)
                or (reviewer.team_id is not None and reviewer.team_id in visible_teams)
                or (
                    reviewer.entity_id is not None
                    and reviewer.entity_id in visible_entities
                )
                for reviewer in reviewers
            )
            if (
                not reviewer_ids.issubset(visible_actors)
                or not reviewer_carriers_visible
            ):
                continue
            reviewer_names = ",".join(str(reviewer.specific) for reviewer in reviewers)

            baseline = "-"
            if complete_audit_visible:
                if audit.framework_id not in visible_frameworks:
                    continue
                baseline = audit.framework.name
            assessments_data.append(
                {
                    "entity_assessment_id": ea.id,
                    "provider": provider,
                    "folder_id": (str(folder.id)),
                    "folder_name": (folder.name),
                    "solutions": solution_names,
                    "baseline": baseline,
                    "due_date": (
                        ea.due_date.strftime("%Y-%m-%d") if ea.due_date else "-"
                    ),
                    "last_update": (
                        ea.updated_at.strftime("%Y-%m-%d") if ea.updated_at else "-"
                    ),
                    "conclusion": ea.conclusion or "ongoing",
                    "compliance_assessment_id": (
                        audit.id if complete_audit_visible else "#"
                    ),
                    "reviewers": reviewer_names,
                    "observation": ea.observation or "-",
                    "has_questions": (
                        audit.has_questions if complete_audit_visible else False
                    ),
                    "completion": (
                        audit.answers_progress if complete_audit_visible else 0
                    ),
                    "review_progress": (
                        audit.progress if complete_audit_visible else 0
                    ),
                }
            )

        return Response(assessments_data)


class RepresentativeViewSet(ExportMixin, BaseModelViewSet):
    """
    API endpoint that allows representatives to be viewed or edited.
    """

    model = Representative
    export_config = {
        "filename": "representatives_export",
        "fields": {
            "email": {"source": "email", "label": "email", "escape": True},
            "first_name": {
                "source": "first_name",
                "label": "first_name",
                "escape": True,
            },
            "last_name": {
                "source": "last_name",
                "label": "last_name",
                "escape": True,
            },
            "description": {
                "source": "description",
                "label": "description",
                "escape": True,
            },
            "phone": {"source": "phone", "label": "phone", "escape": True},
            "role": {"source": "role", "label": "role", "escape": True},
            "provider_entity_ref_id": {
                "source": "entity.ref_id",
                "label": "provider_entity_ref_id",
                "escape": True,
            },
            "provider": {
                "source": "entity.name",
                "label": "provider",
                "escape": True,
            },
        },
        "select_related": ["entity"],
        "wrap_columns": ["first_name", "last_name", "description", "role"],
    }
    filterset_fields = ["entity", "ref_id", "filtering_labels"]
    search_fields = ["email"]

    def get_queryset(self):
        # folder is serialized via source="entity.folder"; pull it in one join
        return super().get_queryset().select_related("entity__folder")


class SolutionViewSet(ExportMixin, BaseModelViewSet):
    """
    API endpoint that allows solutions to be viewed or edited.
    """

    model = Solution
    export_config = {
        "filename": "solutions_export",
        "fields": {
            "ref_id": {"source": "ref_id", "label": "ref_id", "escape": True},
            "name": {"source": "name", "label": "name", "escape": True},
            "description": {
                "source": "description",
                "label": "description",
                "escape": True,
            },
            "provider_entity_ref_id": {
                "source": "provider_entity.ref_id",
                "label": "provider_entity_ref_id",
                "escape": True,
            },
            "provider_entity": {
                "source": "provider_entity.name",
                "label": "provider",
                "escape": True,
            },
            "criticality": {"source": "criticality", "label": "criticality"},
        },
        "select_related": ["provider_entity"],
        "wrap_columns": ["name", "description"],
    }
    filterset_fields = [
        "name",
        "ref_id",
        "is_active",
        "provider_entity",
        "assets",
        "criticality",
        "contracts",
        "owner",
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
        "filtering_labels",
    ]

    def get_queryset(self):
        # folder is serialized via source="provider_entity.folder"; pull it in one join
        return super().get_queryset().select_related("provider_entity__folder")

    @action(detail=False, name="Get data location storage choices")
    def data_location_storage(self, request):
        return Response(dict(COUNTRY_CHOICES))

    @action(detail=False, name="Get data location processing choices")
    def data_location_processing(self, request):
        return Response(dict(COUNTRY_CHOICES))

    @action(detail=False, name="Get data sensitiveness choices")
    def dora_data_sensitiveness(self, request):
        return Response(dict(DORA_SENSITIVENESS_CHOICES))

    @action(detail=False, name="Get reliance level choices")
    def dora_reliance_level(self, request):
        return Response(dict(DORA_RELIANCE_CHOICES))

    @action(detail=False, name="Get substitutability choices")
    def dora_substitutability(self, request):
        return Response(dict(DORA_SUBSTITUTABILITY_CHOICES))

    @action(detail=False, name="Get non-substitutability reason choices")
    def dora_non_substitutability_reason(self, request):
        return Response(dict(DORA_NON_SUBSTITUTABILITY_REASON_CHOICES))

    @action(detail=False, name="Get exit plan choices")
    def dora_has_exit_plan(self, request):
        return Response(dict(DORA_BINARY_CHOICES))

    @action(detail=False, name="Get reintegration possibility choices")
    def dora_reintegration_possibility(self, request):
        return Response(dict(DORA_REINTEGRATION_POSSIBILITY_CHOICES))

    @action(detail=False, name="Get discontinuing impact choices")
    def dora_discontinuing_impact(self, request):
        return Response(dict(DORA_DISCONTINUING_IMPACT_CHOICES))

    @action(detail=False, name="Get alternative providers identified choices")
    def dora_alternative_providers_identified(self, request):
        return Response(dict(DORA_YES_NO_ASSESSMENT_CHOICES))

    def perform_create(self, serializer):
        serializer.save()
        solution = serializer.instance
        solution.recipient_entity = Entity.objects.get(builtin=True)
        solution.save()

    @action(detail=False, name="Get DORA ICT service type choices")
    def dora_ict_service_type(self, request):
        return Response(dict(DORA_ICT_SERVICE_CHOICES))


class ContractViewSet(ExportMixin, BaseModelViewSet):
    """
    API endpoint that allows contracts to be viewed or edited.
    """

    model = Contract
    export_config = {
        "filename": "contracts_export",
        "fields": {
            "ref_id": {"source": "ref_id", "label": "ref_id", "escape": True},
            "name": {"source": "name", "label": "name", "escape": True},
            "description": {
                "source": "description",
                "label": "description",
                "escape": True,
            },
            "provider_entity_ref_id": {
                "source": "provider_entity.ref_id",
                "label": "provider_entity_ref_id",
                "escape": True,
            },
            "provider_entity": {
                "source": "provider_entity.name",
                "label": "provider",
                "escape": True,
            },
            "solution_ref_id": {
                "source": "solutions",
                "label": "solution_ref_id",
                "format": lambda qs: "\n".join(s.ref_id for s in qs.all() if s.ref_id),
                "escape": True,
            },
            "solution": {
                "source": "solutions",
                "label": "solution",
                "format": lambda qs: "\n".join(s.name for s in qs.all() if s.name),
                "escape": True,
            },
            "status": {"source": "status", "label": "status"},
            "start_date": {"source": "start_date", "label": "start_date"},
            "end_date": {"source": "end_date", "label": "end_date"},
            "annual_expense": {"source": "annual_expense", "label": "annual_expense"},
            "currency": {"source": "currency", "label": "currency"},
            "domain": {"source": "folder.name", "label": "domain", "escape": True},
        },
        "select_related": ["folder", "provider_entity"],
        "prefetch_related": ["solutions"],
        "wrap_columns": ["name", "description"],
    }
    filterset_fields = [
        "name",
        "folder",
        "provider_entity",
        "beneficiary_entity",
        "solutions",
        "status",
        "owner",
        "dora_contractual_arrangement",
        "currency",
        "termination_reason",
        "is_intragroup",
        "overarching_contract",
        "governing_law_country",
        "notice_period_entity",
        "notice_period_provider",
        "end_date",
    ]

    @action(detail=False, name="Get status choices")
    def status(self, request):
        return Response(dict(Contract.Status.choices))

    @action(detail=False, name="Get currency choices")
    def currency(self, request):
        return Response(dict(CURRENCY_CHOICES))

    @action(detail=False, name="Get DORA contractual arrangement choices")
    def dora_contractual_arrangement(self, request):
        return Response(dict(DORA_CONTRACTUAL_ARRANGEMENT_CHOICES))

    @action(detail=False, name="Get termination reason choices")
    def termination_reason(self, request):
        return Response(dict(TERMINATION_REASON_CHOICES))

    @action(detail=False, name="Get governing law country choices")
    def governing_law_country(self, request):
        return Response(dict(COUNTRY_CHOICES))
