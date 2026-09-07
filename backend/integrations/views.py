import hashlib
import json
import uuid

import structlog
from core.views import BaseModelViewSet
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.db import transaction
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django_filters.rest_framework import DjangoFilterBackend
from iam.models import Folder, RoleAssignment
from rest_framework import filters, generics, status
from rest_framework.decorators import action
from rest_framework.exceptions import APIException, PermissionDenied, ValidationError
from rest_framework.response import Response
from rest_framework.views import APIView
from webhooks.service import dispatch_webhook_event

from integrations.capabilities import (
    authority_hmac,
    configuration_authority_hmac,
    model_row_authority_hmac,
    persist_webhook_sync_job,
)
from integrations.models import (
    IntegrationConfiguration,
    IntegrationProvider,
    IntegrationSyncJob,
    SyncEvent,
    SyncMapping,
)
from integrations.registry import IntegrationRegistry
from integrations.remote_ids import InvalidRemoteIdentifier, normalize_remote_id
from integrations.serializers import (
    ConnectionTestSerializer,
    IntegrationProviderSerializer,
    SyncMappingSerializer,
    _bind_configuration_mutation_authority,
)

logger = structlog.get_logger(__name__)


class SyncMappingBusy(APIException):
    """A mapping with unresolved durable work cannot be unlinked."""

    status_code = status.HTTP_409_CONFLICT
    default_detail = "The integration mapping has pending or unresolved work."
    default_code = "sync_mapping_busy"


class IntegrationConfigurationBusy(APIException):
    """A configuration with unresolved durable work cannot be mutated."""

    status_code = status.HTTP_409_CONFLICT
    default_detail = "The integration configuration has pending or unresolved work."
    default_code = "integration_configuration_busy"


_UNRESOLVED_SYNC_JOB_STATUSES = (
    IntegrationSyncJob.Status.QUEUED,
    IntegrationSyncJob.Status.PROCESSING,
    IntegrationSyncJob.Status.UNCERTAIN,
    IntegrationSyncJob.Status.REVIEW_REQUIRED,
)


class ConnectionTestView(APIView):
    def post(self, request, *args, **kwargs):
        if not any(
            RoleAssignment.has_permission_anywhere(request.user, codename)
            for codename in (
                "add_integrationconfiguration",
                "change_integrationconfiguration",
            )
        ):
            return Response(status=status.HTTP_403_FORBIDDEN)

        serializer = ConnectionTestSerializer(
            data=request.data, context={"request": request}
        )
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        validated_data = serializer.validated_data
        provider = validated_data.get("provider")

        # Create a temporary, unsaved IntegrationConfiguration instance for the client
        temp_config = IntegrationConfiguration(
            provider=IntegrationProvider.objects.filter(name=provider).first(),
            credentials=validated_data.get("credentials"),
            settings=validated_data.get("settings", {}),
        )

        try:
            # Use the registry to get the correct client implementation
            client = IntegrationRegistry.get_client(temp_config)
            is_connected = client.test_connection()

            if is_connected:
                return Response(
                    {"status": "success", "message": "Connection successful."},
                    status=status.HTTP_200_OK,
                )
            else:
                # The test_connection method returned False, implying a credential error
                return Response(
                    {
                        "status": "failure",
                        "message": "Connection failed. Please check credentials.",
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )
        except Exception:
            # An exception occurred, e.g., network error, invalid URL
            logger.error(
                "Test connection for provider raised an exception",
                provider=provider,
                exc_info=True,
            )
            return Response(
                {"status": "error", "message": "An unexpected error occurred"},
                status=status.HTTP_400_BAD_REQUEST,
            )


class IntegrationProviderListView(generics.ListAPIView):
    """
    An API endpoint to list all available (and active) Integration Providers.
    """

    queryset = IntegrationProvider.objects.filter(is_active=True)
    serializer_class = IntegrationProviderSerializer
    filter_backends = [
        DjangoFilterBackend,
        filters.SearchFilter,
        filters.OrderingFilter,
    ]

    filterset_fields = ["provider_type", "name"]


class IntegrationConfigurationViewSet(BaseModelViewSet):
    """
    API endpoint for creating, viewing, updating, and deleting Integration Configurations.
    """

    model = IntegrationConfiguration
    serializers_module = "integrations.serializers"

    filterset_fields = ["provider", "provider__name", "provider__provider_type"]

    @staticmethod
    def _configuration_permission(action: str) -> Permission:
        return Permission.objects.get(
            codename=f"{action}_integrationconfiguration",
            content_type=ContentType.objects.get_for_model(
                IntegrationConfiguration, for_concrete_model=False
            ),
        )

    def _assert_source_change(self, configuration) -> None:
        if not RoleAssignment.is_access_allowed(
            user=self.request.user,
            perm=self._configuration_permission("change"),
            folder=configuration.folder,
        ):
            raise PermissionDenied("You cannot change this integration configuration.")

    def _assert_source_delete(self, configuration) -> None:
        if not RoleAssignment.is_access_allowed(
            user=self.request.user,
            perm=self._configuration_permission("delete"),
            folder=configuration.folder,
        ):
            raise PermissionDenied("You cannot delete this integration configuration.")

    def _assert_target_folder_authority(
        self, folder: Folder, *, require_add: bool
    ) -> None:
        visible_folder_ids = set(
            RoleAssignment.get_viewable_object_ids(self.request.user, Folder)
        )
        if folder.id not in visible_folder_ids:
            raise PermissionDenied("The target folder is unavailable.")
        if require_add and not RoleAssignment.is_access_allowed(
            user=self.request.user,
            perm=self._configuration_permission("add"),
            folder=folder,
        ):
            raise PermissionDenied(
                "You cannot create an integration configuration in the target folder."
            )

    @staticmethod
    def _lock_providers(provider_ids) -> dict:
        provider_ids = set(provider_ids)
        locked = {
            provider.id: provider
            for provider in IntegrationProvider.objects.select_for_update(of=("self",))
            .filter(id__in=provider_ids)
            .order_by("id")
        }
        if set(locked) != provider_ids:
            raise PermissionDenied("The integration provider is unavailable.")
        return locked

    @staticmethod
    def _snapshot_provider_folders(provider_ids) -> dict:
        provider_ids = set(provider_ids)
        snapshot = dict(
            IntegrationProvider.objects.filter(id__in=provider_ids)
            .order_by("id")
            .values_list("id", "folder_id")
        )
        if set(snapshot) != provider_ids:
            raise PermissionDenied("The integration provider is unavailable.")
        return snapshot

    @staticmethod
    def _lock_owner_folders(folder_ids) -> dict:
        folder_ids = {folder_id for folder_id in folder_ids if folder_id is not None}
        locked = {
            folder.id: folder
            for folder in Folder.objects.select_for_update(of=("self",))
            .filter(id__in=folder_ids)
            .order_by("id")
        }
        if set(locked) != folder_ids:
            raise PermissionDenied("An integration owner folder is unavailable.")
        return locked

    @staticmethod
    def _assert_provider_coherence(
        provider: IntegrationProvider, folder: Folder
    ) -> None:
        if not provider.is_active:
            raise PermissionDenied("The integration provider is unavailable.")
        if (
            provider.folder_id != folder.id
            and not folder.ancestors.filter(id=provider.folder_id).exists()
        ):
            raise PermissionDenied(
                "The integration provider is not available in the target folder."
            )

    def _lock_and_authorize_destination(
        self,
        serializer,
        *,
        current: IntegrationConfiguration | None,
        locked_folders: dict,
        provider_folder_snapshot: dict,
    ) -> tuple[IntegrationProvider, Folder]:
        candidate_provider = serializer.validated_data.get(
            "provider", current.provider if current is not None else None
        )
        candidate_folder = serializer.validated_data.get(
            "folder", current.folder if current is not None else None
        )
        if candidate_provider is None or candidate_folder is None:
            raise ValidationError("Provider and folder are required.")

        # Folder.save/delete operations take the root tree mutex held by the
        # caller.  Refresh the exact destination under that mutex, then acquire
        # providers only after the configuration row on updates.
        target_folder = locked_folders.get(candidate_folder.id)
        if target_folder is None:
            raise PermissionDenied("The target folder is unavailable.")

        provider_ids = {candidate_provider.id}
        if current is not None:
            provider_ids.add(current.provider_id)
        locked_providers = self._lock_providers(provider_ids)
        if any(
            provider.folder_id != provider_folder_snapshot.get(provider.id)
            for provider in locked_providers.values()
        ):
            raise PermissionDenied("The integration provider changed concurrently.")
        target_provider = locked_providers[candidate_provider.id]

        # Replace relationship values with the stabilized rows.  Also replace
        # the current provider cache used for omitted fields on PATCH.
        if current is not None:
            current.provider = locked_providers[current.provider_id]
        if "provider" in serializer.validated_data:
            serializer.validated_data["provider"] = target_provider
        if "folder" in serializer.validated_data:
            serializer.validated_data["folder"] = target_folder

        self._assert_provider_coherence(target_provider, target_folder)
        self._assert_target_folder_authority(
            target_folder,
            require_add=current is None or target_folder.id != current.folder_id,
        )
        return target_provider, target_folder

    @staticmethod
    def _lock_configuration_mappings(
        configuration: IntegrationConfiguration,
    ) -> list[SyncMapping]:
        # The locked configuration row prevents concurrent FK inserts.  Lock
        # every existing child before deciding whether the connection may be
        # repointed or deleted; a mapping is an explicit remote-side-effect
        # relationship and must be unlinked first.
        return list(
            SyncMapping.objects.select_for_update(of=("self",))
            .filter(configuration_id=configuration.id)
            .order_by("id")
        )

    @staticmethod
    def _protected_connection_fields_changed(
        configuration: IntegrationConfiguration, validated_data
    ) -> bool:
        provider = validated_data.get("provider")
        folder = validated_data.get("folder")
        return bool(
            (provider is not None and provider.id != configuration.provider_id)
            or (folder is not None and folder.id != configuration.folder_id)
            or (
                "credentials" in validated_data
                and dict(validated_data["credentials"] or {})
                != dict(configuration.credentials or {})
            )
            or (
                "settings" in validated_data
                and dict(validated_data["settings"] or {})
                != dict(configuration.settings or {})
            )
        )

    @staticmethod
    def _assert_no_unresolved_jobs(configuration: IntegrationConfiguration) -> None:
        # Call only after all child mappings have been locked.  The
        # configuration mutex prevents a conforming enqueue path from adding a
        # new snapshot while this mutation is being decided.
        if (
            IntegrationSyncJob.objects.select_for_update(of=("self",))
            .filter(
                configuration_id_snapshot=configuration.id,
                status__in=_UNRESOLVED_SYNC_JOB_STATUSES,
            )
            .order_by("created_at", "id")
            .exists()
        ):
            raise IntegrationConfigurationBusy()

    def _assert_mappings_allow_update(
        self,
        configuration: IntegrationConfiguration,
        validated_data,
    ) -> None:
        mappings = self._lock_configuration_mappings(configuration)
        self._assert_no_unresolved_jobs(configuration)
        if mappings and self._protected_connection_fields_changed(
            configuration, validated_data
        ):
            raise ValidationError(
                {
                    "detail": (
                        "Unlink all synchronized objects before changing the "
                        "provider, folder, credentials, or settings."
                    )
                }
            )

    def create(self, request, *args, **kwargs):
        try:
            self._process_request_data(request)
            with transaction.atomic():
                Folder._lock_folder_tree()
                serializer = self.get_serializer(data=request.data)
                serializer.is_valid(raise_exception=True)
                candidate_provider = serializer.validated_data.get("provider")
                candidate_folder = serializer.validated_data.get("folder")
                if candidate_provider is None or candidate_folder is None:
                    raise ValidationError("Provider and folder are required.")
                provider_folder_snapshot = self._snapshot_provider_folders(
                    {candidate_provider.id}
                )
                locked_folders = self._lock_owner_folders(
                    {
                        candidate_folder.id,
                        *provider_folder_snapshot.values(),
                    }
                )
                provider, folder = self._lock_and_authorize_destination(
                    serializer,
                    current=None,
                    locked_folders=locked_folders,
                    provider_folder_snapshot=provider_folder_snapshot,
                )
                _bind_configuration_mutation_authority(
                    serializer,
                    instance=None,
                    provider=provider,
                    folder=folder,
                )
                self.perform_create(serializer)
                response_data = serializer.data
                headers = self.get_success_headers(response_data)
            return Response(
                response_data, status=status.HTTP_201_CREATED, headers=headers
            )
        except ValidationError as exc:
            logger.warning(
                "IntegrationConfiguration create rejected",
                errors=exc.detail,
                provider_id=str(request.data.get("provider_id", "")),
            )
            raise

    def update(self, request, *args, **kwargs):
        try:
            partial = kwargs.pop("partial", False)
            with transaction.atomic():
                Folder._lock_folder_tree()
                # Preserve the normal non-disclosure behavior before taking an
                # unrestricted row lock, then discard this potentially stale
                # instance once the lock is acquired.
                candidate = self.get_object()
                serializer = self.get_serializer(
                    candidate,
                    data=request.data,
                    partial=partial,
                )
                serializer.is_valid(raise_exception=True)
                candidate_provider = serializer.validated_data.get(
                    "provider", candidate.provider
                )
                candidate_folder = serializer.validated_data.get(
                    "folder", candidate.folder
                )
                provider_ids = {candidate.provider_id, candidate_provider.id}
                provider_folder_snapshot = self._snapshot_provider_folders(provider_ids)
                locked_folders = self._lock_owner_folders(
                    {
                        candidate.folder_id,
                        candidate_folder.id,
                        *provider_folder_snapshot.values(),
                    }
                )
                try:
                    configuration = (
                        IntegrationConfiguration.objects.select_for_update(of=("self",))
                        .select_related("folder")
                        .get(id=candidate.id)
                    )
                except IntegrationConfiguration.DoesNotExist as exc:
                    raise PermissionDenied(
                        "The integration configuration is unavailable."
                    ) from exc
                if (
                    configuration.folder_id != candidate.folder_id
                    or configuration.provider_id != candidate.provider_id
                ):
                    raise PermissionDenied(
                        "The integration configuration changed concurrently."
                    )

                # Visibility/publication/focus state can change while waiting
                # for the row.  Re-run the complete IAM-scoped source query.
                if not self.get_queryset().filter(id=configuration.id).exists():
                    raise PermissionDenied(
                        "The integration configuration is unavailable."
                    )
                self._assert_source_change(configuration)

                serializer.instance = configuration
                provider, folder = self._lock_and_authorize_destination(
                    serializer,
                    current=configuration,
                    locked_folders=locked_folders,
                    provider_folder_snapshot=provider_folder_snapshot,
                )
                self._assert_mappings_allow_update(
                    configuration, serializer.validated_data
                )
                _bind_configuration_mutation_authority(
                    serializer,
                    instance=configuration,
                    provider=provider,
                    folder=folder,
                )
                self.perform_update(serializer)
                if getattr(configuration, "_prefetched_objects_cache", None):
                    configuration._prefetched_objects_cache = {}
                response_data = serializer.data
            return Response(response_data)
        except ValidationError as exc:
            logger.warning(
                "IntegrationConfiguration update rejected",
                errors=exc.detail,
                config_id=kwargs.get("pk"),
                provider_id=str(request.data.get("provider_id", "")),
            )
            raise

    def partial_update(self, request, *args, **kwargs):
        self._process_request_data(request)
        kwargs["partial"] = True
        return self.update(request, *args, **kwargs)

    def destroy(self, request, *args, **kwargs):
        self._process_request_data(request)
        with transaction.atomic():
            Folder._lock_folder_tree()
            candidate = self.get_object()
            provider_folder_snapshot = self._snapshot_provider_folders(
                {candidate.provider_id}
            )
            self._lock_owner_folders(
                {
                    candidate.folder_id,
                    *provider_folder_snapshot.values(),
                }
            )
            try:
                configuration = (
                    IntegrationConfiguration.objects.select_for_update(of=("self",))
                    .select_related("folder")
                    .get(id=candidate.id)
                )
            except IntegrationConfiguration.DoesNotExist as exc:
                raise PermissionDenied(
                    "The integration configuration is unavailable."
                ) from exc
            if (
                configuration.folder_id != candidate.folder_id
                or configuration.provider_id != candidate.provider_id
            ):
                raise PermissionDenied(
                    "The integration configuration changed concurrently."
                )
            if not self.get_queryset().filter(id=configuration.id).exists():
                raise PermissionDenied("The integration configuration is unavailable.")
            self._assert_source_delete(configuration)

            providers = self._lock_providers({configuration.provider_id})
            if any(
                provider.folder_id
                != provider_folder_snapshot.get(provider.id)
                for provider in providers.values()
            ):
                raise PermissionDenied("The integration provider changed concurrently.")
            configuration.provider = providers[configuration.provider_id]
            mappings = self._lock_configuration_mappings(configuration)
            self._assert_no_unresolved_jobs(configuration)
            if mappings:
                raise ValidationError(
                    {
                        "detail": (
                            "Unlink all synchronized objects before deleting "
                            "this integration configuration."
                        )
                    }
                )

            serializer = self.get_serializer(configuration)
            _bind_configuration_mutation_authority(
                serializer,
                instance=configuration,
                provider=configuration.provider,
                folder=configuration.folder,
                operation="delete",
            )
            serializer.delete(configuration)
            try:
                dispatch_webhook_event(configuration, "deleted")
            except Exception:
                logger.error(
                    "Webhook dispatch failed on integration configuration delete",
                    config_id=str(configuration.id),
                    exc_info=True,
                )
        return Response(status=status.HTTP_204_NO_CONTENT)

    @action(detail=True, methods=["post"], url_path="test-connection")
    def test_connection(self, request, pk=None):
        """
        Custom action to test the connection for a saved integration configuration.
        URL: /api/integrations/configs/{id}/test-connection/
        """
        logger.info(f"Testing connection for integration config: {pk}")
        instance = self.get_object()

        try:
            # Use the registry to get the correct client implementation
            client = IntegrationRegistry.get_client(instance)
            is_connected = client.test_connection()

            if is_connected:
                return Response(
                    {"status": "success", "message": "Connection successful."},
                    status=status.HTTP_200_OK,
                )
            else:
                return Response(
                    {
                        "status": "failure",
                        "message": "Connection failed. Please check credentials.",
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )
        except Exception:
            logger.error(
                "Test connection for config raised an exception",
                config_id=pk,
                exc_info=True,
            )
            return Response(
                {"status": "error", "message": "An unexpected error occurred"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    def _list_remote_objects(self, request, pk):
        from integrations.syncable import get_spec

        instance = self.get_object()
        model_key = request.query_params.get("model_key", "applied_control")
        if get_spec(model_key) is None:
            return Response(
                {"error": f"Unknown model_key '{model_key}'"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            limit = int(request.query_params.get("limit", 50))
        except TypeError, ValueError:
            limit = 50
        query_params = {
            "search": request.query_params.get("search", ""),
            "id": request.query_params.get("id", ""),
            "limit": max(1, min(limit, 100)),
        }
        try:
            client = IntegrationRegistry.get_client(instance, model_key)
            remote_objects = client.list_remote_objects(query_params=query_params)
            return Response(remote_objects, status=status.HTTP_200_OK)
        except Exception:
            logger.error(
                "Listing remote objects for config raised an exception",
                config_id=pk,
                exc_info=True,
            )
            return Response(
                {"status": "error", "message": "An unexpected error occurred"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    @action(detail=True, methods=["get"], url_path="remote-objects")
    def list_remote_objects(self, request, pk=None):
        return self._list_remote_objects(request, pk)

    # The AutocompleteSelect lazy mode appends /autocomplete to its options
    # endpoint; same behavior as remote-objects, which also accepts search.
    @action(detail=True, methods=["get"], url_path="remote-objects/autocomplete")
    def remote_objects_autocomplete(self, request, pk=None):
        return self._list_remote_objects(request, pk)

    @action(detail=True, methods=["post"], url_path="rpc")
    def execute_rpc(self, request, pk=None):
        """
        Generic endpoint for interactive integration commands.
        Payload: { "action": "get_tables", "params": { ... } }
        """
        config = self.get_object()

        action_name = request.data.get("action")
        params = request.data.get("params", {})

        if not action_name:
            return Response(
                {"error": "Action is required"}, status=status.HTTP_400_BAD_REQUEST
            )

        try:
            orchestrator = IntegrationRegistry.get_orchestrator(config)

            result = orchestrator.execute_action(action_name, params)

            return Response({"result": result})

        except NotImplementedError:
            return Response(
                {
                    "error": f"Action '{action_name}' not supported by provider '{config.provider}'"
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        except ValueError:
            logger.warning(
                "ValueError while executing integration RPC action",
                action_name=action_name,
                config_id=config.pk,
                exc_info=True,
            )
            return Response(
                {"error": "Invalid request parameters"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except Exception:
            # Catch connectivity errors from the client
            logger.error(
                "RPC execution for integration config raised an exception",
                config_id=pk,
                action_name=action_name,
                exc_info=True,
            )
            return Response(
                {
                    "error": "An unexpected error occurred while executing the requested action."
                },
                status=status.HTTP_502_BAD_GATEWAY,
            )


@method_decorator(csrf_exempt, name="dispatch")
class IntegrationWebhookView(View):
    """
    Receives, authenticates, and dispatches incoming webhooks
    from integration providers.

    This view is designed to be provider-agnostic. It uses a shared secret
    for authentication.
    """

    def post(
        self, request: HttpRequest, config_id: uuid.UUID, *args, **kwargs
    ) -> HttpResponse:
        # Use a generic rejection response to avoid leaking config existence
        rejection = JsonResponse({"error": "Webhook rejected"}, status=403)

        try:
            config = IntegrationConfiguration.objects.select_related("provider").get(
                pk=config_id,
                is_active=True,
                provider__is_active=True,
            )
        except IntegrationConfiguration.DoesNotExist:
            logger.warning(
                f"Webhook received for unknown or inactive config ID: {config_id}"
            )
            return rejection

        # Instantiate the correct orchestrator
        try:
            orchestrator = IntegrationRegistry.get_orchestrator(config)
        except Exception as e:
            logger.error(f"Failed to load orchestrator for config {config_id}: {e}")
            return rejection

        # Delegate authentication/validation
        # The orchestrator checks headers, secrets, signatures etc.
        try:
            if not orchestrator.validate_webhook_request(request):
                return rejection
        except Exception:
            logger.warning(
                "Webhook validation failed", config_id=config_id, exc_info=True
            )
            return rejection

        # Bind the exact rows and body that were authenticated. The minting
        # transaction re-locks both rows and rejects any intervening change.
        authenticated_configuration_hmac = configuration_authority_hmac(config)
        authenticated_provider_hmac = model_row_authority_hmac(config.provider)
        authenticated_body_hmac = authority_hmac(
            hashlib.sha256(request.body).hexdigest(),
            domain="integration-webhook-authenticated-body-v1",
        )

        # Parse payload
        try:
            payload = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON payload"}, status=400)

        # Extract event type
        try:
            event_type = orchestrator.extract_webhook_event_type(payload)
        except (AttributeError, KeyError, TypeError, ValueError):
            return JsonResponse({"error": "Could not determine event type"}, status=400)
        if not event_type:
            return JsonResponse({"error": "Could not determine event type"}, status=400)

        try:
            event_action = orchestrator.classify_webhook_event(event_type)
        except (TypeError, ValueError):
            return JsonResponse({"error": "Unsupported event type"}, status=400)
        if event_action not in {"update", "delete"}:
            # Authenticated create/no-op/unknown events are acknowledged but do
            # not gain a durable background-job capability.
            return HttpResponse(status=202)

        try:
            remote_id = normalize_remote_id(
                config.provider.name,
                orchestrator.extract_webhook_remote_id(payload),
            )
        except (InvalidRemoteIdentifier, TypeError, ValueError):
            return JsonResponse({"error": "Invalid remote identifier"}, status=400)

        persist_webhook_sync_job(
            authenticated_configuration=config,
            authenticated_configuration_hmac_sha256=(authenticated_configuration_hmac),
            authenticated_provider_hmac_sha256=authenticated_provider_hmac,
            authenticated_body_hmac_sha256=authenticated_body_hmac,
            remote_id=remote_id,
            event_type=event_type,
            payload=payload,
        )

        return HttpResponse(status=202)


class SyncMappingDeleteView(generics.DestroyAPIView):
    """
    An API endpoint to delete a SyncMapping.
    """

    serializer_class = SyncMappingSerializer

    def get_queryset(self):
        try:
            visible_ids = RoleAssignment.get_viewable_object_ids(
                self.request.user, SyncMapping
            )
        except (NotImplementedError, Permission.DoesNotExist):
            return SyncMapping.objects.none()
        return SyncMapping.objects.filter(id__in=visible_ids)

    @staticmethod
    def _deny() -> None:
        raise PermissionDenied("The integration mapping is unavailable.")

    def _assert_visible(self, instance) -> None:
        try:
            visible_ids = RoleAssignment.get_viewable_object_ids(
                self.request.user, type(instance)
            )
        except (NotImplementedError, Permission.DoesNotExist):
            self._deny()
        if not visible_ids.filter(id=instance.pk).exists():
            self._deny()

    def _assert_action(self, instance, action: str, *, folder: Folder) -> None:
        model = type(instance)
        try:
            permission = Permission.objects.get(
                content_type=ContentType.objects.get_for_model(
                    model, for_concrete_model=False
                ),
                codename=f"{action}_{model._meta.model_name}",
            )
        except Permission.DoesNotExist:
            self._deny()
        if not RoleAssignment.is_access_allowed(
            user=self.request.user,
            perm=permission,
            folder=folder,
        ):
            self._deny()

    @transaction.atomic
    def destroy(self, request, *args, **kwargs):
        # Folder mutations use this root-row mutex.  Taking it first stabilizes
        # both the owner folders and the provider ancestor relation while the
        # authority-bearing graph is locked and re-proved below.
        Folder._lock_folder_tree()
        candidate = self.get_object()

        content_type = ContentType.objects.filter(id=candidate.content_type_id).first()
        local_model = content_type.model_class() if content_type is not None else None
        if local_model is None or not any(
            field.name == "folder" for field in local_model._meta.get_fields()
        ):
            self._deny()
        local_folder_id_snapshot = (
            local_model._base_manager.filter(pk=candidate.local_object_id)
            .values_list("folder_id", flat=True)
            .first()
        )
        configuration_snapshot = (
            IntegrationConfiguration.objects.filter(id=candidate.configuration_id)
            .values("folder_id", "provider__folder_id")
            .first()
        )
        if local_folder_id_snapshot is None or configuration_snapshot is None:
            self._deny()
        owner_folder_ids = {
            candidate.folder_id,
            local_folder_id_snapshot,
            configuration_snapshot["folder_id"],
            configuration_snapshot["provider__folder_id"],
        }
        locked_folder_ids = set(
            Folder.objects.select_for_update(of=("self",))
            .filter(id__in=owner_folder_ids)
            .order_by("id")
            .values_list("id", flat=True)
        )
        if locked_folder_ids != owner_folder_ids:
            self._deny()

        configuration = (
            IntegrationConfiguration.objects.select_for_update(of=("self",))
            .select_related("folder")
            .filter(id=candidate.configuration_id)
            .first()
        )
        if configuration is None:
            self._deny()

        provider = (
            IntegrationProvider.objects.select_for_update(of=("self",))
            .select_related("folder")
            .filter(id=configuration.provider_id)
            .first()
        )
        if provider is None:
            self._deny()

        mapping = (
            SyncMapping.objects.select_for_update(of=("self",))
            .select_related("content_type", "folder")
            .filter(id=candidate.id)
            .first()
        )
        if (
            mapping is None
            or mapping.configuration_id != configuration.id
            or mapping.content_type_id != candidate.content_type_id
            or mapping.local_object_id != candidate.local_object_id
        ):
            self._deny()

        try:
            normalize_remote_id(
                provider.name,
                mapping.remote_id,
                allow_blank=True,
            )
        except InvalidRemoteIdentifier:
            # Old non-canonical values remain removable, but structurally
            # invalid identifiers need a reviewed repair path.
            self._deny()

        local_model = mapping.content_type.model_class()
        if local_model is None or not hasattr(local_model, "_base_manager"):
            self._deny()
        local_object = (
            local_model._base_manager.select_for_update(of=("self",))
            .filter(pk=mapping.local_object_id)
            .first()
        )
        if local_object is None:
            self._deny()
        local_folder = Folder.get_folder(local_object)
        if local_folder is None:
            self._deny()

        owner_folder = configuration.folder
        provider_is_coherent = (
            provider.folder_id == owner_folder.id
            or owner_folder.ancestors.filter(id=provider.folder_id).exists()
        )
        if (
            mapping.folder_id != owner_folder.id
            or local_folder.id != owner_folder.id
            or not provider_is_coherent
            or owner_folder.id not in locked_folder_ids
            or provider.folder_id not in locked_folder_ids
        ):
            self._deny()

        # Visibility is independently proved for every relationship carrier;
        # seeing the mapping never implies access to its configuration, remote
        # provider, local object, or either authority-bearing folder.
        for instance in (
            mapping,
            configuration,
            provider,
            local_object,
            owner_folder,
            provider.folder,
        ):
            self._assert_visible(instance)

        # Unlinking deletes the mapping itself and changes the effective
        # integration state of both the configuration and the local object.
        # It does not mutate or delete the provider, so provider view authority
        # is sufficient and least-privileged.
        self._assert_action(mapping, "delete", folder=owner_folder)
        self._assert_action(configuration, "change", folder=owner_folder)
        self._assert_action(local_object, "change", folder=local_folder)

        blocking_job_ids = list(
            IntegrationSyncJob.objects.select_for_update(of=("self",))
            .filter(
                mapping_id_snapshot=mapping.id,
                status__in=_UNRESOLVED_SYNC_JOB_STATUSES,
            )
            .order_by("created_at", "id")
            .values_list("id", flat=True)
        )
        if blocking_job_ids:
            raise SyncMappingBusy()

        mapping.version += 1
        mapping.save(update_fields=["version", "updated_at"])
        SyncEvent.objects.create(
            mapping=mapping,
            mapping_id_snapshot=mapping.id,
            configuration_id_snapshot=mapping.configuration_id,
            content_type_id_snapshot=mapping.content_type_id,
            local_object_id_snapshot=mapping.local_object_id,
            remote_id_snapshot=mapping.remote_id,
            job_id_snapshot=None,
            request_digest_snapshot="",
            actor_id_snapshot=request.user.id,
            direction=SyncMapping.SyncDirection.PUSH,
            changes={
                "action": "unlink",
                "before": {
                    "local_object_id": str(mapping.local_object_id),
                    "remote_id": mapping.remote_id,
                    "sync_status": mapping.sync_status,
                },
                "after": {},
                "mapping_version": mapping.version,
            },
            triggered_by=SyncEvent.TriggeredBy.USER,
            success=True,
        )
        mapping.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
