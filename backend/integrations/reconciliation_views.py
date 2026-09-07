"""HTTP boundary for governed integration reconciliation."""

from rest_framework.response import Response
from rest_framework.views import APIView

from integrations.reconciliation import reconcile_sync_job
from integrations.serializers import IntegrationSyncJobReconcileSerializer


class IntegrationSyncJobReconcileView(APIView):
    """Resolve one ambiguous effect without returning its retained payload."""

    def post(self, request, job_id):
        serializer = IntegrationSyncJobReconcileSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        result = reconcile_sync_job(
            job_id=job_id,
            user=request.user,
            validated_data=serializer.validated_data,
        )
        return Response(result)
