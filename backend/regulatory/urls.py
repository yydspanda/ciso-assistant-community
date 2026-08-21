from django.urls import include, path
from rest_framework.routers import DefaultRouter

from .views import RegulatoryDocumentViewSet


app_name = "regulatory"

router = DefaultRouter()
router.register(
    r"documents",
    RegulatoryDocumentViewSet,
    basename="regulatory-documents",
)

urlpatterns = [path("", include(router.urls))]
