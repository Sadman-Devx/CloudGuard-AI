from django.shortcuts import get_object_or_404
from drf_spectacular.utils import extend_schema
from rest_framework import generics, status
from rest_framework.exceptions import NotFound, ValidationError
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.projects.models import Project

from .models import CloudResource, ConfigurationSnapshot
from .serializers import CloudResourceSerializer, FixtureImportSerializer, SnapshotSerializer
from .services.fixtures import FixtureNotFound, list_fixtures, load_fixture
from .services.snapshots import import_snapshot


class ProjectSnapshotsView(generics.ListAPIView):
    """GET lists a project's snapshots; POST uploads a configuration (the JSON body itself)."""

    serializer_class = SnapshotSerializer

    def get_queryset(self):
        project = get_object_or_404(Project, pk=self.kwargs["project_id"])
        return ConfigurationSnapshot.objects.filter(project=project)

    @extend_schema(request=dict, responses={201: SnapshotSerializer})
    def post(self, request, project_id):
        project = get_object_or_404(Project, pk=project_id)
        snapshot = import_snapshot(
            project,
            request.data,
            source_type=ConfigurationSnapshot.SourceType.UPLOAD,
            source_name=request.headers.get("X-Source-Name", "")[:128],
        )
        return Response(SnapshotSerializer(snapshot).data, status=status.HTTP_201_CREATED)


class FixtureListView(APIView):
    @extend_schema(responses={200: dict})
    def get(self, request):
        return Response({"results": list_fixtures()})


class ProjectFixtureImportView(APIView):
    @extend_schema(request=FixtureImportSerializer, responses={201: SnapshotSerializer})
    def post(self, request, project_id):
        project = get_object_or_404(Project, pk=project_id)
        serializer = FixtureImportSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        name = serializer.validated_data["fixture"]
        try:
            data = load_fixture(name)
        except FixtureNotFound:
            raise ValidationError({"fixture": [f"Unknown fixture '{name}'."]}) from None
        snapshot = import_snapshot(
            project,
            data,
            source_type=ConfigurationSnapshot.SourceType.FIXTURE,
            source_name=name,
        )
        return Response(SnapshotSerializer(snapshot).data, status=status.HTTP_201_CREATED)


class SnapshotDetailView(generics.RetrieveAPIView):
    queryset = ConfigurationSnapshot.objects.all()
    serializer_class = SnapshotSerializer


class SnapshotResourcesView(generics.ListAPIView):
    """Normalized inventory for a snapshot; filter with ``?type=security_group``."""

    serializer_class = CloudResourceSerializer

    def get_queryset(self):
        snapshot_id = self.kwargs["snapshot_id"]
        if not ConfigurationSnapshot.objects.filter(pk=snapshot_id).exists():
            raise NotFound("Snapshot not found.")
        queryset = CloudResource.objects.filter(snapshot_id=snapshot_id)
        resource_type = self.request.query_params.get("type")
        if resource_type:
            queryset = queryset.filter(resource_type=resource_type)
        return queryset
