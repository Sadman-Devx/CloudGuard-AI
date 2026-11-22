import json

from django.conf import settings
from django.shortcuts import get_object_or_404
from drf_spectacular.utils import extend_schema
from rest_framework import generics, status
from rest_framework.exceptions import APIException, NotFound, PermissionDenied, ValidationError
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.views import APIView

from apps.projects.models import Project
from common.exceptions import ConfigValidationFailed
from common.sanitize import strip_control_chars
from common.throttles import WriteThrottle
from domain.network.importers import ImporterError
from domain.network.importers.aws_describe import import_aws_describe
from domain.network.importers.aws_live import EXTERNAL_ID, ROLE_ARN, AwsImportError, fetch_aws_data
from domain.network.importers.cloudformation import import_cloudformation
from domain.network.importers.terraform import import_terraform
from domain.network.risk_overlay import build_risk_overlay
from domain.network.schema import ConfigValidationError, parse_config

from .models import CloudResource, ConfigurationSnapshot
from .serializers import (
    AwsImportSerializer,
    CloudResourceSerializer,
    FixtureImportSerializer,
    IacImportSerializer,
    SnapshotSerializer,
)
from .services.fixtures import FixtureNotFound, list_fixtures, load_fixture
from .services.snapshots import import_snapshot
from .services.topology import SnapshotIncompatible, snapshot_topology


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
            source_name=strip_control_chars(request.headers.get("X-Source-Name", ""))[:128],
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


def _imported(snapshot, report) -> Response:
    body = SnapshotSerializer(snapshot).data
    body["import_report"] = {"warnings": report.warnings, "stats": report.stats}
    return Response(body, status=status.HTTP_201_CREATED)


class ProjectIacImportView(APIView):
    """Import a Terraform plan/state (``terraform show -json``) or a CloudFormation template.

    The file is parsed, never executed. Anything the model cannot represent is dropped and listed in
    ``import_report.warnings`` (also stored on the snapshot).
    """

    @extend_schema(request=IacImportSerializer, responses={201: dict}, tags=["import"])
    def post(self, request, project_id):
        project = get_object_or_404(Project, pk=project_id)
        body = IacImportSerializer(data=request.data)
        body.is_valid(raise_exception=True)
        fmt, content = body.validated_data["format"], body.validated_data["content"]
        name = strip_control_chars(body.validated_data.get("name", ""))[:128]
        try:
            if fmt == "terraform":
                try:
                    document = content if isinstance(content, dict) else json.loads(content)
                except ValueError as exc:
                    raise ImporterError(
                        "The Terraform file is not valid JSON. Use `terraform show -json`."
                    ) from exc
                report = import_terraform(document, name=name)
                source = ConfigurationSnapshot.SourceType.TERRAFORM
            else:
                report = import_cloudformation(content, name=name)
                source = ConfigurationSnapshot.SourceType.CLOUDFORMATION
        except ImporterError as exc:
            raise ConfigValidationFailed(exc.issues) from exc
        except RecursionError as exc:
            raise ConfigValidationFailed(
                [{"path": "", "code": "too_deeply_nested", "message": "The file is nested too deeply."}]
            ) from exc
        snapshot = import_snapshot(
            project,
            report.config,
            source_type=source,
            source_name=name or fmt,
            extra_warnings=report.warnings,
        )
        return _imported(snapshot, report)


class AwsImportStatusView(APIView):
    @extend_schema(responses={200: dict}, tags=["import"])
    def get(self, request):
        return Response(
            {
                "enabled": settings.AWS_IMPORT_ENABLED,
                "role_allowlist": bool(settings.AWS_IMPORT_ALLOWED_ROLE_ARNS),
                "regions": settings.AWS_IMPORT_ALLOWED_REGIONS,
            }
        )


class AwsImportFailed(APIException):
    def __init__(self, error: AwsImportError):
        super().__init__(detail=error.message, code=error.code)
        self.status_code = error.status


class ProjectAwsImportView(APIView):
    """Read-only import of a live AWS account (``Describe*`` calls only; nothing is ever written).

    Credentials are never sent to this endpoint: the server uses its own identity, optionally
    assuming ``role_arn``. Disabled unless ``AWS_IMPORT_ENABLED`` is set (see settings).
    """

    throttle_classes = [WriteThrottle, ScopedRateThrottle]
    throttle_scope = "aws_import"

    @extend_schema(request=AwsImportSerializer, responses={201: dict}, tags=["import"])
    def post(self, request, project_id):
        if not settings.AWS_IMPORT_ENABLED:
            raise PermissionDenied(
                "Live AWS import is disabled on this server "
                "(set AWS_IMPORT_ENABLED=true on a private deployment).",
                code="aws_import_disabled",
            )
        project = get_object_or_404(Project, pk=project_id)
        body = AwsImportSerializer(data=request.data)
        body.is_valid(raise_exception=True)
        data = body.validated_data
        region, role_arn = data["region"], data.get("role_arn") or None
        external_id = data.get("external_id") or None
        if settings.AWS_IMPORT_ALLOWED_REGIONS and region not in settings.AWS_IMPORT_ALLOWED_REGIONS:
            raise ValidationError({"region": ["This region is not allowed on this server."]})
        if role_arn:
            if not ROLE_ARN.match(role_arn):
                raise ValidationError({"role_arn": ["Expected arn:aws:iam::<12 digits>:role/<name>."]})
            allowed = settings.AWS_IMPORT_ALLOWED_ROLE_ARNS
            if allowed and role_arn not in allowed:
                raise ValidationError({"role_arn": ["This role is not on the server's allowlist."]})
        elif settings.AWS_IMPORT_ALLOWED_ROLE_ARNS:
            raise ValidationError({"role_arn": ["This server only imports through an allowlisted role."]})
        if external_id and not EXTERNAL_ID.match(external_id):
            raise ValidationError({"external_id": ["Contains characters AWS does not allow."]})

        try:
            raw = fetch_aws_data(
                region,
                role_arn=role_arn,
                external_id=external_id,
                vpc_ids=data.get("vpc_ids") or None,
                include_s3=data.get("include_s3", False),
            )
            report = import_aws_describe(raw, region=region, name=strip_control_chars(data.get("name", "")))
        except AwsImportError as exc:
            raise AwsImportFailed(exc) from exc
        except ImporterError as exc:
            raise ConfigValidationFailed(exc.issues) from exc
        snapshot = import_snapshot(
            project,
            report.config,
            source_type=ConfigurationSnapshot.SourceType.AWS,
            source_name=f"aws:{region}",
            extra_warnings=report.warnings,
        )
        return _imported(snapshot, report)


class SnapshotTopologyRiskView(APIView):
    """Which resources are risky and why, plus the internet paths that reach them (for the graph)."""

    @extend_schema(responses={200: dict}, tags=["topology"])
    def get(self, request, pk):
        snapshot = get_object_or_404(ConfigurationSnapshot, pk=pk)
        try:
            config = parse_config(snapshot.raw_json)
        except ConfigValidationError as exc:
            raise ConfigValidationFailed([issue.as_dict() for issue in exc.errors]) from exc
        return Response({"snapshot": snapshot.id, **build_risk_overlay(config)})


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


class SnapshotTopologyView(APIView):
    """Nodes and edges of the digital-twin graph. Read-only; derived from the stored input."""

    @extend_schema(responses={200: dict}, tags=["topology"])
    def get(self, request, pk):
        snapshot = get_object_or_404(ConfigurationSnapshot, pk=pk)
        try:
            return Response(snapshot_topology(snapshot))
        except SnapshotIncompatible as exc:
            raise ConfigValidationFailed(exc.errors) from exc
