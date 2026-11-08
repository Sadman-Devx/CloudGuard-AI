from rest_framework.response import Response
from rest_framework.views import APIView

from domain.network.dashboard import build_dashboard
from domain.network.proposal import ProposalError

from .adapters import default_adapters
from .services import workflow


def _err(code, message, status):
    return Response({"error": {"code": code, "message": message}}, status=status)


class SimulateProposalView(APIView):
    """POST /api/findings/{finding_id}/simulate-proposal/  body: {"proposal": {...}} (optional)"""

    def post(self, request, finding_id):
        try:
            result = workflow.run_for_finding(
                finding_id, request.data.get("proposal"), default_adapters())
        except ProposalError as exc:
            return _err("INVALID_PROPOSAL", str(exc), 422)
        except LookupError as exc:
            return _err("NOT_FOUND", str(exc), 404)
        return Response(result, status=201)


class ProjectDashboardView(APIView):
    """GET /api/projects/{project_id}/dashboard/"""

    def get(self, request, project_id):
        try:
            state = default_adapters().project_state(project_id)
        except LookupError as exc:
            return _err("NOT_FOUND", str(exc), 404)
        return Response(build_dashboard(state))
