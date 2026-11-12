"""FastAPI router. Mount with:  app.include_router(attack_path_router)"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from .apps.attack_paths.demo_graph import SAMPLE_GRAPH
from .graph import AttackGraph

router = APIRouter(prefix="/api/attack-path", tags=["attack-path"])

# In-memory store. Swap for DB / cached cloud inventory in production.
_graph = AttackGraph.from_dict(SAMPLE_GRAPH)


class NodeIn(BaseModel):
    id: str
    name: str
    type: str
    criticality: int = Field(1, ge=1, le=10)
    internet_exposed: bool = False
    crown_jewel: bool = False
    vulns: list[dict] = []


class EdgeIn(BaseModel):
    source: str
    target: str
    kind: str
    exploitability: float = Field(0.5, ge=0, le=1)
    label: str = ""


class GraphIn(BaseModel):
    nodes: list[NodeIn]
    edges: list[EdgeIn]


class SimulateIn(BaseModel):
    remove_nodes: list[str]
    max_depth: int = Field(6, ge=1, le=10)


@router.get("/graph")
def get_graph():
    return _graph.to_dict()


@router.put("/graph")
def replace_graph(payload: GraphIn):
    global _graph
    try:
        _graph = AttackGraph.from_dict(payload.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {"nodes": len(_graph.nodes), "status": "updated"}


@router.get("/paths")
def get_paths(top_k: int = Query(10, ge=1, le=100), max_depth: int = Query(6, ge=1, le=10)):
    paths = _graph.attack_paths(top_k=top_k, max_depth=max_depth)
    return {"paths": paths, "choke_points": _graph.choke_points(paths)}


@router.get("/blast-radius/{node_id}")
def get_blast_radius(
    node_id: str, max_depth: int = Query(4, ge=1, le=10), min_prob: float = Query(0.01, ge=0.0001, le=1)
):
    try:
        return _graph.blast_radius(node_id, max_depth, min_prob)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"Node '{node_id}' not found") from exc


@router.post("/simulate")
def simulate(payload: SimulateIn):
    missing = [n for n in payload.remove_nodes if n not in _graph.nodes]
    if missing:
        raise HTTPException(status_code=404, detail=f"Unknown nodes: {missing}")
    return _graph.simulate_fix(payload.remove_nodes, payload.max_depth)
