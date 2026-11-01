import { Background, ConnectionMode, Controls, ReactFlow, ReactFlowProvider } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { useMemo } from "react";

import { filterTopology, graphHeight, layoutTopology } from "./layout.js";
import { nodeTypes } from "./nodeTypes.js";

function Graph({ topology, hiddenTypes, selection, onSelect }) {
  const { nodes, edges } = useMemo(() => layoutTopology(filterTopology(topology, hiddenTypes)), [topology, hiddenTypes]);

  const shownNodes = useMemo(
    () => nodes.map((n) => ({ ...n, selected: selection?.kind === "node" && selection.id === n.id })),
    [nodes, selection],
  );
  const shownEdges = useMemo(
    () => edges.map((e) => ({ ...e, selected: selection?.kind === "edge" && selection.id === e.id })),
    [edges, selection],
  );

  return (
    <ReactFlow
      key={nodes.map((n) => n.id).join("|")}
      nodes={shownNodes}
      edges={shownEdges}
      nodeTypes={nodeTypes}
      connectionMode={ConnectionMode.Loose}
      nodesConnectable={false}
      nodesDraggable={false}
      elementsSelectable
      fitView
      fitViewOptions={{ padding: 0.08, maxZoom: 1.1 }}
      minZoom={0.2}
      maxZoom={1.6}
      onNodeClick={(_, node) => onSelect({ kind: "node", id: node.id })}
      onEdgeClick={(_, edge) => onSelect({ kind: "edge", id: edge.id })}
      onPaneClick={() => onSelect(null)}
      proOptions={{ hideAttribution: true }}
    >
      <Background gap={20} color="#cbd5e1" />
      <Controls showInteractive={false} />
    </ReactFlow>
  );
}

export default function TopologyGraph(props) {
  const height = useMemo(() => graphHeight(props.topology, props.hiddenTypes), [props.topology, props.hiddenTypes]);
  return (
    <div
      role="region"
      aria-label="Network topology graph"
      data-testid="topology-graph"
      style={{ height }}
      className="overflow-hidden rounded-xl border border-slate-200 bg-white"
    >
      <ReactFlowProvider>
        <Graph {...props} />
      </ReactFlowProvider>
    </div>
  );
}