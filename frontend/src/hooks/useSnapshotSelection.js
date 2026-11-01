import { useState } from "react";

import { listProjects, listSnapshots } from "../api/endpoints.js";
import { useAsyncData } from "./useAsyncData.js";

/**
 * Project + snapshot pickers shared by pages. `null` choices mean "follow the default":
 * the focused snapshot (arriving from another tab), else the first project / latest snapshot.
 */
export function useSnapshotSelection(focus = null) {
  const [chosenProject, setChosenProject] = useState(null);
  const [chosenSnapshot, setChosenSnapshot] = useState(null);

  const projects = useAsyncData("projects", listProjects);
  const projectId =
    chosenProject ?? focus?.projectId ?? projects.data?.[0]?.id ?? null;
  const snapshots = useAsyncData(projectId, (signal) =>
    listSnapshots(projectId, signal),
  );

  const has = (id) => snapshots.data?.some((s) => s.id === id);
  const snapshotId =
    chosenSnapshot && has(chosenSnapshot)
      ? chosenSnapshot
      : focus && focus.projectId === projectId && has(focus.snapshotId)
        ? focus.snapshotId
        : (snapshots.data?.[0]?.id ?? null);

  return {
    projects,
    snapshots,
    projectId,
    snapshotId,
    chooseProject: (id) => {
      setChosenProject(id);
      setChosenSnapshot(null);
    },
    chooseSnapshot: setChosenSnapshot,
  };
}