import { useCallback, useEffect, useState } from "react";

import { getHealth } from "../api/endpoints.js";

/** Loads /api/health/ once and exposes a manual refresh. */
export function useHealth() {
  const [state, setState] = useState({ phase: "loading", data: null, error: null });
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    getHealth(controller.signal)
      .then((data) => setState({ phase: data?.status === "ok" ? "ok" : "degraded", data, error: null }))
      .catch((error) => {
        if (error?.name === "AbortError") return;
        setState({ phase: "unreachable", data: null, error });
      });
    return () => controller.abort();
  }, [attempt]);

  const refresh = useCallback(() => {
    setState({ phase: "loading", data: null, error: null });
    setAttempt((n) => n + 1);
  }, []);

  return { ...state, refresh };
}
