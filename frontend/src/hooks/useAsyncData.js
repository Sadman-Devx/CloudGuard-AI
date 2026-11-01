import { useEffect, useRef, useState } from "react";

/**
 * Load data for a request `key` (null = idle). Results are tagged with the key they belong to, so
 * switching keys shows `loading` immediately without setting state synchronously inside an effect.
 */
export function useAsyncData(key, load) {
  const [state, setState] = useState({ key: null, data: null, error: null });
  const loadRef = useRef(load);

  useEffect(() => {
    loadRef.current = load;
  });

  useEffect(() => {
    if (key == null) return undefined;
    const controller = new AbortController();
    loadRef
      .current(controller.signal)
      .then((data) => setState({ key, data, error: null }))
      .catch((error) => {
        if (error?.name !== "AbortError") setState({ key, data: null, error });
      });
    return () => controller.abort();
  }, [key]);

  const current = state.key === key;
  return {
    data: current ? state.data : null,
    error: current ? state.error : null,
    loading: key != null && !current,
  };
}