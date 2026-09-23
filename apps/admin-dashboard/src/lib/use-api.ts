'use client';

import { useCallback, useEffect, useRef, useState } from 'react';

// Fetches on mount; on failure keeps `fallback` and reports `live: false`
// so pages can label the data as demo data rather than fake-live.
// `reload()` re-runs the fetcher (e.g. after a mutation).
export function useApiData<T>(fetcher: () => Promise<T>, fallback: T): { data: T; live: boolean; reload: () => void } {
  const [data, setData] = useState(fallback);
  const [live, setLive] = useState(false);
  const fetcherRef = useRef(fetcher);
  fetcherRef.current = fetcher;

  const run = useCallback(() => {
    fetcherRef.current()
      .then((d) => { setData(d); setLive(true); })
      .catch(() => { /* offline — fallback stays */ });
  }, []);

  useEffect(() => {
    let cancelled = false;
    fetcherRef.current()
      .then((d) => { if (!cancelled) { setData(d); setLive(true); } })
      .catch(() => { /* offline — fallback stays */ });
    return () => { cancelled = true; };
  }, []);

  return { data, live, reload: run };
}
