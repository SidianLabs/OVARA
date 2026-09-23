'use client';

import { useEffect, useRef, useState } from 'react';

// Fetches once on mount; on failure keeps `fallback` and reports `live: false`
// so pages can label the data as demo data rather than fake-live.
export function useApiData<T>(fetcher: () => Promise<T>, fallback: T): { data: T; live: boolean } {
  const [data, setData] = useState(fallback);
  const [live, setLive] = useState(false);
  const fetcherRef = useRef(fetcher);
  fetcherRef.current = fetcher;

  useEffect(() => {
    let cancelled = false;
    fetcherRef.current()
      .then((d) => { if (!cancelled) { setData(d); setLive(true); } })
      .catch(() => { /* offline — fallback stays */ });
    return () => { cancelled = true; };
  }, []);

  return { data, live };
}
