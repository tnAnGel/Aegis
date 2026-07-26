// React-Query hook for the /admin/api/metrics/series endpoint.
//
// Wraps metricsApi.series with a 30-second refetch interval and a 15-second
// stale time so the dashboard keeps charts fresh without hammering the backend.
// The query key includes the range so switching between time windows triggers
// an immediate (stale-first) re-fetch.

import { useQuery } from "@tanstack/react-query";
import { metricsApi } from "@/api/client";
import type { MetricsRange, MetricsSeriesResponse } from "@/types";

export interface UseMetricsSeriesResult {
    data: MetricsSeriesResponse | undefined;
    isLoading: boolean;
    isError: boolean;
    error: Error | null;
    isFetching: boolean;
}

/**
 * useMetricsSeries(range)
 *
 * Fetches the time-bucketed fleet-wide metrics series for the given window.
 *
 * @param range  One of: "1h" | "6h" | "24h" | "7d" | "30d"
 * @returns      react-query result carrying MetricsSeriesResponse | undefined
 *
 * Query key:  ['metrics', 'series', range]
 * Refetch:    every 30 s
 * Stale time: 15 s
 */
export function useMetricsSeries(range: MetricsRange): UseMetricsSeriesResult {
    const query = useQuery<MetricsSeriesResponse, Error>({
        queryKey: ["metrics", "series", range],
        queryFn: () => metricsApi.series(range),
        refetchInterval: 30_000,
        staleTime: 15_000,
    });

    return {
        data: query.data,
        isLoading: query.isLoading,
        isError: query.isError,
        error: query.error,
        isFetching: query.isFetching,
    };
}
