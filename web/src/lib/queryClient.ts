import { QueryClient } from "@tanstack/react-query";

// Conservative defaults — we want fresh data on tab focus (operators
// flick between Sites and Metrics) but don't want to thrash the
// admin port. retry policy is tame: one extra try, then surface.
export const queryClient = new QueryClient({
    defaultOptions: {
        queries: {
            staleTime: 5_000,
            gcTime: 5 * 60_000,
            retry: 1,
            refetchOnWindowFocus: true,
            refetchOnReconnect: true,
        },
        mutations: {
            retry: false,
        },
    },
});
