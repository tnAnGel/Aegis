import {
    createRootRoute,
    createRoute,
    createRouter,
} from "@tanstack/react-router";
import { AppLayoutV2 } from "@/v2/AppLayoutV2";
import { NotFoundV2Page } from "@/pages/v2/NotFound";
import { DashboardV2Page } from "@/pages/v2/Dashboard";
import { MLPageV2 } from "@/pages/v2/ML";
import { CrowdSecPageV2 } from "@/pages/v2/CrowdSec";
import { ClusterPageV2 } from "@/pages/v2/Cluster";
import { UpstreamsV2Page } from "@/pages/v2/Upstreams";
import { CertificatesV2Page } from "@/pages/v2/Certificates";
import { SecurityV2Page } from "@/pages/v2/Security";
import { BotsV2Page } from "@/pages/v2/Bots";
import { DdosV2Page } from "@/pages/v2/Ddos";
import { MetricsV2Page } from "@/pages/v2/Metrics";
import { SettingsV2Page } from "@/pages/v2/Settings";
import { ReputationV2Page } from "@/pages/v2/Reputation";
import { GeoIPV2Page } from "@/pages/v2/GeoIP";
import { SigmaV2Page } from "@/pages/v2/Sigma";
import { SignatureMineV2Page } from "@/pages/v2/SignatureMine";
import { TelemetryV2Page } from "@/pages/v2/Telemetry";
import { RateLimitsV2Page } from "@/pages/v2/RateLimits";
import { ConfigEditorV2Page } from "@/pages/v2/ConfigEditor";
import { LogsV2Page } from "@/pages/v2/Logs";
import { ArsenalPage } from "@/pages/v2/Arsenal";
import { ChallengeLadderPage } from "@/pages/v2/ChallengeLadder";
import { ScenariosPage } from "@/pages/v2/Scenarios";
import { WorkersPage } from "@/pages/v2/Workers";
import { BenchmarkPage } from "@/pages/v2/Benchmark";
import { UpdatesPage } from "@/pages/v2/Updates";
import { SitesV2Page } from "@/pages/v2/Sites";
import { SiteMapHostsV2Page, SiteMapHostV2Page } from "@/pages/v2/SiteMap";
import { SiteDetailV2Page } from "@/pages/v2/SiteDetail";
import { ActuatorsPage } from "@/pages/v2/Actuators";
import { BgpRtbhPage } from "@/pages/v2/BgpRtbh";
import { EnrichmentPage } from "@/pages/v2/Enrichment";
import { HoneypotsPage } from "@/pages/v2/Honeypots";
import { TarpitPage } from "@/pages/v2/Tarpit";
import { PrivacyPassPage } from "@/pages/v2/PrivacyPass";

// ── Root route: the V2 shell is the ONE AND ONLY UI ──────────────────────────
// AppLayoutV2 renders its own <Outlet /> internally. 404s render NotFoundV2Page
// INSIDE the shell via notFoundComponent (the canonical TanStack v1 pattern —
// a `path: "*"` splat route is NOT used; in 1.78 it shadowed the index route,
// which is what made "/" render "Not Found"). The legacy V1 tree was removed
// entirely.
const rootRoute = createRootRoute({
    component: AppLayoutV2,
    notFoundComponent: NotFoundV2Page,
});

const make = (path: string, Component: () => JSX.Element) =>
    createRoute({ getParentRoute: () => rootRoute, path, component: Component });

const routeTree = rootRoute.addChildren([
    make("/", DashboardV2Page),
    make("/metrics", MetricsV2Page),
    make("/sites", SitesV2Page),
    createRoute({
        getParentRoute: () => rootRoute,
        path: "/sites/$host",
        component: SiteDetailV2Page,
    }),
    make("/site-map", SiteMapHostsV2Page),
    createRoute({
        getParentRoute: () => rootRoute,
        path: "/site-map/$host",
        component: SiteMapHostV2Page,
    }),
    make("/upstreams", UpstreamsV2Page),
    make("/certificates", CertificatesV2Page),
    make("/security", SecurityV2Page),
    make("/bots", BotsV2Page),
    make("/ddos", DdosV2Page),
    make("/rate-limits", RateLimitsV2Page),
    make("/reputation", ReputationV2Page),
    make("/geoip", GeoIPV2Page),
    make("/sigma", SigmaV2Page),
    make("/arsenal", ArsenalPage),
    make("/challenge", ChallengeLadderPage),
    make("/scenarios", ScenariosPage),
    make("/actuators", ActuatorsPage),
    make("/enrichment", EnrichmentPage),
    make("/honeypots", HoneypotsPage),
    make("/tarpit", TarpitPage),
    make("/bgp", BgpRtbhPage),
    make("/privacy-pass", PrivacyPassPage),
    make("/ml", MLPageV2),
    make("/signatures", SignatureMineV2Page),
    make("/crowdsec", CrowdSecPageV2),
    make("/cluster", ClusterPageV2),
    make("/telemetry", TelemetryV2Page),
    make("/config", ConfigEditorV2Page),
    make("/logs", LogsV2Page),
    // Backward-compat alias: /audit → the same logs view.
    make("/audit", LogsV2Page),
    make("/workers", WorkersPage),
    make("/benchmark", BenchmarkPage),
    make("/updates", UpdatesPage),
    make("/settings", SettingsV2Page),
]);

// The Vite bundle is served under /admin/ui/ (see vite.config.ts). Telling the
// router its basepath means it builds links as `/admin/ui/sites` instead of
// bare `/sites` — without this every in-app navigation lands on a server 404.
export const router = createRouter({ routeTree, basepath: "/admin/ui" });

declare module "@tanstack/react-router" {
    interface Register {
        router: typeof router;
    }
}
