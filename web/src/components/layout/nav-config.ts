/**
 * Grouped navigation configuration for the AEGIS admin panel sidebar.
 *
 * All 33 route items from the original flat NAV array are distributed across
 * 6 collapsible groups plus 1 pinned-bottom Settings item.
 *
 * Import:
 *   import { NAV_GROUPS, SETTINGS_ITEM, STORAGE_KEY, NavGroup, NavItem } from "./nav-config";
 */

import {
    Activity,
    BarChart3,
    Bot,
    Brain,
    ChevronDown,
    Code2,
    Cpu,
    Download,
    FileCode2,
    FileLock2,
    Fingerprint,
    FlaskConical,
    Gauge,
    Globe,
    Globe2,
    Hourglass,
    KeyRound,
    LayoutDashboard,
    Lock,
    Map as MapIcon,
    Radio,
    ScanSearch,
    ScrollText,
    Search,
    Server,
    Settings,
    ShieldAlert,
    ShieldCheck,
    ShieldQuestion,
    Swords,
    Users,
    Zap,
} from "lucide-react";

// Re-export ChevronDown so NavGroup.tsx can import it from one place.
export { ChevronDown, Lock, Settings };

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface NavItem {
    /** English label — also used as the i18n fallback. */
    label: string;
    /**
     * Key into the `nav` i18n namespace (e.g. "item.security"). The sidebar
     * resolves this via t(); `label` is the fallback if no translation exists.
     */
    i18nKey: string;
    to: string;
    icon: React.ComponentType<{ className?: string }>;
}

export interface NavGroup {
    id: string;
    /** English label — also used as the i18n fallback. */
    label: string;
    /** Key into the `nav` i18n namespace (e.g. "group.security"). */
    i18nKey: string;
    icon: React.ComponentType<{ className?: string }>;
    items: NavItem[];
}

// ---------------------------------------------------------------------------
// localStorage key for persisted open-group state
// ---------------------------------------------------------------------------

export const STORAGE_KEY = "aegis:nav:open";

// ---------------------------------------------------------------------------
// Groups
// ---------------------------------------------------------------------------

export const NAV_GROUPS: NavGroup[] = [
    {
        id: "overview",
        label: "Overview",
        i18nKey: "group.overview",
        icon: LayoutDashboard,
        items: [
            { label: "Dashboard", i18nKey: "item.dashboard", to: "/", icon: LayoutDashboard },
            { label: "Metrics", i18nKey: "item.metrics", to: "/metrics", icon: BarChart3 },
        ],
    },
    {
        id: "traffic",
        label: "Traffic & Routing",
        i18nKey: "group.traffic",
        icon: Globe2,
        items: [
            { label: "Sites", i18nKey: "item.sites", to: "/sites", icon: Globe2 },
            { label: "Site map", i18nKey: "item.siteMap", to: "/site-map", icon: MapIcon },
            { label: "Upstreams", i18nKey: "item.upstreams", to: "/upstreams", icon: Server },
            { label: "Certificates", i18nKey: "item.certificates", to: "/certificates", icon: FileLock2 },
        ],
    },
    {
        id: "security",
        label: "Security",
        i18nKey: "group.security",
        icon: ShieldCheck,
        items: [
            { label: "Security", i18nKey: "item.security", to: "/security", icon: ShieldCheck },
            { label: "Bots", i18nKey: "item.bots", to: "/bots", icon: Bot },
            { label: "DDoS", i18nKey: "item.ddos", to: "/ddos", icon: ShieldAlert },
            { label: "Log", i18nKey: "item.logs", to: "/logs", icon: ScrollText },
            { label: "Rate limits", i18nKey: "item.rateLimits", to: "/rate-limits", icon: Gauge },
            { label: "Reputation", i18nKey: "item.reputation", to: "/reputation", icon: Fingerprint },
            { label: "GeoIP", i18nKey: "item.geoip", to: "/geoip", icon: Globe },
            { label: "Sigma rules", i18nKey: "item.sigma", to: "/sigma", icon: FileCode2 },
        ],
    },
    {
        id: "arsenal",
        label: "Defence Arsenal",
        i18nKey: "group.arsenal",
        icon: Swords,
        items: [
            { label: "Defence Arsenal", i18nKey: "item.arsenal", to: "/arsenal", icon: Swords },
            { label: "Challenge Ladder", i18nKey: "item.challenge", to: "/challenge", icon: ShieldQuestion },
            { label: "Scenarios", i18nKey: "item.scenarios", to: "/scenarios", icon: Zap },
            { label: "Active actions", i18nKey: "item.actuators", to: "/actuators", icon: Activity },
            { label: "Honeypots", i18nKey: "item.honeypots", to: "/honeypots", icon: FlaskConical },
            { label: "Tarpit", i18nKey: "item.tarpit", to: "/tarpit", icon: Hourglass },
            { label: "BGP RTBH", i18nKey: "item.bgp", to: "/bgp", icon: Radio },
            { label: "Privacy Pass", i18nKey: "item.privacyPass", to: "/privacy-pass", icon: KeyRound },
        ],
    },
    {
        id: "intel",
        label: "Intelligence & ML",
        i18nKey: "group.intel",
        icon: Brain,
        items: [
            { label: "Enrichment", i18nKey: "item.enrichment", to: "/enrichment", icon: Search },
            { label: "ML", i18nKey: "item.ml", to: "/ml", icon: Brain },
            { label: "Signature miner", i18nKey: "item.signatures", to: "/signatures", icon: ScanSearch },
            { label: "CrowdSec", i18nKey: "item.crowdsec", to: "/crowdsec", icon: Users },
        ],
    },
    {
        id: "operations",
        label: "Operations",
        i18nKey: "group.operations",
        icon: Server,
        items: [
            { label: "Workers", i18nKey: "item.workers", to: "/workers", icon: Cpu },
            { label: "Cluster", i18nKey: "item.cluster", to: "/cluster", icon: Server },
            { label: "Benchmark", i18nKey: "item.benchmark", to: "/benchmark", icon: BarChart3 },
            { label: "Telemetry", i18nKey: "item.telemetry", to: "/telemetry", icon: Activity },
            { label: "Updates", i18nKey: "item.updates", to: "/updates", icon: Download },
            { label: "Config editor", i18nKey: "item.config", to: "/config", icon: Code2 },
        ],
    },
];

// ---------------------------------------------------------------------------
// Pinned-bottom Settings item (rendered outside the group list)
// ---------------------------------------------------------------------------

export const SETTINGS_ITEM: NavItem = {
    label: "Settings",
    i18nKey: "item.settings",
    to: "/settings",
    icon: Settings,
};

// ---------------------------------------------------------------------------
// Helpers consumed by NavGroup.tsx
// ---------------------------------------------------------------------------

/**
 * Derive the initial set of open group IDs from localStorage, then
 * force-open whichever group contains the current pathname.
 */
export function getInitialOpen(groups: NavGroup[], pathname: string): Set<string> {
    let stored: string[];
    try {
        const raw = localStorage.getItem(STORAGE_KEY);
        stored = raw !== null ? (JSON.parse(raw) as string[]) : groups.map((g) => g.id);
    } catch {
        stored = groups.map((g) => g.id);
    }

    const openSet = new Set(stored);

    // Always open the group whose item matches the active route.
    for (const group of groups) {
        if (
            group.items.some((item) =>
                item.to === "/"
                    ? pathname === "/"
                    : pathname === item.to || pathname.startsWith(item.to + "/"),
            )
        ) {
            openSet.add(group.id);
        }
    }

    return openSet;
}

/**
 * Toggle a group's open state and persist the full set to localStorage.
 * Returns the new Set (immutable-style update).
 */
export function toggleGroup(id: string, openSet: Set<string>): Set<string> {
    const next = new Set(openSet);
    if (next.has(id)) {
        next.delete(id);
    } else {
        next.add(id);
    }
    localStorage.setItem(STORAGE_KEY, JSON.stringify([...next]));
    return next;
}
