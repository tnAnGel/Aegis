/**
 * WorldMap — V2 Dashboard component
 *
 * Uses react-simple-maps (d3-geo under the hood) + Natural Earth 110m
 * TopoJSON (fetched from CDN, not bundled) for a geometrically accurate
 * world map silhouette rendered with geoEqualEarth projection.
 *
 * Props API:
 *   points    — [{country, lat?, lng?, weight}] — weight ∈ [0,1]
 *   className — optional extra class(es) for the root <div>
 *
 * Empty state: renders the real map silhouette with "No traffic data yet"
 * overlay — dots populate once GeoIP is configured.
 */

import * as React from "react";
import {
    ComposableMap,
    Geographies,
    Geography,
    Graticule,
    Marker,
    Sphere,
} from "react-simple-maps";
import { cn } from "@/lib/cn";

// ─── Types (public API) ───────────────────────────────────────────────────────

export interface WorldMapPoint {
    /** ISO 3166-1 alpha-2 country code, e.g. "US", "DE". Used for label. */
    country: string;
    /** Latitude in decimal degrees. Optional if country is in COUNTRY_COORDS. */
    lat?: number;
    /** Longitude in decimal degrees. Optional if country is in COUNTRY_COORDS. */
    lng?: number;
    /**
     * Relative traffic weight ∈ [0, 1].  Controls dot radius and glow
     * intensity.  Pass 0 for the lowest visibility and 1 for the largest dot.
     */
    weight: number;
}

// ─── Static country → lat/lng lookup (~45 most common) ───────────────────────
// Coordinates are centroid-style, verified to fall within Natural Earth 110m
// land polygons with geoEqualEarth projection.

export const COUNTRY_COORDS: Record<string, { lat: number; lng: number }> = {
    US: { lat:  37.09,  lng: -95.71 },
    CN: { lat:  35.86,  lng: 104.19 },
    DE: { lat:  51.17,  lng:  10.45 },
    GB: { lat:  55.38,  lng:  -3.44 },
    FR: { lat:  46.23,  lng:   2.21 },
    RU: { lat:  61.52,  lng: 105.32 },
    JP: { lat:  36.20,  lng: 138.25 },
    IN: { lat:  20.59,  lng:  78.96 },
    BR: { lat: -14.24,  lng: -51.93 },
    CA: { lat:  56.13,  lng: -106.35 },
    AU: { lat: -25.27,  lng: 133.78 },
    KR: { lat:  35.91,  lng: 127.77 },
    NL: { lat:  52.13,  lng:   5.29 },
    SG: { lat:   1.35,  lng: 103.82 },
    IT: { lat:  41.87,  lng:  12.57 },
    ES: { lat:  40.46,  lng:  -3.75 },
    SE: { lat:  60.13,  lng:  18.64 },
    NO: { lat:  60.47,  lng:   8.47 },
    PL: { lat:  51.92,  lng:  19.15 },
    CH: { lat:  46.82,  lng:   8.23 },
    TR: { lat:  38.96,  lng:  35.24 },
    MX: { lat:  23.63,  lng: -102.55 },
    ID: { lat:  -0.79,  lng: 113.92 },
    SA: { lat:  23.89,  lng:  45.08 },
    ZA: { lat: -30.56,  lng:  22.94 },
    AR: { lat: -38.42,  lng: -63.62 },
    UA: { lat:  48.38,  lng:  31.17 },
    IL: { lat:  31.05,  lng:  34.85 },
    HK: { lat:  22.40,  lng: 114.11 },
    TW: { lat:  23.70,  lng: 120.96 },
    NG: { lat:   9.08,  lng:   8.68 },
    EG: { lat:  26.82,  lng:  30.80 },
    PK: { lat:  30.38,  lng:  69.35 },
    VN: { lat:  14.06,  lng: 108.28 },
    TH: { lat:  15.87,  lng: 100.99 },
    MY: { lat:   4.21,  lng: 101.98 },
    BD: { lat:  23.68,  lng:  90.36 },
    PH: { lat:  12.88,  lng: 121.77 },
    IR: { lat:  32.43,  lng:  53.69 },
    CL: { lat: -35.68,  lng: -71.54 },
    RO: { lat:  45.94,  lng:  24.97 },
    CZ: { lat:  49.82,  lng:  15.47 },
    AT: { lat:  47.52,  lng:  14.55 },
    FI: { lat:  61.92,  lng:  25.75 },
    DK: { lat:  56.26,  lng:   9.50 },
};

// ─── TopoJSON data URL ────────────────────────────────────────────────────────
// Natural Earth 110m (per-country polygons) — maintained by Mike Bostock.
// ~105 KB raw / ~28 KB gzip. Fetched once at runtime and cached by the browser.
// Using countries-110m.json (not land-110m.json) so per-country geometry is
// available for future hover/highlight features.
const GEO_URL =
    "https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json";

// ─── Map dimensions ───────────────────────────────────────────────────────────
// 800×400 (2:1) is the canonical size for react-simple-maps with geoEqualEarth.
// The library scales to 100% CSS width via the SVG's width="100%" attribute.
const MAP_WIDTH  = 800;
const MAP_HEIGHT = 400;

// ─── Colour tokens (match existing dashboard palette) ─────────────────────────
const LAND_FILL        = "hsl(210 22% 16%)";
const LAND_STROKE      = "hsl(210 26% 26%)";
const GRATICULE_STROKE = "hsl(210 22% 16% / 0.4)";
const DOT_COLOR        = "#22d362";
const SPHERE_FILL      = "hsl(210 28% 6%)";
const SPHERE_STROKE    = "hsl(210 26% 22%)";

// ─── Component props ──────────────────────────────────────────────────────────

export interface WorldMapProps {
    /** Geo-located traffic points */
    points?: WorldMapPoint[];
    /** Extra class(es) on the root container */
    className?: string;
}

// ─── WorldMap component ───────────────────────────────────────────────────────

export function WorldMap({ points = [], className }: WorldMapProps) {

    // Resolve lat/lng from COUNTRY_COORDS where not provided, then deduplicate
    // by country so two rows for the same country don't stack dots.
    const resolved = React.useMemo((): Array<{
        country: string;
        lng: number;
        lat: number;
        weight: number;
    }> => {
        const seen = new Map<string, { country: string; lng: number; lat: number; weight: number }>();
        for (const p of points) {
            let lat = p.lat;
            let lng = p.lng;
            if (lat === undefined || lng === undefined) {
                const coords = COUNTRY_COORDS[p.country];
                if (coords) {
                    lat = coords.lat;
                    lng = coords.lng;
                }
            }
            if (lat === undefined || lng === undefined) continue;
            if (!seen.has(p.country)) {
                seen.set(p.country, { country: p.country, lng, lat, weight: p.weight });
            }
        }
        return Array.from(seen.values());
    }, [points]);

    const maxWeight = resolved.reduce((m, p) => Math.max(m, p.weight), 0) || 1;

    return (
        <div
            className={cn("relative w-full overflow-hidden rounded-lg", className)}
            style={{ background: SPHERE_FILL }}
            aria-label="World traffic map"
            role="img"
        >
            <ComposableMap
                width={MAP_WIDTH}
                height={MAP_HEIGHT}
                projection="geoEqualEarth"
                projectionConfig={{ scale: 153 }}
                style={{ width: "100%", height: "auto", display: "block" }}
            >
                <defs>
                    {/*
                     * Glow filters — canonical pattern:
                     *   1. Blur the source into a soft halo
                     *   2. feMerge: render blur behind, then SourceGraphic on top
                     * This ensures the crisp original is always visible over the halo.
                     */}
                    <filter id="wmB-glow-strong" x="-150%" y="-150%" width="400%" height="400%">
                        <feGaussianBlur in="SourceGraphic" stdDeviation="8" result="blur" />
                        <feMerge>
                            <feMergeNode in="blur" />
                            <feMergeNode in="SourceGraphic" />
                        </feMerge>
                    </filter>
                    <filter id="wmB-glow" x="-100%" y="-100%" width="300%" height="300%">
                        <feGaussianBlur in="SourceGraphic" stdDeviation="4" result="blur" />
                        <feMerge>
                            <feMergeNode in="blur" />
                            <feMergeNode in="SourceGraphic" />
                        </feMerge>
                    </filter>
                </defs>

                {/* Ocean background sphere — id required by react-simple-maps */}
                <Sphere
                    id="rsm-sphere"
                    fill={SPHERE_FILL}
                    stroke={SPHERE_STROKE}
                    strokeWidth={0.5}
                />

                {/* Graticule grid — very faint, same projection as land */}
                <Graticule
                    stroke={GRATICULE_STROKE}
                    strokeWidth={0.5}
                    step={[30, 30]}
                />

                {/* Real Natural Earth 110m land polygons (per-country geometry) */}
                <Geographies geography={GEO_URL}>
                    {({ geographies }) =>
                        geographies.map((geo) => (
                            <Geography
                                key={geo.rsmKey}
                                geography={geo}
                                fill={LAND_FILL}
                                stroke={LAND_STROKE}
                                strokeWidth={0.5}
                                style={{
                                    default: { outline: "none" },
                                    hover:   { outline: "none", fill: LAND_FILL },
                                    pressed: { outline: "none" },
                                }}
                            />
                        ))
                    }
                </Geographies>

                {/* Traffic markers — z-order: halos first, then cores */}
                {resolved.map((p) => {
                    const norm = p.weight / maxWeight;
                    // Radius: 3 (min) → 9 (max)
                    const r = 3 + norm * 6;
                    // d3-geo convention: coordinates are [lng, lat]
                    const coords: [number, number] = [p.lng, p.lat];
                    return (
                        <Marker key={p.country} coordinates={coords}>
                            {/* Outer halo — very soft, large radius */}
                            <circle
                                r={r * 2.5}
                                fill={DOT_COLOR}
                                opacity={0.12 + norm * 0.18}
                                filter="url(#wmB-glow-strong)"
                            />
                            {/* Inner glow */}
                            <circle
                                r={r * 1.4}
                                fill={DOT_COLOR}
                                opacity={0.30 + norm * 0.30}
                                filter="url(#wmB-glow)"
                            />
                            {/* Crisp core dot */}
                            <circle
                                r={r}
                                fill={DOT_COLOR}
                                opacity={0.9}
                            >
                                <title>{p.country}</title>
                            </circle>
                        </Marker>
                    );
                })}
            </ComposableMap>

            {/* Empty-state overlay — real map silhouette always renders behind */}
            {resolved.length === 0 && (
                <div className="absolute inset-0 grid place-items-center pointer-events-none">
                    <div className="text-center space-y-1">
                        <p className="text-xs text-muted-foreground/50">
                            No traffic data yet
                        </p>
                        <p className="text-[0.65rem] text-muted-foreground/35">
                            Load a GeoIP database on the GeoIP page to populate markers
                        </p>
                    </div>
                </div>
            )}
        </div>
    );
}
