import {
    Area,
    AreaChart,
    CartesianGrid,
    Legend,
    ResponsiveContainer,
    Tooltip,
    XAxis,
    YAxis,
} from "recharts";

/// V175 — historical stacked/overlay area chart.
///
/// Unlike LiveAreaChart (which derives per-second rates from a
/// rolling ring buffer of cumulative counters), this component
/// accepts an **explicit** data array of MetricPoint rows that
/// already carry absolute or pre-computed values. It is the right
/// primitive for any query that returns a historical range from the
/// API (e.g., /api/metrics/history?from=…&to=…) or for data that
/// has already been shaped outside the component.
///
/// The x-axis key is always `t` (Unix epoch ms). Each MetricPoint
/// must carry exactly the keys listed in the `series` config. Values
/// are rendered as-is — no delta derivation, no ring buffer.
///
/// Props
/// ─────
/// data        Array of MetricPoint rows. Each row MUST have `t`
///             (Unix ms) plus one numeric field for every series key.
/// series      Array of SeriesConfig objects describing which fields
///             to draw, their display label, stroke color, and
///             whether each individual series should participate in
///             the stacked sum. Mixing stacked + non-stacked in the
///             same chart is valid: non-stacked series render as
///             independent overlays on top of the stack.
/// height      Container height in px. Default 220.
/// stacked     Master toggle. When false every series is an overlay
///             regardless of its own `stacked` field. Default true.
/// xFormatter  Optional override for the x-axis tick label. Defaults
///             to HH:MM on the same day, or "Jun 3 14:00" across
///             day boundaries.
/// yFormatter  Optional override for y-axis tick labels and the
///             tooltip value. Defaults to a compact SI formatter
///             (1k, 2.3M, …).
/// showLegend  Show the recharts Legend row. Default true.
/// showGrid    Show the horizontal CartesianGrid. Default true.

// ─── Types ───────────────────────────────────────────────────────────────────

/** A single point in the historical data array. */
export interface MetricPoint {
    /** Unix epoch milliseconds — used as the x-axis value. */
    t: number;
    /** Arbitrary numeric series values keyed by series.key. */
    [key: string]: number;
}

/** Per-series rendering configuration. */
export interface SeriesConfig {
    /** Field name in MetricPoint rows. */
    key: string;
    /** Human-readable label for legend and tooltip. */
    label: string;
    /** Stroke and gradient stop color (any valid CSS color string). */
    color: string;
    /**
     * When true this series contributes to the stack sum.
     * When false it renders as an independent overlay line/area.
     * Ignored when the chart-level `stacked` prop is false.
     * Default true.
     */
    stacked?: boolean;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/** Compact SI number formatter: 1234 → "1.2k", 1_200_000 → "1.2M". */
function siCompact(v: number): string {
    if (!Number.isFinite(v)) return "—";
    const abs = Math.abs(v);
    if (abs >= 1_000_000) return `${(v / 1_000_000).toFixed(1)}M`;
    if (abs >= 1_000) return `${(v / 1_000).toFixed(1)}k`;
    if (abs < 10) return v.toFixed(2);
    return v.toFixed(0);
}

/**
 * Derive total per series so the legend can show sum labels.
 * Uses simple sum — appropriate for both rate-per-second and
 * absolute count series (caller decides what the data represents).
 */
function seriesTotal(data: MetricPoint[], key: string): number {
    return data.reduce((acc, row) => acc + (row[key] ?? 0), 0);
}

// Default x-axis tick formatter. Detects whether the data spans
// multiple calendar days and adjusts accordingly.
function makeDefaultXFormatter(data: MetricPoint[]) {
    if (data.length < 2) {
        return (v: number) =>
            new Date(v).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    }
    const first = new Date(data[0]!.t);
    const last  = new Date(data[data.length - 1]!.t);
    const sameDay =
        first.getFullYear() === last.getFullYear() &&
        first.getMonth()    === last.getMonth() &&
        first.getDate()     === last.getDate();

    return (v: number) => {
        const d = new Date(v);
        if (sameDay) {
            return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
        }
        return d.toLocaleDateString([], { month: "short", day: "numeric" }) +
               " " +
               d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    };
}

// ─── Legend with totals ───────────────────────────────────────────────────────

function LegendWithTotals({
    series,
    data,
    yFormatter,
}: {
    series: SeriesConfig[];
    data: MetricPoint[];
    yFormatter: (v: number) => string;
}) {
    return (
        <div className="flex flex-wrap items-center gap-x-5 gap-y-1.5 pt-2 px-1">
            {series.map((s) => {
                const total = seriesTotal(data, s.key);
                return (
                    <div key={s.key} className="flex items-center gap-1.5 text-xs">
                        <span
                            className="inline-block h-2 w-2 rounded-full shrink-0"
                            style={{ background: s.color }}
                        />
                        <span className="text-muted-foreground">{s.label}</span>
                        <span className="tabular-nums font-semibold text-foreground">
                            {yFormatter(total)}
                        </span>
                    </div>
                );
            })}
        </div>
    );
}

// ─── Component ───────────────────────────────────────────────────────────────

export function HistoricalAreaChart({
    data,
    series,
    height = 220,
    stacked = true,
    xFormatter,
    yFormatter = siCompact,
    showLegend = true,
    showGrid = true,
}: {
    data: MetricPoint[];
    series: SeriesConfig[];
    height?: number;
    stacked?: boolean;
    xFormatter?: (v: number) => string;
    yFormatter?: (v: number) => string;
    showLegend?: boolean;
    showGrid?: boolean;
}) {
    const xFmt = xFormatter ?? makeDefaultXFormatter(data);

    // Empty-state: no data rows at all.
    if (data.length === 0) {
        return (
            <div
                className="w-full grid place-items-center border border-dashed border-muted rounded-md"
                style={{ height }}
            >
                <div className="text-center">
                    <div className="text-xs text-muted-foreground">No data</div>
                    <div className="text-[10px] text-muted-foreground/70 mt-0.5">
                        select a time range to load history
                    </div>
                </div>
            </div>
        );
    }

    // All-zero check: prevent a collapsed flat-line chart that looks
    // broken. Mirror the same guard LiveAreaChart uses.
    const totalSum = data.reduce(
        (sum, row) => sum + series.reduce((s, sp) => s + (row[sp.key] ?? 0), 0),
        0,
    );
    if (totalSum === 0) {
        return (
            <div
                className="w-full grid place-items-center border border-dashed border-muted rounded-md"
                style={{ height }}
            >
                <div className="text-center">
                    <div className="text-xs text-muted-foreground">0 events</div>
                    <div className="text-[10px] text-muted-foreground/70 mt-0.5">
                        no traffic in this period
                    </div>
                </div>
            </div>
        );
    }

    // Split series into stacked vs overlay groups so we can assign
    // stackId only to those that participate in the stack.
    const STACK_ID = "hist-stack";

    return (
        <div className="w-full space-y-1" style={{ minWidth: 0 }}>
            <div style={{ height }}>
                <ResponsiveContainer width="100%" height="100%">
                    <AreaChart
                        data={data}
                        margin={{ top: 8, right: 8, bottom: 0, left: -8 }}
                    >
                        <defs>
                            {series.map((s) => (
                                <linearGradient
                                    key={s.key}
                                    id={`hist-${s.key}`}
                                    x1="0"
                                    y1="0"
                                    x2="0"
                                    y2="1"
                                >
                                    <stop offset="0%"   stopColor={s.color} stopOpacity={0.45} />
                                    <stop offset="100%" stopColor={s.color} stopOpacity={0.02} />
                                </linearGradient>
                            ))}
                        </defs>

                        {showGrid && (
                            <CartesianGrid
                                strokeDasharray="3 3"
                                opacity={0.15}
                                vertical={false}
                            />
                        )}

                        <XAxis
                            dataKey="t"
                            tickFormatter={xFmt}
                            tick={{ fontSize: 10, fill: "currentColor", opacity: 0.6 }}
                            axisLine={false}
                            tickLine={false}
                            minTickGap={48}
                            scale="time"
                            type="number"
                            domain={["dataMin", "dataMax"]}
                        />
                        <YAxis
                            tickFormatter={yFormatter}
                            tick={{ fontSize: 10, fill: "currentColor", opacity: 0.6 }}
                            axisLine={false}
                            tickLine={false}
                            width={42}
                        />

                        <Tooltip
                            contentStyle={{
                                background:   "rgba(20,20,28,0.96)",
                                border:       "1px solid rgba(255,255,255,0.12)",
                                borderRadius: 6,
                                fontSize:     11,
                                color:        "#e5e7eb",
                            }}
                            itemStyle={{ color: "#e5e7eb" }}
                            labelStyle={{ color: "#9ca3af" }}
                            labelFormatter={(v) => {
                                const d = new Date(v as number);
                                return d.toLocaleString([], {
                                    month:   "short",
                                    day:     "numeric",
                                    hour:    "2-digit",
                                    minute:  "2-digit",
                                    second:  "2-digit",
                                });
                            }}
                            formatter={(value: number, _name, item) => [
                                yFormatter(value),
                                (item.name as string) ?? "",
                            ]}
                        />

                        {/* Recharts built-in Legend hidden — we render our own below */}
                        {showLegend && (
                            <Legend
                                // Use a non-rendering wrapper to let recharts track
                                // series metadata while we override the visual below.
                                wrapperStyle={{ display: "none" }}
                            />
                        )}

                        {series.map((s) => {
                            const participatesInStack =
                                stacked && (s.stacked !== false);
                            return (
                                <Area
                                    key={s.key}
                                    type="monotone"
                                    dataKey={s.key}
                                    name={s.label}
                                    stroke={s.color}
                                    strokeWidth={1.5}
                                    fill={`url(#hist-${s.key})`}
                                    stackId={participatesInStack ? STACK_ID : undefined}
                                    isAnimationActive={false}
                                    dot={false}
                                    activeDot={{ r: 3, strokeWidth: 0 }}
                                />
                            );
                        })}
                    </AreaChart>
                </ResponsiveContainer>
            </div>

            {/* Custom legend row with per-series sum totals */}
            {showLegend && (
                <LegendWithTotals
                    series={series}
                    data={data}
                    yFormatter={yFormatter}
                />
            )}
        </div>
    );
}
