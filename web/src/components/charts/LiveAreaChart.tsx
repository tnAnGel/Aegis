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

/// V171 — live stacked area chart. Renders one filled series per
/// `series` config; auto-scales y; clean dark/light grid; gradient
/// fills. The rows come from useTimeSeriesMulti.
export interface AreaSeries {
    /** Data key in the row object. */
    key: string;
    /** Human label for legend + tooltip. */
    label: string;
    /** Stroke / gradient color. */
    color: string;
}

export function LiveAreaChart({
    rows,
    series,
    height = 200,
    stacked = true,
}: {
    rows: Array<{ t: number } & Record<string, number>>;
    series: AreaSeries[];
    height?: number;
    stacked?: boolean;
}) {
    // V174 — if every value across the window is exactly zero (e.g.,
    // upstream counters when every request gets blocked before reaching
    // upstream), Recharts collapses min == max == 0 and the chart looks
    // empty. Show an explicit "no events" hint instead.
    const totalSum = rows.reduce(
        (sum, row) => sum + series.reduce((s, sp) => s + (row[sp.key] ?? 0), 0),
        0,
    );
    if (rows.length > 0 && totalSum === 0) {
        return (
            <div
                className="w-full grid place-items-center border border-dashed border-muted rounded-md"
                style={{ height }}
            >
                <div className="text-center">
                    <div className="text-xs text-muted-foreground">0 events / sec</div>
                    <div className="text-[10px] text-muted-foreground/70 mt-0.5">
                        no traffic in this window
                    </div>
                </div>
            </div>
        );
    }
    return (
        <div className="w-full" style={{ height }}>
            <ResponsiveContainer width="100%" height="100%">
                <AreaChart
                    data={rows}
                    margin={{ top: 8, right: 8, bottom: 0, left: -8 }}
                >
                    <defs>
                        {series.map((s) => (
                            <linearGradient
                                key={s.key}
                                id={`live-${s.key}`}
                                x1="0"
                                y1="0"
                                x2="0"
                                y2="1"
                            >
                                <stop offset="0%" stopColor={s.color} stopOpacity={0.45} />
                                <stop offset="100%" stopColor={s.color} stopOpacity={0.02} />
                            </linearGradient>
                        ))}
                    </defs>
                    <CartesianGrid
                        strokeDasharray="3 3"
                        opacity={0.15}
                        vertical={false}
                    />
                    <XAxis
                        dataKey="t"
                        tickFormatter={(v) =>
                            new Date(v).toLocaleTimeString([], {
                                hour: "2-digit",
                                minute: "2-digit",
                                second: "2-digit",
                            })
                        }
                        tick={{ fontSize: 10, fill: "currentColor", opacity: 0.6 }}
                        axisLine={false}
                        tickLine={false}
                        minTickGap={40}
                    />
                    <YAxis
                        tick={{ fontSize: 10, fill: "currentColor", opacity: 0.6 }}
                        axisLine={false}
                        tickLine={false}
                        width={40}
                    />
                    <Tooltip
                        contentStyle={{
                            background: "rgba(20,20,28,0.96)",
                            border: "1px solid rgba(255,255,255,0.12)",
                            borderRadius: 6,
                            fontSize: 11,
                            color: "#e5e7eb",
                        }}
                        itemStyle={{ color: "#e5e7eb" }}
                        labelStyle={{ color: "#9ca3af" }}
                        labelFormatter={(v) =>
                            new Date(v as number).toLocaleTimeString()
                        }
                        formatter={(value: number, _name, item) => [
                            value.toFixed(2),
                            (item.dataKey as string) ?? "",
                        ]}
                    />
                    <Legend
                        wrapperStyle={{ fontSize: 11, paddingTop: 6 }}
                        iconType="circle"
                    />
                    {series.map((s) => (
                        <Area
                            key={s.key}
                            type="monotone"
                            dataKey={s.key}
                            name={s.label}
                            stroke={s.color}
                            strokeWidth={1.5}
                            fill={`url(#live-${s.key})`}
                            stackId={stacked ? "stack" : undefined}
                            isAnimationActive={false}
                        />
                    ))}
                </AreaChart>
            </ResponsiveContainer>
        </div>
    );
}
