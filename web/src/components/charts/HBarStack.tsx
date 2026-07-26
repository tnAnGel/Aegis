import {
    Bar,
    BarChart,
    CartesianGrid,
    Legend,
    ResponsiveContainer,
    Tooltip,
    XAxis,
    YAxis,
} from "recharts";

/// V171 — horizontal stacked bar list. Per-domain or per-filter
/// breakdowns where each row shows the same set of components
/// (allowed / challenged / denied). Bars stack so the row's total
/// length is the host's total traffic; segment colors show the
/// outcome mix at a glance.
export interface HBarRow {
    /** Y-axis label — e.g., the hostname. */
    name: string;
    /** Numeric segments keyed by series id. */
    [series: string]: string | number;
}

export interface HBarSeriesSpec {
    key: string;
    label: string;
    color: string;
}

export function HBarStack({
    rows,
    series,
    height = 240,
}: {
    rows: HBarRow[];
    series: HBarSeriesSpec[];
    height?: number;
}) {
    return (
        <div className="w-full" style={{ height }}>
            <ResponsiveContainer width="100%" height="100%">
                <BarChart
                    data={rows}
                    layout="vertical"
                    margin={{ top: 6, right: 10, bottom: 0, left: 0 }}
                >
                    <CartesianGrid
                        strokeDasharray="3 3"
                        horizontal={false}
                        opacity={0.15}
                    />
                    <XAxis
                        type="number"
                        tick={{ fontSize: 10, fill: "currentColor", opacity: 0.6 }}
                        axisLine={false}
                        tickLine={false}
                    />
                    <YAxis
                        type="category"
                        dataKey="name"
                        tick={{ fontSize: 11, fill: "currentColor" }}
                        width={140}
                        axisLine={false}
                        tickLine={false}
                    />
                    <Tooltip
                        contentStyle={{
                            background: "rgba(20,20,28,0.92)",
                            border: "1px solid rgba(255,255,255,0.1)",
                            borderRadius: 6,
                            fontSize: 11,
                        }}
                        cursor={{ fill: "rgba(255,255,255,0.05)" }}
                    />
                    <Legend
                        wrapperStyle={{ fontSize: 11, paddingTop: 4 }}
                        iconType="circle"
                    />
                    {series.map((s) => (
                        <Bar
                            key={s.key}
                            dataKey={s.key}
                            name={s.label}
                            stackId="a"
                            fill={s.color}
                            radius={[2, 2, 2, 2]}
                            isAnimationActive={false}
                        />
                    ))}
                </BarChart>
            </ResponsiveContainer>
        </div>
    );
}
