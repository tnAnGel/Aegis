import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";

/// V171 — donut chart with a centered big-number metric. Used for
/// status code distribution (2xx/4xx/5xx), filter attribution, etc.
/// Renders a thin ring so the center label is visible even on small
/// cards.
export interface Slice {
    name: string;
    value: number;
    color: string;
}

export function DonutChart({
    slices,
    centerValue,
    centerLabel,
    height = 200,
}: {
    slices: Slice[];
    centerValue: string;
    centerLabel?: string;
    height?: number;
}) {
    const total = slices.reduce((s, x) => s + x.value, 0);
    if (total === 0) {
        return (
            <div
                className="w-full grid place-items-center text-xs text-muted-foreground"
                style={{ height }}
            >
                no data yet
            </div>
        );
    }
    return (
        <div className="w-full relative" style={{ height }}>
            <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                    <Pie
                        data={slices}
                        dataKey="value"
                        nameKey="name"
                        innerRadius="62%"
                        outerRadius="92%"
                        paddingAngle={2}
                        startAngle={90}
                        endAngle={-270}
                        isAnimationActive={false}
                    >
                        {slices.map((s) => (
                            <Cell key={s.name} fill={s.color} stroke="transparent" />
                        ))}
                    </Pie>
                    <Tooltip
                        // V234 — explicit light text colours. recharts
                        // defaults tooltip item/label text to a dark colour,
                        // which was invisible on this dark popup background
                        // ("nothing visible" on hover). Force a light colour
                        // and disable the grey cursor wash over the slice.
                        contentStyle={{
                            background: "rgba(20,20,28,0.96)",
                            border: "1px solid rgba(255,255,255,0.12)",
                            borderRadius: 6,
                            fontSize: 11,
                            color: "#e5e7eb",
                        }}
                        itemStyle={{ color: "#e5e7eb" }}
                        labelStyle={{ color: "#e5e7eb" }}
                        cursor={{ fill: "rgba(255,255,255,0.04)" }}
                        formatter={(value: number, name) => [
                            `${value.toLocaleString()} (${((value / total) * 100).toFixed(1)}%)`,
                            name,
                        ]}
                    />
                </PieChart>
            </ResponsiveContainer>
            <div className="absolute inset-0 grid place-items-center pointer-events-none">
                <div className="text-center">
                    <div className="text-2xl font-semibold tabular">{centerValue}</div>
                    {centerLabel && (
                        <div className="text-[10px] uppercase tracking-wide text-muted-foreground mt-0.5">
                            {centerLabel}
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
}
