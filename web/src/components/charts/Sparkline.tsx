import { Area, AreaChart, ResponsiveContainer, YAxis } from "recharts";
import type { SeriesPoint } from "./useTimeSeries";

/// V171 — minimal sparkline area chart for embedding under KPI big
/// numbers. No axes, no grid, no tooltip — just the line + soft
/// gradient fill. Auto-scales to data min/max so even tiny rates
/// look meaningful.
export function Sparkline({
    data,
    color = "#3b82f6",
    height = 40,
}: {
    data: SeriesPoint[];
    color?: string;
    height?: number;
}) {
    const id = `sparkline-${color.replace("#", "")}`;
    if (data.length < 2) {
        // Less than 2 samples = no line to draw. Render a flat
        // baseline so the KPI card layout doesn't jump.
        return (
            <div
                className="w-full"
                style={{ height }}
                aria-label="awaiting data"
            />
        );
    }
    return (
        <div className="w-full" style={{ height }}>
            <ResponsiveContainer width="100%" height="100%">
                <AreaChart
                    data={data}
                    margin={{ top: 2, right: 0, bottom: 0, left: 0 }}
                >
                    <defs>
                        <linearGradient id={id} x1="0" y1="0" x2="0" y2="1">
                            <stop offset="0%" stopColor={color} stopOpacity={0.6} />
                            <stop offset="100%" stopColor={color} stopOpacity={0} />
                        </linearGradient>
                    </defs>
                    <YAxis hide domain={["auto", "auto"]} />
                    <Area
                        type="monotone"
                        dataKey="v"
                        stroke={color}
                        strokeWidth={1.5}
                        fill={`url(#${id})`}
                        isAnimationActive={false}
                    />
                </AreaChart>
            </ResponsiveContainer>
        </div>
    );
}
