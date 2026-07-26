/// V171 — Top threats heatmap row. Each cell is one attacker IP;
/// color intensity maps to threat score 0..100. Sorted by score
/// descending. Hover shows IP + exact score.
///
/// This isn't a true 2D heatmap (which would need per-IP × per-time
/// data we don't store), but a "density bar" — same visual idiom
/// security ops dashboards use for at-a-glance hot-spot detection.

export interface Threat {
    ip: string;
    score: number;
}

function scoreColor(score: number): string {
    // 0..33 → green, 33..66 → amber, 66..100 → red, smoothly
    // interpolated. HSL hue 130→0 with saturation 70%, lightness
    // 50% gives a clean red→yellow→green gradient that's accessible
    // for the common deuteranopia case.
    const clamped = Math.max(0, Math.min(100, score));
    const hue = 130 - (clamped / 100) * 130;
    return `hsl(${hue.toFixed(0)} 70% 50%)`;
}

export function ThreatHeatmap({
    threats,
    max = 24,
}: {
    threats: Threat[];
    max?: number;
}) {
    if (threats.length === 0) {
        return (
            <div className="text-xs text-muted-foreground italic px-2 py-4">
                No threats above score threshold.
            </div>
        );
    }
    const sorted = [...threats]
        .sort((a, b) => b.score - a.score)
        .slice(0, max);
    return (
        <div className="flex flex-wrap gap-1">
            {sorted.map((t) => (
                <div
                    key={t.ip}
                    role="img"
                    aria-label={`${t.ip} threat score ${t.score}`}
                    className="group relative h-10 rounded-md flex flex-col justify-center items-center transition-transform hover:scale-105 cursor-default"
                    style={{
                        backgroundColor: scoreColor(t.score),
                        width: `calc(${(100 / Math.min(max, 12)).toFixed(2)}% - 4px)`,
                        minWidth: 80,
                    }}
                >
                    <div className="text-[10px] font-mono font-medium text-black/80">
                        {t.ip}
                    </div>
                    <div className="text-[9px] font-mono text-black/60">
                        score {t.score.toFixed(0)}
                    </div>
                </div>
            ))}
        </div>
    );
}
