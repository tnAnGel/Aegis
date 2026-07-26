// ArcGauge — pure-SVG 270-degree arc gauge.
//
// Renders a filled background arc and an animated foreground arc whose
// stroke-dashoffset transitions from 377 (empty) to 377 - (value/max)*377
// (full) over 0.6 s.  The total circumference of r=80 at 270° is 80*2π*(270/360)
// ≈ 377 px; the remaining 90° gap (≈ 126 px) is handled by dasharray "377 503"
// which makes the gap invisible in the bottom-centre of the circle.

interface ArcGaugeProps {
    value: number;
    max: number;
    label: string;
    unit: string;
    color: "cyan" | "violet" | "amber";
}

const COLOR_MAP: Record<ArcGaugeProps["color"], string> = {
    cyan: "#06b6d4",
    violet: "#8b5cf6",
    amber: "#f59e0b",
};

// The SVG arc path for a 270° sweep starting at 135° (bottom-left),
// going clockwise to 45° (bottom-right).  We use stroke-dasharray /
// stroke-dashoffset on a full circle, which is simpler than an arc path.
// r = 80, cx = cy = 100, circumference = 2*π*80 ≈ 502.65; 270/360 of that ≈ 377.

const CIRCUMFERENCE = 502.65;      // 2 * π * 80
const ARC_LENGTH    = 377;         // 270 / 360 * 502.65
const GAP_LENGTH    = CIRCUMFERENCE - ARC_LENGTH; // ~125.65 — hidden at bottom

export function ArcGauge({ value, max, label, unit, color }: ArcGaugeProps) {
    const clampedValue = Math.max(0, Math.min(value, max));
    const fillRatio    = max > 0 ? clampedValue / max : 0;
    // dashoffset: 377 = empty arc, 0 = fully filled; we fill left-to-right.
    const offset       = ARC_LENGTH - fillRatio * ARC_LENGTH;

    const stroke = COLOR_MAP[color];
    // Rotation: align the arc gap to the bottom centre.  A standard
    // stroke-dasharray trick starts at the 3 o'clock position (rightmost
    // point); we rotate so the gap is at the bottom (135° start).
    const rotate = "rotate(135, 100, 100)";

    const displayValue = Number.isFinite(value) ? value.toFixed(value >= 10 ? 1 : 2) : "—";

    return (
        <div className="flex flex-col items-center gap-1 select-none">
            <div className="relative" style={{ width: 160, height: 160 }}>
                <svg
                    viewBox="0 0 200 200"
                    width={160}
                    height={160}
                    aria-label={`${label}: ${displayValue} ${unit}`}
                    role="img"
                >
                    {/* Soft drop-shadow / glow filter */}
                    <defs>
                        <filter id={`glow-${color}`} x="-30%" y="-30%" width="160%" height="160%">
                            <feGaussianBlur stdDeviation="4" result="blur" />
                            <feComposite in="SourceGraphic" in2="blur" operator="over" />
                        </filter>
                    </defs>

                    {/* Background track */}
                    <circle
                        cx={100}
                        cy={100}
                        r={80}
                        fill="none"
                        stroke="rgba(255,255,255,0.08)"
                        strokeWidth={14}
                        strokeDasharray={`${ARC_LENGTH} ${GAP_LENGTH}`}
                        strokeLinecap="round"
                        transform={rotate}
                    />

                    {/* Foreground arc with CSS transition for animation */}
                    <circle
                        cx={100}
                        cy={100}
                        r={80}
                        fill="none"
                        stroke={stroke}
                        strokeWidth={14}
                        strokeDasharray={`${ARC_LENGTH} ${GAP_LENGTH}`}
                        strokeDashoffset={offset}
                        strokeLinecap="round"
                        transform={rotate}
                        filter={`url(#glow-${color})`}
                        style={{
                            transition: "stroke-dashoffset 0.6s ease",
                            opacity: 0.92,
                        }}
                    />

                    {/* Centered numeric readout — drawn IN the SVG at the
                        circle centre (100,100) so it's geometrically dead-centre
                        of the ring regardless of container sizing. */}
                    <text
                        x={100}
                        y={94}
                        textAnchor="middle"
                        dominantBaseline="central"
                        fontSize={32}
                        fontWeight={700}
                        fill={stroke}
                        style={{ fontVariantNumeric: "tabular-nums" }}
                    >
                        {displayValue}
                    </text>
                    <text
                        x={100}
                        y={120}
                        textAnchor="middle"
                        dominantBaseline="central"
                        fontSize={13}
                        fill="rgba(148,163,184,0.85)"
                    >
                        {unit}
                    </text>
                </svg>
            </div>

            {/* Label below the gauge */}
            <span className="text-xs font-medium text-muted-foreground tracking-wide uppercase">
                {label}
            </span>
        </div>
    );
}
