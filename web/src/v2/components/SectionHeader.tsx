import * as React from "react";
import { cn } from "@/lib/cn";

/**
 * V2 SectionHeader
 *
 * Small-caps, uppercase, wide-tracked muted label used as a section
 * divider inside cards or between dashboard rows. Matches the
 * "OVERVIEW", "TRAFFIC & ROUTING", "SECURITY EVENTS" style headings
 * from the mockup.
 *
 * Rendered as a <p> (not a heading) because it's purely decorative
 * hierarchy — screen readers should not mistake it for page structure.
 */
export interface SectionHeaderProps extends React.HTMLAttributes<HTMLParagraphElement> {
    /** The label text — rendered uppercase automatically. */
    label: string;
}

export function SectionHeader({ label, className, ...props }: SectionHeaderProps) {
    return (
        <p
            className={cn("v2-section-label", className)}
            aria-label={label}
            {...props}
        >
            {label}
        </p>
    );
}
