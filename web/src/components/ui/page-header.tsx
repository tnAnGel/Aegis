import * as React from "react";
import { cn } from "@/lib/cn";

// ---------------------------------------------------------------------------
// PageHeader
// ---------------------------------------------------------------------------

interface PageHeaderProps {
    /** Page title — string or any ReactNode (e.g. with a badge inline). */
    title: React.ReactNode;
    /** Short descriptor rendered below the title in muted text. */
    description?: React.ReactNode;
    /** Right-aligned slot for action buttons / controls. */
    actions?: React.ReactNode;
    /**
     * Optional Lucide-style icon component rendered to the left of the title
     * at h-5 w-5. Avoids the workaround of embedding an icon inside the
     * `title` ReactNode.
     */
    icon?: React.ComponentType<{ className?: string }>;
}

/**
 * Consistent page-level header used at the top of every admin page.
 *
 * Spacing contract: the outer wrapper has NO bottom margin — pages control
 * spacing via their root `space-y-6` wrapper. This avoids double-spacing
 * between the header and first section.
 *
 * Usage:
 * ```tsx
 * <PageHeader
 *   title="Sites"
 *   description="Manage reverse-proxy virtual hosts."
 *   actions={<Button>Add site</Button>}
 * />
 * ```
 */
export function PageHeader({ title, description, actions, icon: Icon }: PageHeaderProps) {
    return (
        <div className="flex items-start justify-between gap-3">
            <div className="min-w-0">
                <h1 className="text-xl font-semibold tracking-tight flex items-center gap-2">
                    {Icon && <Icon className="h-5 w-5 shrink-0" />}
                    {title}
                </h1>
                {description && (
                    <p className="mt-0.5 text-sm text-muted-foreground">{description}</p>
                )}
            </div>
            {actions && (
                <div className="flex shrink-0 items-center gap-2">{actions}</div>
            )}
        </div>
    );
}

// ---------------------------------------------------------------------------
// PageSection  (formerly "Section")
// ---------------------------------------------------------------------------

interface PageSectionProps {
    /** Section heading text or ReactNode. */
    title: React.ReactNode;
    /** Optional sub-line below the heading in smaller muted text. */
    description?: React.ReactNode;
    /** Right-aligned slot (e.g. a filter Select). */
    actions?: React.ReactNode;
    children: React.ReactNode;
    className?: string;
    /**
     * "default" — small, muted, uppercase (standard section divider).
     * "sub"     — text-base, bold, no uppercase (nested / card-family grouping).
     */
    size?: "default" | "sub";
}

/**
 * Reusable section wrapper that replaces the hand-rolled
 * `<section><h2 className="text-sm font-semibold …">` pattern used across
 * Telemetry, Arsenal, and Benchmark.
 *
 * Usage:
 * ```tsx
 * <PageSection title="Traffic overview" actions={<MySelect />}>
 *   <div className="grid grid-cols-3 gap-4">…</div>
 * </PageSection>
 * ```
 */
export function PageSection({
    title,
    description,
    actions,
    children,
    className,
    size = "default",
}: PageSectionProps) {
    const headingCls =
        size === "sub"
            ? "text-base font-semibold tracking-tight"
            : "text-sm font-semibold tracking-tight text-muted-foreground uppercase";

    return (
        <section className={cn("space-y-3", className)}>
            <div className="flex items-center justify-between gap-3">
                <div className="min-w-0">
                    <h2 className={headingCls}>{title}</h2>
                    {description && (
                        <p className="mt-0.5 text-xs text-muted-foreground">{description}</p>
                    )}
                </div>
                {actions && (
                    <div className="flex shrink-0 items-center gap-2">{actions}</div>
                )}
            </div>
            {children}
        </section>
    );
}
