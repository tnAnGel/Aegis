import * as React from "react";
import { cn } from "@/lib/cn";

interface EmptyStateProps {
    icon?: React.ReactNode;
    title: string;
    description?: string;
    action?: React.ReactNode;
    className?: string;
}

export function EmptyState({ icon, title, description, action, className }: EmptyStateProps) {
    return (
        <div
            className={cn(
                "flex flex-col items-center justify-center text-center py-12 px-4 border border-dashed rounded-lg bg-card/50",
                className,
            )}
        >
            {icon && (
                <div className="mb-3 text-muted-foreground/60 [&>svg]:h-10 [&>svg]:w-10">
                    {icon}
                </div>
            )}
            <p className="text-sm font-medium text-foreground">{title}</p>
            {description && (
                <p className="mt-1 text-xs text-muted-foreground max-w-md">{description}</p>
            )}
            {action && <div className="mt-4">{action}</div>}
        </div>
    );
}
