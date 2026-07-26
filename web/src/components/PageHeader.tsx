import * as React from "react";

interface Props {
    title: React.ReactNode;
    description?: React.ReactNode;
    actions?: React.ReactNode;
}

export function PageHeader({ title, description, actions }: Props) {
    return (
        <div className="flex items-center justify-between gap-3 mb-5">
            <div className="min-w-0">
                <h1 className="text-xl font-semibold tracking-tight">{title}</h1>
                {description && (
                    <p className="mt-0.5 text-sm text-muted-foreground">{description}</p>
                )}
            </div>
            {actions && <div className="flex items-center gap-2">{actions}</div>}
        </div>
    );
}
