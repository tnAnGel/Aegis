import { AlertCircle, RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";

interface ErrorStateProps {
    title?: string;
    error: unknown;
    onRetry?: () => void;
}

export function ErrorState({ title = "Something went wrong", error, onRetry }: ErrorStateProps) {
    const message =
        error instanceof Error ? error.message : typeof error === "string" ? error : "Unknown error";
    return (
        <div className="flex flex-col items-center justify-center py-12 px-4 border border-dashed border-destructive/30 rounded-lg bg-destructive/5 text-center">
            <AlertCircle className="h-8 w-8 text-destructive mb-3" />
            <p className="text-sm font-medium text-foreground">{title}</p>
            <p className="mt-1 text-xs text-destructive/80 font-mono max-w-xl break-words">
                {message}
            </p>
            {onRetry && (
                <Button variant="outline" size="sm" className="mt-4" onClick={onRetry}>
                    <RefreshCw className="h-3.5 w-3.5" />
                    Retry
                </Button>
            )}
        </div>
    );
}
