import * as React from "react";
import { KeyRound } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { getToken, setToken } from "@/api/client";
import { useToast } from "@/hooks/useToast";
import { useQueryClient } from "@tanstack/react-query";

export function TokenInput() {
    const [value, setValue] = React.useState(getToken());
    const { toast } = useToast();
    const qc = useQueryClient();

    React.useEffect(() => {
        // Pick up tokens from a one-shot URL hash like #token=XXX.
        if (location.hash && location.hash.includes("token=")) {
            const params = new URLSearchParams(location.hash.replace(/^#/, ""));
            const t = params.get("token");
            if (t) {
                setToken(t);
                setValue(getToken());
                history.replaceState(null, "", location.pathname);
                qc.invalidateQueries();
            }
        }
    }, [qc]);

    const save = () => {
        setToken(value);
        setValue(getToken());
        toast({ title: "Token saved", variant: "success" });
        qc.invalidateQueries();
    };

    return (
        <div className="flex items-center gap-1">
            <div className="relative">
                <KeyRound className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
                <Input
                    type="password"
                    placeholder="x-admin-token"
                    aria-label="Admin API token"
                    autoComplete="off"
                    value={value}
                    onChange={(e) => setValue(e.target.value)}
                    onKeyDown={(e) => {
                        if (e.key === "Enter") {
                            e.preventDefault();
                            save();
                        }
                    }}
                    className="w-56 pl-7 font-mono text-xs"
                />
            </div>
            <Button size="sm" variant="secondary" onClick={save}>
                Save
            </Button>
        </div>
    );
}
