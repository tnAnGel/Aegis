/**
 * V2 ConfigEditor page — /v2/config
 *
 * Mirrors the raw DSL config editor from V1 ConfigEditor.tsx, restyled with
 * V2 MetricCard chrome. Monaco editor is reused unchanged. All react-query
 * hooks and mutations are identical to V1 — only presentation changes.
 */

import * as React from "react";
import { useTranslation } from "react-i18next";
import Editor, { type Monaco } from "@monaco-editor/react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTheme } from "@/hooks/useTheme";
import { configApi } from "@/api/client";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState } from "@/components/ErrorState";
import { useToast } from "@/hooks/useToast";
import {
    CheckCircle2,
    RotateCcw,
    Save,
    Sparkles,
    TestTube2,
} from "lucide-react";
import { MetricCard } from "@/v2/components/MetricCard";
import { SectionHeader } from "@/v2/components/SectionHeader";
import { StatusBadge } from "@/v2/components/StatusBadge";

// ─── Language definition (identical to V1) ───────────────────────────────────

const KEYWORDS = [
    "admin", "defaults", "server", "include", "location",
    "listen", "server_name", "ssl_certificate", "ssl_certificate_key",
    "proxy_pass", "filters", "rate_limit",
    "waf", "bot_fingerprint", "adaptive_spike_detection", "challenge_ladder",
    "geoip", "xdp", "requests_per_second", "burst",
    "request_timeout", "graceful_shutdown", "header_read_timeout",
    "token", "audit_log_path", "managed_sites_dir", "ops_sites_dir",
    "ssl", "http2", "http3", "default_server", "on", "off",
];

function registerLanguage(monaco: Monaco) {
    if (monaco.languages.getLanguages().some((l) => l.id === "aegis")) return;
    monaco.languages.register({ id: "aegis" });
    monaco.languages.setMonarchTokensProvider("aegis", {
        tokenizer: {
            root: [
                [/#.*$/, "comment"],
                [/"([^"\\]|\\.)*"/, "string"],
                [/'([^'\\]|\\.)*'/, "string"],
                [/\b\d+(ms|s|m)?\b/, "number"],
                [new RegExp(`\\b(${KEYWORDS.join("|")})\\b`), "keyword"],
                [/[{};]/, "delimiter"],
                [/[A-Za-z0-9_./:\-]+/, "identifier"],
            ],
        },
    });
    monaco.languages.registerCompletionItemProvider("aegis", {
        provideCompletionItems(model, position) {
            const word = model.getWordUntilPosition(position);
            return {
                suggestions: KEYWORDS.map((k) => ({
                    label: k,
                    kind: monaco.languages.CompletionItemKind.Keyword,
                    insertText: k,
                    range: {
                        startLineNumber: position.lineNumber,
                        endLineNumber: position.lineNumber,
                        startColumn: word.startColumn,
                        endColumn: word.endColumn,
                    },
                })),
            };
        },
    });
}

// ─── Main page ────────────────────────────────────────────────────────────────

export function ConfigEditorV2Page() {
    const { t } = useTranslation(["configeditor", "common"]);
    const { theme } = useTheme();
    const { toast } = useToast();
    const qc = useQueryClient();
    const editorRef = React.useRef<{
        getValue: () => string;
        setValue: (v: string) => void;
    } | null>(null);

    const config = useQuery({
        queryKey: ["config", "raw"],
        queryFn: configApi.raw,
    });

    const [draft, setDraft] = React.useState<string | null>(null);
    React.useEffect(() => {
        if (config.data && draft === null) {
            setDraft(config.data);
        }
    }, [config.data, draft]);

    const dirty = draft !== null && draft !== config.data;

    const testMut = useMutation({
        mutationFn: configApi.test,
        onSuccess: (r) => {
            if (r.ok) {
                toast({
                    title: t("toast.configOk.title"),
                    description: r.summary?.split("\n")[0],
                    variant: "success",
                });
            } else {
                toast({
                    title: t("toast.configInvalid.title"),
                    description: r.error,
                    variant: "destructive",
                });
            }
        },
        onError: (e) =>
            toast({
                title: t("toast.testFailed.title"),
                description: e instanceof Error ? e.message : String(e),
                variant: "destructive",
            }),
    });

    const applyMut = useMutation({
        mutationFn: async () => {
            const text = editorRef.current?.getValue() ?? draft ?? "";
            const saved = await configApi.save(text);
            if (!saved.ok) throw new Error(saved.error ?? "save failed");
            return configApi.apply();
        },
        onSuccess: (r) => {
            if (r.ok) {
                toast({ title: t("toast.applied.title"), description: r.message, variant: "success" });
                qc.invalidateQueries();
                config.refetch().then(() => setDraft(null));
            } else {
                toast({ title: t("toast.reloadFailed.title"), description: r.message, variant: "destructive" });
            }
        },
        onError: (e) =>
            toast({
                title: t("toast.applyFailed.title"),
                description: e instanceof Error ? e.message : String(e),
                variant: "destructive",
            }),
    });

    return (
        <div className="space-y-5">
            {/* Page header + toolbar */}
            <div className="flex items-start justify-between gap-4 flex-wrap">
                <div>
                    <SectionHeader label={t("title")} />
                    <p className="text-xs text-muted-foreground mt-1.5 leading-snug">
                        {t("subtitle")}
                    </p>
                </div>

                {/* Toolbar actions */}
                <div className="flex items-center gap-2 flex-wrap shrink-0">
                    {dirty ? (
                        <StatusBadge state="degraded" label={t("unsavedChanges")} />
                    ) : (
                        <StatusBadge state="healthy" label={t("inSync")} />
                    )}
                    <Button
                        variant="outline"
                        size="sm"
                        className="h-8 text-xs"
                        onClick={() => setDraft(config.data ?? null)}
                        disabled={!dirty}
                    >
                        <RotateCcw className="h-3.5 w-3.5 mr-1" />
                        {t("revert")}
                    </Button>
                    <Button
                        variant="secondary"
                        size="sm"
                        className="h-8 text-xs"
                        onClick={() => {
                            const text = editorRef.current?.getValue() ?? draft ?? "";
                            testMut.mutate(text);
                        }}
                        disabled={testMut.isPending}
                    >
                        <TestTube2 className="h-3.5 w-3.5 mr-1" />
                        {t("test")}
                    </Button>
                    <Button
                        size="sm"
                        className="h-8 text-xs"
                        onClick={() => applyMut.mutate()}
                        disabled={applyMut.isPending}
                    >
                        <Save className="h-3.5 w-3.5 mr-1" />
                        {t("applyReload")}
                    </Button>
                </div>
            </div>

            {/* Last test result */}
            {testMut.data && (
                <MetricCard
                    title={testMut.data.ok ? t("lastTestPassed") : t("lastTestFailed")}
                    description={testMut.data.ok ? t("configOk") : t("seeErrorBelow")}
                >
                    <div className="flex items-center gap-2 mb-3">
                        {testMut.data.ok ? (
                            <CheckCircle2 className="h-4 w-4 text-[var(--v2-chart-allow)]" />
                        ) : (
                            <Sparkles className="h-4 w-4 text-destructive" />
                        )}
                        <span
                            className={`text-xs font-semibold ${
                                testMut.data.ok
                                    ? "text-[var(--v2-chart-allow)]"
                                    : "text-destructive"
                            }`}
                        >
                            {testMut.data.ok ? t("allChecksPassed") : t("validationError")}
                        </span>
                    </div>
                    <pre className="bg-background/40 border border-border/50 rounded-lg px-4 py-3 text-xs font-mono whitespace-pre-wrap text-foreground/80 leading-relaxed">
                        {testMut.data.summary ?? testMut.data.error ?? ""}
                    </pre>
                </MetricCard>
            )}

            {/* Monaco editor */}
            <MetricCard
                title={t("editorTitle")}
                description={t("editorDescription")}
                noPadding
                contentClassName="min-h-0"
            >
                <div className="h-[65vh] overflow-hidden rounded-b-xl">
                    {config.isLoading ? (
                        <Skeleton className="h-full w-full rounded-none" />
                    ) : config.isError ? (
                        <div className="p-6">
                            <ErrorState error={config.error} onRetry={() => config.refetch()} />
                        </div>
                    ) : (
                        <Editor
                            height="100%"
                            theme={theme === "dark" ? "vs-dark" : "vs"}
                            language="aegis"
                            value={draft ?? config.data ?? ""}
                            beforeMount={registerLanguage}
                            onMount={(editor) => {
                                editorRef.current = editor;
                            }}
                            onChange={(v) => setDraft(v ?? "")}
                            options={{
                                fontSize: 13,
                                minimap: { enabled: false },
                                fontFamily:
                                    'ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace',
                                scrollBeyondLastLine: false,
                                tabSize: 4,
                                renderWhitespace: "selection",
                                automaticLayout: true,
                            }}
                        />
                    )}
                </div>
            </MetricCard>
        </div>
    );
}
