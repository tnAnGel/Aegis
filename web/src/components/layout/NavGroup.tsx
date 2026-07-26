/**
 * NavGroup — collapsible sidebar navigation group.
 *
 * Renders a group header (icon + label + chevron) and an animated list of
 * NavItem links beneath it.  Open/closed state is driven by the parent
 * (Sidebar.tsx) which owns the shared `openGroups` Set and the
 * `onToggle` callback so that localStorage persistence lives in one place.
 *
 * Usage:
 * ```tsx
 * <NavGroup
 *   group={group}
 *   isOpen={openGroups.has(group.id)}
 *   onToggle={() => handleToggle(group.id)}
 *   pathname={location.pathname}
 * />
 * ```
 */

import { Link } from "@tanstack/react-router";
import { ChevronDown } from "lucide-react";
import { cn } from "@/lib/cn";
import type { NavGroup as NavGroupType } from "./nav-config";

interface NavGroupProps {
    group: NavGroupType;
    /** Whether this group is currently expanded. */
    isOpen: boolean;
    /** Called when the user clicks the group header to toggle expand/collapse. */
    onToggle: () => void;
    /** Current router pathname — used to determine the active item. */
    pathname: string;
}

/**
 * Returns true when `pathname` matches the given nav item's `to` path.
 * The root route ("/") only matches exactly; all others also match child paths.
 */
function isActive(to: string, pathname: string): boolean {
    if (to === "/") return pathname === "/";
    return pathname === to || pathname.startsWith(to + "/");
}

export function NavGroup({ group, isOpen, onToggle, pathname }: NavGroupProps) {
    const GroupIcon = group.icon;

    return (
        <div>
            {/* ── Group header (collapse toggle) ─────────────────────────── */}
            <button
                onClick={onToggle}
                className={cn(
                    "flex w-full items-center gap-2 px-3 py-1.5",
                    "text-xs font-semibold uppercase tracking-wider",
                    "text-muted-foreground hover:text-foreground",
                    "transition-colors duration-150",
                )}
                aria-expanded={isOpen}
            >
                <GroupIcon className="h-3.5 w-3.5 shrink-0" />
                <span className="flex-1 text-left">{group.label}</span>
                <ChevronDown
                    className={cn(
                        "h-3.5 w-3.5 transition-transform duration-200",
                        isOpen ? "rotate-180" : "",
                    )}
                />
            </button>

            {/* ── Animated item list ──────────────────────────────────────── */}
            <div
                className={cn(
                    "overflow-hidden transition-all duration-200",
                    isOpen ? "max-h-[1000px]" : "max-h-0",
                )}
            >
                <div className="mt-0.5 space-y-0.5 pb-1">
                    {group.items.map((item) => {
                        const Icon = item.icon;
                        const active = isActive(item.to, pathname);
                        return (
                            <Link
                                key={item.to}
                                to={item.to}
                                aria-current={active ? "page" : undefined}
                                className={cn(
                                    "flex items-center gap-2.5 rounded-md px-3 py-1.5 text-sm transition-colors",
                                    active
                                        ? "bg-secondary text-secondary-foreground font-medium"
                                        : "text-muted-foreground hover:bg-accent hover:text-accent-foreground",
                                )}
                            >
                                <Icon className="h-4 w-4 shrink-0" />
                                {item.label}
                            </Link>
                        );
                    })}
                </div>
            </div>
        </div>
    );
}
