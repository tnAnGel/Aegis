import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

/** Classic shadcn helper — merge tailwind classes while resolving
 * conflicts via tailwind-merge so `cn("p-2", isActive && "p-4")`
 * doesn't ship both. */
export function cn(...inputs: ClassValue[]) {
    return twMerge(clsx(inputs));
}
