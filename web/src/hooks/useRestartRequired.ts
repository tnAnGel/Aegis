// Shared hook for surfacing "restart required" state across feature-flag
// toggle controls. Any page that calls envApi.set and gets back
// restart_required:true should call setRestartRequired(true) so the
// persistent restart-required banner appears.
//
// The flag is intentionally in-component state (not global / persisted)
// because a page navigation clears it — if the operator restarts the
// service the browser will eventually reconnect and see fresh state.

import { useState } from "react";

export interface UseRestartRequired {
    restartRequired: boolean;
    setRestartRequired: (v: boolean) => void;
    /** Call this when the restart banner is dismissed or a restart succeeds. */
    clearRestartRequired: () => void;
}

export function useRestartRequired(): UseRestartRequired {
    const [restartRequired, setRestartRequired] = useState(false);
    return {
        restartRequired,
        setRestartRequired,
        clearRestartRequired: () => setRestartRequired(false),
    };
}
