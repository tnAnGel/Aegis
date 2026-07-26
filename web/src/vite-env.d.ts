/// <reference types="vite/client" />

interface ImportMetaEnv {
    readonly VITE_AEGIS_API_BASE?: string;
    readonly VITE_USE_MOCKS?: string;
}

interface ImportMeta {
    readonly env: ImportMetaEnv;
}
