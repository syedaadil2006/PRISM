/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** Override the API base, e.g. when the UI is hosted separately. */
  readonly VITE_API_BASE?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
