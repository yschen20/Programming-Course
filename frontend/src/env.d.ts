/// <reference types="vite/client" />

declare module '*.vue' {
  import type { DefineComponent } from 'vue'
  const component: DefineComponent<{}, {}, any>
  export default component
}

interface ImportMetaEnv {
  readonly VITE_API_BASE_URL: string
  // 其他环境变量...
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}

// 扩展Vue Router的RouteMeta接口
import 'vue-router'

declare module 'vue-router' {
  interface RouteMeta {
    title?: string
    icon?: string
  }
}
