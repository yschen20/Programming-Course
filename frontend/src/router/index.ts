// src/router/index.ts
import { createRouter, createWebHistory, RouteRecordRaw } from 'vue-router'
import { useUserStore } from '@/store/user'

const routes: Array<RouteRecordRaw> = [
  {
    path: '/login',
    name: 'Login',
    component: () => import('@/views/Login.vue'),
    meta: { title: '登录' }
  },
  {
    path: '/',
    component: () => import('@/layout/index.vue'),
    redirect: '/dashboard',
    children: [
      {
        path: 'dashboard',
        name: 'Dashboard',
        component: () => import('@/views/Dashboard.vue'),
        meta: { title: '监控大盘', icon: 'Odometer' }
      },
      {
        path: 'defense',
        name: 'Defense',
        component: () => import('@/views/Defense.vue'),
        meta: { title: '安全防御', icon: 'Lock' }
      },
      {
        path: 'traffic',
        name: 'Traffic',
        component: () => import('@/views/Traffic.vue'),
        meta: { title: '流量审计', icon: 'DataLine' }
      },
      {
        path: 'alerts',
        name: 'Alerts',
        component: () => import('@/views/Alerts.vue'),
        meta: { title: '告警中心', icon: 'Bell' }
      },
      {
        path: 'aimodel',
        name: 'AiModel',
        component: () => import('@/views/AiModel.vue'),
        meta: { title: 'AI 引擎', icon: 'Cpu' }
      },
      {
        path: 'settings',
        name: 'Settings',
        component: () => import('@/views/Settings.vue'),
        meta: { title: '系统设置', icon: 'Setting' }
      }
    ]
  },
  // 兜底路由：捕获所有未匹配到的路径，重定向回监控大盘
  {
    path: '/:pathMatch(.*)*',
    name: 'NotFound',
    redirect: '/dashboard'
  }
]

const router = createRouter({
  history: createWebHistory(),
  routes
})

// 路由守卫：验证登录状态及动态标题
router.beforeEach((to, _from, next) => {
  const userStore = useUserStore()
  
  // 动态修改页面标题
  if (to.meta.title) {
    document.title = `${to.meta.title} - 校园网异常检测平台`
  }

  // 需要登录拦截的情况
  if (to.name !== 'Login' && !userStore.token) {
    next({ name: 'Login' })
  } else {
    next()
  }
})

export default router