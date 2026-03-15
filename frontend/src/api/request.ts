// src/api/request.ts
import axios from 'axios'
import { ElMessage } from 'element-plus'
import { useUserStore } from '@/store/user'

// 创建axios实例
const request = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || '/api',
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json'
  }
})

// 并发 401 弹窗锁
let isReloginShow = false

// 请求拦截器
request.interceptors.request.use(
  config => {
    const userStore = useUserStore()
    if (userStore.token) {
      config.headers.Authorization = `Bearer ${userStore.token}`
    }
    return config
  },
  error => {
    return Promise.reject(error)
  }
)

// 响应拦截器
request.interceptors.response.use(
  response => {
    return response.data
  },
  error => {
    const { response } = error
    if (response) {
      // 获取后端的实际错误信息（后端使用 'error' 字段代替传统的 'message'）
      const errorMsg = response.data?.error || response.data?.message || '未知错误'
      
      switch (response.status) {
        case 401:
          // 未授权，清除状态并跳转到登录页（加入防抖锁，避免多个并发请求同时触发弹窗）
          if (!isReloginShow) {
            isReloginShow = true
            const userStore = useUserStore()
            userStore.logout()
            ElMessage.error(`登录已失效: ${errorMsg}，请重新登录`)
            
            setTimeout(() => {
              isReloginShow = false
              window.location.href = '/login'
            }, 1500)
          }
          break
        case 403:
          ElMessage.error('没有权限执行此操作')
          break
        case 404:
          ElMessage.error('请求的资源或接口不存在')
          break
        case 429:
          ElMessage.warning(`操作过于频繁: ${errorMsg}`)
          break
        case 500:
          ElMessage.error(`服务器内部错误: ${errorMsg}`)
          break
        default:
          ElMessage.error(`请求失败: ${errorMsg}`)
      }
    } else {
      ElMessage.error('网络错误，请检查网络连接或服务是否启动')
    }
    return Promise.reject(error)
  }
)

export default request