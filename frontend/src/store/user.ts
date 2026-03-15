// src/store/user.ts
import { defineStore } from 'pinia'

export const useUserStore = defineStore('user', {
  state: () => ({
    // 初始化时从本地缓存读取
    token: localStorage.getItem('defense_token') || '',
    userInfo: JSON.parse(localStorage.getItem('defense_user') || '{}')
  }),
  actions: {
    setToken(token: string) {
      this.token = token
      localStorage.setItem('defense_token', token)
    },
    setUserInfo(info: any) {
      this.userInfo = info
      localStorage.setItem('defense_user', JSON.stringify(info))
    },
    logout() {
      this.token = ''
      this.userInfo = {}
      // 清除本地缓存
      localStorage.removeItem('defense_token')
      localStorage.removeItem('defense_user')
    }
  }
})