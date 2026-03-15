<template>
  <div class="login-container">
    <div class="login-background"></div>
    <div class="login-wrapper">
      <el-card class="login-card" shadow="never">
        <div class="login-header">
          <div class="logo-circle">
            <el-icon class="logo-icon"><Lock /></el-icon>
          </div>
          <h2>校园网异常检测平台</h2>
          <p class="login-subtitle">Securing Your Campus Network</p>
        </div>
        <el-form 
          :model="form" 
          @submit.prevent="handleLogin"
          :rules="rules"
          ref="loginForm"
          class="login-form"
        >
          <el-form-item prop="username">
            <el-input 
              v-model="form.username" 
              placeholder="请输入管理员账号"
              prefix-icon="User"
              size="large"
              clearable
            />
          </el-form-item>
          <el-form-item prop="password">
            <el-input 
              v-model="form.password" 
              type="password" 
              placeholder="请输入管理员密码"
              show-password
              prefix-icon="Key"
              size="large"
              @keyup.enter="handleLogin"
            />
          </el-form-item>
          <el-button 
            type="primary" 
            native-type="submit" 
            class="submit-btn"
            size="large"
            :loading="loading"
          >
            {{ loading ? '安全登录中...' : '登 录' }}
          </el-button>
        </el-form>
      </el-card>
      <div class="login-footer">
        <p>© 2026 校园网异常检测防御系统 V1.0</p>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { login } from '@/api'
import { useUserStore } from '@/store/user'
import { ElMessage } from 'element-plus'
import { Lock } from '@element-plus/icons-vue'

const router = useRouter()
const userStore = useUserStore()
const loginForm = ref()
const loading = ref(false)

const form = reactive({ username: '', password: '' })

const rules = {
  username: [{ required: true, message: '请输入用户名', trigger: 'blur' }],
  password: [{ required: true, message: '请输入密码', trigger: 'blur' }]
}

const handleLogin = async () => {
  if (!loginForm.value) return
  try {
    await loginForm.value.validate()
    loading.value = true
    const res: any = await login(form)
    userStore.setToken(res.token)
    userStore.setUserInfo(res.user)
    ElMessage.success('身份验证成功，欢迎回来')
    router.push('/dashboard')
  } catch (error: any) {
    if (error !== 'cancel') {
      ElMessage.error(error.response?.data?.error || '登录失败，请检查账号密码')
    }
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.login-container {
  position: relative;
  display: flex;
  justify-content: center;
  align-items: center;
  height: 100vh;
  overflow: hidden;
  background-color: #0f172a;
}

.login-background {
  position: absolute;
  top: -50%;
  left: -50%;
  width: 200%;
  height: 200%;
  background: radial-gradient(circle at center, #1e293b 0%, #0f172a 100%);
  z-index: 0;
}

.login-wrapper {
  position: relative;
  z-index: 1;
  width: 100%;
  max-width: 400px;
  padding: 20px;
  animation: slide-up 0.6s cubic-bezier(0.16, 1, 0.3, 1);
}

.login-card {
  border-radius: 16px;
  background: rgba(255, 255, 255, 0.05);
  backdrop-filter: blur(20px);
  -webkit-backdrop-filter: blur(20px);
  border: 1px solid rgba(255, 255, 255, 0.1);
  padding: 20px;
}

.login-header {
  text-align: center;
  margin-bottom: 30px;
}

.logo-circle {
  width: 72px;
  height: 72px;
  background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%);
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  margin: 0 auto 16px;
  box-shadow: 0 8px 16px rgba(59, 130, 246, 0.3);
}

.logo-icon {
  font-size: 36px;
  color: #ffffff;
}

.login-header h2 {
  margin: 0 0 8px 0;
  font-size: 22px;
  font-weight: 600;
  color: #f8fafc;
  letter-spacing: 1px;
}

.login-subtitle {
  margin: 0;
  font-size: 13px;
  color: #94a3b8;
}

.login-form :deep(.el-input__wrapper) {
  background-color: rgba(255, 255, 255, 0.05);
  border-radius: 8px;
  box-shadow: 0 0 0 1px rgba(255, 255, 255, 0.1) inset;
}

.login-form :deep(.el-input__inner) {
  color: #f8fafc;
}

.submit-btn {
  width: 100%;
  border-radius: 8px;
  margin-top: 10px;
  background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%);
  border: none;
  font-weight: 600;
  letter-spacing: 2px;
  transition: all 0.3s ease;
}

.submit-btn:hover {
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(59, 130, 246, 0.4);
}

.login-footer {
  margin-top: 20px;
  text-align: center;
}

.login-footer p {
  font-size: 12px;
  color: #64748b;
}

@keyframes slide-up {
  from { opacity: 0; transform: translateY(30px); }
  to { opacity: 1; transform: translateY(0); }
}
</style>