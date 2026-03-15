<template>
  <el-container class="layout-container">
    <el-aside :width="isCollapse ? '64px' : '220px'" class="aside-menu">
      <div class="logo-container">
        <el-icon class="logo-icon" color="#3b82f6" :size="28"><Lock /></el-icon>
        <transition name="fade">
          <span v-show="!isCollapse" class="logo-text">安全防御平台</span>
        </transition>
      </div>
      
      <el-menu 
        :default-active="$route.path"
        class="el-menu-vertical"
        :collapse="isCollapse"
        background-color="transparent"
        text-color="#9ca3af"
        active-text-color="#ffffff"
        router
      >
        <el-menu-item 
          v-for="route in menuRoutes" 
          :key="route.path" 
          :index="'/' + route.path"
        >
          <el-icon v-if="route.meta && route.meta.icon && iconMap[route.meta.icon as string]">
            <component :is="iconMap[route.meta.icon as string]" />
          </el-icon>
          <template #title>{{ route.meta?.title }}</template>
        </el-menu-item>
      </el-menu>
    </el-aside>

    <el-container class="main-container">
      <el-header class="app-header">
        <div class="header-left">
          <el-icon class="collapse-btn" @click="toggleCollapse">
            <Fold v-if="!isCollapse" />
            <Expand v-else />
          </el-icon>
          <el-breadcrumb separator="/" style="margin-left: 15px;">
            <el-breadcrumb-item :to="{ path: '/' }">首页</el-breadcrumb-item>
            <el-breadcrumb-item>{{ $route.meta.title }}</el-breadcrumb-item>
          </el-breadcrumb>
        </div>

        <div class="header-right">
          <el-dropdown trigger="click" @command="handleCommand">
            <span class="user-dropdown">
              <el-avatar :size="32" class="user-avatar" style="background-color: #3b82f6;">
                {{ userStore.userInfo.username?.charAt(0).toUpperCase() || 'A' }}
              </el-avatar>
              <span class="username">{{ userStore.userInfo.username || 'Admin' }}</span>
              <el-icon><ArrowDown /></el-icon>
            </span>
            <template #dropdown>
              <el-dropdown-menu>
                <el-dropdown-item command="changePwd">修改密码</el-dropdown-item>
                <el-dropdown-item divided command="logout">安全退出</el-dropdown-item>
              </el-dropdown-menu>
            </template>
          </el-dropdown>
        </div>
      </el-header>

      <el-main class="app-main">
        <router-view v-slot="{ Component }">
          <transition name="fade-transform" mode="out-in">
            <component :is="Component" />
          </transition>
        </router-view>
      </el-main>
    </el-container>
    
    <el-dialog v-model="pwdDialogVisible" title="修改系统密码" width="400px" destroy-on-close>
      <el-form :model="pwdForm" label-width="80px">
        <el-form-item label="原密码">
          <el-input v-model="pwdForm.oldPassword" type="password" show-password placeholder="请输入原密码" />
        </el-form-item>
        <el-form-item label="新密码">
          <el-input v-model="pwdForm.newPassword" type="password" show-password placeholder="请输入新密码" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="pwdDialogVisible = false">取消</el-button>
        <el-button type="primary" @click="submitChangePwd">确定修改</el-button>
      </template>
    </el-dialog>
  </el-container>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue'
import { useUserStore } from '@/store/user'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { changePassword } from '@/api'
// 【修复】：补充所有必要的图标引入
import { 
  Odometer, Lock, Fold, Expand, ArrowDown, 
  DataLine, Bell, Cpu, Setting 
} from '@element-plus/icons-vue'

const userStore = useUserStore()
const router = useRouter()
const isCollapse = ref(false)

// 【修复】：将所有路由中用到的图标注册到 Map 中
const iconMap: Record<string, any> = {
  'Odometer': Odometer,
  'Lock': Lock,
  'DataLine': DataLine,
  'Bell': Bell,
  'Cpu': Cpu,
  'Setting': Setting
}

// 动态获取菜单路由
const menuRoutes = computed(() => {
  const rootRoute = router.options.routes.find(r => r.path === '/')
  return rootRoute?.children?.filter(r => r.meta && r.meta.title) || []
})

const toggleCollapse = () => {
  isCollapse.value = !isCollapse.value
}

// 用户下拉菜单指令处理
const handleCommand = (command: string) => {
  if (command === 'logout') {
    userStore.logout()
    router.push('/login')
    ElMessage.success('已安全退出')
  } else if (command === 'changePwd') {
    pwdForm.value = { oldPassword: '', newPassword: '' } // 每次打开清空表单
    pwdDialogVisible.value = true
  }
}

// 修改密码相关逻辑
const pwdDialogVisible = ref(false)
const pwdForm = ref({ oldPassword: '', newPassword: '' })

const submitChangePwd = async () => {
  if (!pwdForm.value.oldPassword || !pwdForm.value.newPassword) {
    return ElMessage.warning('请填写完整密码信息')
  }
  try {
    await changePassword({ 
      old_password: pwdForm.value.oldPassword, 
      new_password: pwdForm.value.newPassword 
    })
    ElMessage.success('密码修改成功，请重新登录')
    pwdDialogVisible.value = false
    userStore.logout()
    router.push('/login')
  } catch (error: any) {
    ElMessage.error(error.response?.data?.error || '修改失败，请检查原密码是否正确')
  }
}
</script>

<style scoped>
.layout-container { height: 100vh; overflow: hidden; background-color: #f8fafc; }

/* 现代暗黑侧边栏 */
.aside-menu {
  background-color: #0f172a;
  transition: width 0.3s cubic-bezier(0.2, 0, 0, 1);
  box-shadow: 4px 0 24px rgba(0, 0, 0, 0.05);
  display: flex;
  flex-direction: column;
  z-index: 20;
}

.logo-container {
  height: 64px;
  display: flex;
  align-items: center;
  justify-content: center;
  background-color: #0B1120;
  border-bottom: 1px solid rgba(255, 255, 255, 0.05);
  overflow: hidden;
  white-space: nowrap;
}

.logo-icon { margin-right: 10px; }
.logo-text { color: #f8fafc; font-size: 17px; font-weight: 600; letter-spacing: 1px;}

.el-menu-vertical { border-right: none; flex: 1; overflow-y: auto; overflow-x: hidden; }
:deep(.el-menu-item) { border-radius: 8px; margin: 4px 12px; height: 44px; line-height: 44px; }
:deep(.el-menu-item.is-active) {
  background-color: #1e293b !important;
  color: #fff !important;
  box-shadow: inset 3px 0 0 #3b82f6;
}

.app-header {
  height: 64px;
  background-color: rgba(255, 255, 255, 0.9);
  backdrop-filter: blur(8px);
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 0 24px;
  border-bottom: 1px solid #e2e8f0;
  z-index: 10;
}

.header-left { display: flex; align-items: center; }
.collapse-btn { font-size: 20px; color: #64748b; cursor: pointer; transition: color 0.2s; }
.collapse-btn:hover { color: #3b82f6; }

.user-dropdown { display: flex; align-items: center; cursor: pointer; padding: 0 8px; }
.username { font-size: 14px; color: #303133; margin-right: 4px; margin-left: 8px; }

.app-main { padding: 0; height: calc(100vh - 64px); overflow-y: auto; box-sizing: border-box; }

/* 转场动画 */
.fade-transform-enter-active, .fade-transform-leave-active { transition: all 0.3s ease; }
.fade-transform-enter-from { opacity: 0; transform: translateX(10px); }
.fade-transform-leave-to { opacity: 0; transform: translateX(-10px); }
</style>