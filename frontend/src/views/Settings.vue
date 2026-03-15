<template>
  <div class="settings-wrapper">
    <div class="settings-header">
      <div class="header-left">
        <div class="header-icon-bg">
          <el-icon><Setting /></el-icon>
        </div>
        <div class="header-content">
          <h1 class="main-title">系统全局设置</h1>
          <div class="status-indicator">
            <span class="pulse-dot active"></span>
            <span class="status-text">配置热重载引擎已就绪</span>
          </div>
        </div>
      </div>
    </div>

    <div class="glass-card main-settings">
      <el-tabs v-model="activeTab" class="modern-tabs">
        
        <el-tab-pane name="defense">
          <template #label>
            <span class="tab-label"><el-icon><Lock /></el-icon> 安全防御策略</span>
          </template>

          <div class="tab-content-wrapper">
            <el-alert 
              title="智能重载：参数修改后，后端守护进程将通过指令队列自动执行配置热更新，无需重启服务。" 
              type="success" 
              :closable="false" 
              show-icon 
              class="config-alert"
            />

            <el-form :model="defenseConfig" label-position="top" class="custom-form">
              <el-row :gutter="40">
                <el-col :span="12">
                  <div class="setting-item-box">
                    <div class="setting-info">
                      <h4 class="item-title">启用自动防御拦截</h4>
                      <p class="item-desc">开启后，系统将根据AI检测结果自动下发防火墙策略进行IP封禁。</p>
                    </div>
                    <el-switch 
                      v-model="defenseConfig.auto_block" 
                      active-text="全自动拦截" 
                      inactive-text="仅记录日志"
                      class="custom-switch"
                      inline-prompt
                    />
                  </div>
                </el-col>
              </el-row>

              <el-row :gutter="40" class="mt-30">
                <el-col :span="12">
                  <div class="setting-item-box vertical">
                    <div class="setting-info">
                      <h4 class="item-title">默认封禁时长 (Seconds)</h4>
                      <p class="item-desc">当源IP触发安全阈值时，默认在系统中封禁的秒数。</p>
                    </div>
                    <div class="input-with-unit">
                      <el-input-number 
                        v-model="defenseConfig.block_duration" 
                        :min="60" 
                        controls-position="right"
                        class="modern-number-input"
                      />
                      <span class="unit-tag">秒 (s)</span>
                    </div>
                  </div>
                </el-col>
                <el-col :span="12">
                  <div class="setting-item-box vertical">
                    <div class="setting-info">
                      <h4 class="item-title">全局流量触发阈值</h4>
                      <p class="item-desc">单IP每秒数据包(PPS)超过此值将直接被判定为流量洪水。</p>
                    </div>
                    <div class="input-with-unit">
                      <el-input-number 
                        v-model="defenseConfig.threshold_pps" 
                        :min="10" 
                        controls-position="right"
                        class="modern-number-input"
                      />
                      <span class="unit-tag">PPS</span>
                    </div>
                  </div>
                </el-col>
              </el-row>

              <div class="form-actions mt-40">
                <el-button 
                  type="primary" 
                  size="large" 
                  class="save-btn shadow-primary" 
                  @click="saveDefenseConfig"
                  :icon="Check"
                >
                  保存并应用全局策略
                </el-button>
              </div>
            </el-form>
          </div>
        </el-tab-pane>

        <el-tab-pane name="cleanup">
          <template #label>
            <span class="tab-label"><el-icon><Box /></el-icon> 数据存储与清理</span>
          </template>

          <div class="tab-content-wrapper">
            <div class="storage-dashboard">
              <div class="storage-item">
                <span class="s-label">审计日志保留周期</span>
                <div class="s-control">
                  <el-input-number v-model="cleanupConfig.retention_days" :min="1" :max="365" class="modern-number-input" />
                  <span class="s-unit">天</span>
                </div>
                <p class="s-hint">系统将自动定期清理超过此期限的历史流量记录与告警日志。</p>
              </div>
            </div>

            <div class="cleanup-console mt-40">
              <div class="console-header">
                <el-icon><WarningFilled /></el-icon>
                <span>危险操作区 (Dangerous Area)</span>
              </div>
              <div class="console-body">
                <div class="body-text">
                  <h5>立即执行磁盘空间清理</h5>
                  <p>该操作将立即扫描数据库并强制删除过期记录，此过程不可逆。</p>
                </div>
                <el-button 
                  type="danger" 
                  size="large" 
                  @click="runManualCleanup" 
                  :icon="Delete"
                  plain
                  class="cleanup-btn save-btn"
                >
                  强制释放磁盘空间
                </el-button>
              </div>
            </div>

            <div class="form-actions mt-40">
              <el-button 
                type="primary" 
                size="large" 
                class="save-btn shadow-primary" 
                @click="saveCleanupConfig"
                :icon="Check"
              >
                保存保留策略
              </el-button>
            </div>
          </div>
        </el-tab-pane>
      </el-tabs>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { getDefenseConfig, updateDefenseConfig, getCleanupConfig, updateCleanupConfig, manualDataCleanup } from '@/api'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Check, Delete, Lock, Box, Setting, WarningFilled } from '@element-plus/icons-vue'

const activeTab = ref('defense')
const defenseConfig = ref({ auto_block: true, block_duration: 3600, threshold_pps: 500 })
const cleanupConfig = ref({ retention_days: 30 })

const fetchConfigs = async () => {
  try {
    const [defRes, clnRes] = await Promise.all([getDefenseConfig(), getCleanupConfig()])
    if (defRes) Object.assign(defenseConfig.value, defRes)
    if (clnRes) Object.assign(cleanupConfig.value, clnRes)
  } catch {}
}

const saveDefenseConfig = async () => {
  try {
    await updateDefenseConfig(defenseConfig.value)
    ElMessage.success('防御参数已同步至配置中心')
  } catch {}
}

const saveCleanupConfig = async () => {
  try {
    await updateCleanupConfig(cleanupConfig.value)
    ElMessage.success('数据保留策略已更新')
  } catch {}
}

const runManualCleanup = async () => {
  try {
    await ElMessageBox.confirm(
      `系统将强制清理超过 ${cleanupConfig.value.retention_days} 天的所有非核心数据，这可能会释放大量磁盘空间，是否继续？`, 
      '立即清理确认', 
      { 
        confirmButtonText: '立即执行',
        cancelButtonText: '取消',
        type: 'warning',
        dangerouslyUseHTMLString: true
      }
    )
    const res: any = await manualDataCleanup()
    ElMessage.success(res.message || '磁盘清理任务已完成')
  } catch (e: any) {}
}

onMounted(fetchConfigs)
</script>

<style scoped>
.settings-wrapper {
  padding: 30px;
  background-color: #f1f5f9;
  min-height: calc(100vh - 60px);
}

/* 头部样式 */
.settings-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 30px;
}
.header-left { display: flex; align-items: center; gap: 20px; }
.header-icon-bg {
  width: 56px; height: 56px; border-radius: 16px;
  background: linear-gradient(135deg, #475569, #1e293b);
  display: flex; align-items: center; justify-content: center;
  font-size: 30px; color: white; box-shadow: 0 8px 16px rgba(30, 41, 59, 0.2);
}
.main-title { font-size: 28px; font-weight: 800; color: #1e293b; margin: 0; }
.status-indicator { display: flex; align-items: center; gap: 8px; margin-top: 5px; }
.pulse-dot { width: 8px; height: 8px; border-radius: 50%; background-color: #10b981; }
.pulse-dot.active { animation: pulse-green 2s infinite; }

@keyframes pulse-green {
  0% { box-shadow: 0 0 0 0px rgba(16, 185, 129, 0.7); }
  70% { box-shadow: 0 0 0 10px rgba(16, 185, 129, 0); }
  100% { box-shadow: 0 0 0 0px rgba(16, 185, 129, 0); }
}
.status-text { font-size: 13px; color: #64748b; font-weight: 500; }

/* 玻璃拟态主卡片 */
.glass-card {
  background: white; border-radius: 24px; padding: 0;
  box-shadow: 0 10px 25px -5px rgba(0,0,0,0.05); border: 1px solid rgba(255,255,255,0.8);
  overflow: hidden;
}

/* 选项卡美化 */
.modern-tabs :deep(.el-tabs__header) {
  margin: 0; padding: 10px 30px 0; background: #f8fafc; border-bottom: 1px solid #e2e8f0;
}
.modern-tabs :deep(.el-tabs__item) { height: 60px; font-size: 15px; font-weight: 700; color: #64748b; }
.modern-tabs :deep(.el-tabs__item.is-active) { color: #1e293b; }
.tab-label { display: flex; align-items: center; gap: 10px; }
.tab-content-wrapper { padding: 40px; max-width: 900px; }

/* 表单与项美化 */
.config-alert { border-radius: 12px; margin-bottom: 35px; padding: 15px 20px; }
.setting-item-box {
  display: flex; justify-content: space-between; align-items: center;
  background: #f8fafc; padding: 25px; border-radius: 18px; border: 1px solid #edf2f7;
}
.setting-item-box.vertical { flex-direction: column; align-items: flex-start; gap: 20px; }
.item-title { font-size: 16px; font-weight: 800; color: #1e293b; margin: 0 0 8px 0; }
.item-desc { font-size: 13px; color: #64748b; margin: 0; line-height: 1.5; }

/* 输入控件拟态化 */
.input-with-unit { display: flex; align-items: center; gap: 15px; }
.unit-tag { font-size: 12px; font-weight: 800; color: #94a3b8; background: #f1f5f9; padding: 4px 10px; border-radius: 6px; }
.modern-number-input { width: 180px; }
.modern-number-input :deep(.el-input__inner) { font-weight: 700; font-family: 'JetBrains Mono', monospace; }

/* 开关组件样式 */
.custom-switch :deep(.el-switch__label) {
  width: auto !important;
  margin: 0 10px;
}

/* 存储面板 */
.storage-dashboard { background: #f1f5f9; padding: 30px; border-radius: 20px; }
.storage-item { display: flex; flex-direction: column; gap: 15px; }
.s-label { font-size: 14px; font-weight: 700; color: #475569; }
.s-control { display: flex; align-items: center; gap: 15px; }
.s-unit { font-weight: 700; color: #1e293b; }
.s-hint { font-size: 12px; color: #94a3b8; margin: 0; }

/* 危险区控制台 */
.cleanup-console { border: 2px dashed #fecaca; border-radius: 20px; overflow: hidden; }
.console-header { background: #fef2f2; padding: 12px 25px; display: flex; align-items: center; gap: 10px; color: #ef4444; font-weight: 800; font-size: 13px; }
.console-body { padding: 25px; display: flex; justify-content: space-between; align-items: center; }
.body-text h5 { margin: 0 0 5px 0; font-size: 15px; color: #991b1b; }
.body-text p { margin: 0; font-size: 12px; color: #f87171; }

/* 按钮样式 */
.form-actions { display: flex; gap: 15px; }
.save-btn { padding: 30px 45px; font-size: 16px; border-radius: 14px; font-weight: 800; min-width: 200px; }
.shadow-primary { box-shadow: 0 8px 20px rgba(59, 130, 246, 0.3); }

.mt-30 { margin-top: 30px; }
.mt-40 { margin-top: 40px; }
</style>