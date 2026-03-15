<template>
  <div class="alerts-wrapper">
    <div class="alerts-header">
      <div class="header-left">
        <div class="header-icon-bg">
          <el-icon><WarningFilled /></el-icon>
        </div>
        <div class="header-content">
          <h1 class="main-title">安全告警中心</h1>
          <div class="status-indicator">
            <span class="pulse-dot warning"></span>
            <span class="status-text">实时威胁检测引擎运行中</span>
          </div>
        </div>
      </div>
      <div class="header-right">
        <el-button 
          type="danger" 
          class="clear-btn" 
          @click="handleClearAll" 
          :icon="Delete" 
          plain 
          round
        >
          清空历史告警记录
        </el-button>
      </div>
    </div>

    <el-row :gutter="20" class="stat-summary-row">
      <el-col :xs="24" :sm="8">
        <div class="mini-stat-card border-primary">
          <div class="m-stat-info">
            <span class="m-label">总告警次数</span>
            <span class="m-value text-primary">{{ total }}</span>
          </div>
          <el-icon class="m-icon color-primary"><Bell /></el-icon>
        </div>
      </el-col>
      <el-col :xs="24" :sm="8">
        <div class="mini-stat-card border-danger">
          <div class="m-stat-info">
            <span class="m-label">未处理高危威胁</span>
            <span class="m-value text-danger">{{ highRiskCount }}</span>
          </div>
          <el-icon class="m-icon color-danger"><Warning /></el-icon>
        </div>
      </el-col>
      <el-col :xs="24" :sm="8">
        <div class="mini-stat-card border-success">
          <div class="m-stat-info">
            <span class="m-label">今日已解决事件</span>
            <span class="m-value text-success">{{ resolvedCount }}</span>
          </div>
          <el-icon class="m-icon color-success"><CircleCheck /></el-icon>
        </div>
      </el-col>
    </el-row>

    <div class="glass-card filter-section">
      <el-row :gutter="15">
        <el-col :xs="24" :sm="12" :md="5">
          <div class="filter-item">
            <span class="filter-label">威胁等级</span>
            <el-select v-model="filterParams.severity" placeholder="全部等级" clearable class="full-width">
              <el-option label="🔥 高危 (High)" value="high" />
              <el-option label="⚡ 中危 (Medium)" value="medium" />
              <el-option label="🌱 低危 (Low)" value="low" />
            </el-select>
          </div>
        </el-col>
        <el-col :xs="24" :sm="12" :md="5">
          <div class="filter-item">
            <span class="filter-label">处置状态</span>
            <el-select v-model="filterParams.status" placeholder="全部状态" clearable class="full-width">
              <el-option label="待处理 (Pending)" value="pending" />
              <el-option label="已解决 (Resolved)" value="resolved" />
            </el-select>
          </div>
        </el-col>
        <el-col :xs="24" :sm="12" :md="10" class="flex-end">
          <el-button type="primary" class="action-btn shadow-primary" @click="handleFilter" icon="Search">筛选事件</el-button>
          <el-button class="action-btn" @click="resetFilter" icon="RefreshRight">重置</el-button>
        </el-col>
      </el-row>
    </div>

    <div class="glass-card table-section">
      <el-table 
        :data="alerts" 
        v-loading="loading" 
        class="modern-table"
        :row-class-name="tableRowClassName"
        stripe
      >
        <el-table-column prop="level" label="优先级" width="110" align="center">
          <template #default="{ row }">
            <div :class="['level-indicator', getLevelType(row.level)]">
              <el-icon><component :is="getLevelIcon(row.level)" /></el-icon>
              <span>{{ getLevelText(row.level) }}</span>
            </div>
          </template>
        </el-table-column>

        <el-table-column label="威胁来源 (源 IP)" width="180">
          <template #default="{ row }">
            <div class="ip-display">
              <el-icon :class="{ 'is-active': row.status !== 'resolved' }"><Monitor /></el-icon>
              <span class="font-mono">{{ row.src_ip || 'Internal' }}</span>
            </div>
          </template>
        </el-table-column>

        <el-table-column label="安全事件描述" min-width="300">
          <template #default="{ row }">
            <div class="event-details">
              <el-tag size="small" :type="row.status === 'resolved' ? 'info' : 'danger'" class="type-tag">
                {{ row.type || '异常流' }}
              </el-tag>
              <span class="desc-text">{{ row.description }}</span>
            </div>
          </template>
        </el-table-column>

        <el-table-column label="发生时间" width="180" align="center">
          <template #default="{ row }">
            <span class="time-text">{{ formatTime(row.timestamp) }}</span>
          </template>
        </el-table-column>

        <el-table-column label="状态" width="110" align="center">
          <template #default="{ row }">
            <div :class="['status-dot-text', row.status === 'resolved' ? 'is-success' : 'is-pending']">
              <span class="dot"></span>
              {{ row.status === 'resolved' ? '已解决' : '待处理' }}
            </div>
          </template>
        </el-table-column>

        <el-table-column label="管理操作" width="140" fixed="right" align="center">
          <template #default="{ row }">
            <el-button 
              v-if="row.status !== 'resolved'" 
              type="success" 
              link
              @click="markResolved(row.id)"
              icon="Check"
            >
              标记解决
            </el-button>
            <el-icon v-else color="#10b981" :size="20"><CircleCheckFilled /></el-icon>
          </template>
        </el-table-column>

        <template #empty>
          <el-empty description="当前网络环境安全，无未处理告警" :image-size="120" />
        </template>
      </el-table>
      
      <div class="pagination-container">
        <el-pagination 
          v-model:current-page="page" 
          v-model:page-size="limit" 
          :total="total" 
          @current-change="fetchAlerts" 
          background 
          layout="total, prev, pager, next" 
        />
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, reactive, computed } from 'vue'
import { getAlerts, updateAlertStatus, clearAllAlerts } from '@/api'
import { ElMessage, ElMessageBox } from 'element-plus'
import { 
  Delete, Check, Warning, CircleClose, InfoFilled, 
  WarningFilled, Monitor, Bell, CircleCheck, Search,
  RefreshRight, CircleCheckFilled
} from '@element-plus/icons-vue'

const loading = ref(false)
const alerts = ref<any[]>([])
const page = ref(1)
const limit = ref(15)
const total = ref(0)

const filterParams = reactive({
  severity: '',
  status: ''
})

// 计算属性：高危告警数和今日解决数
const highRiskCount = computed(() => alerts.value.filter(a => a.status !== 'resolved' && (a.level?.toLowerCase() === 'high' || a.level?.toLowerCase() === 'critical')).length)
const resolvedCount = computed(() => alerts.value.filter(a => a.status === 'resolved').length)

const formatTime = (ts: number) => {
  if (!ts) return '-'
  return new Date(ts > 1e11 ? ts : ts * 1000).toLocaleString('zh-CN', { hour12: false })
}

const getLevelType = (level: string) => {
  const l = level?.toLowerCase()
  if (l === 'high' || l === 'critical') return 'danger'
  if (l === 'medium') return 'warning'
  return 'info'
}

const getLevelIcon = (level: string) => {
  const l = level?.toLowerCase()
  if (l === 'high' || l === 'critical') return CircleClose
  if (l === 'medium') return Warning
  return InfoFilled
}

const getLevelText = (level: string) => {
  const l = level?.toLowerCase()
  if (l === 'high' || l === 'critical') return '高危'
  if (l === 'medium') return '中危'
  return '低危'
}

const tableRowClassName = ({ row }: { row: any }) => {
  if (row.status !== 'resolved') {
    const l = row.level?.toLowerCase()
    if (l === 'high' || l === 'critical') return 'row-critical-highlight'
  }
  return ''
}

const fetchAlerts = async () => {
  loading.value = true
  try {
    const res: any = await getAlerts({ 
      limit: limit.value, 
      offset: (page.value - 1) * limit.value,
      severity: filterParams.severity || undefined,
      status: filterParams.status || undefined
    })
    alerts.value = res.alerts || []
    total.value = res.total || 0
  } catch (error) {
    ElMessage.error('告警流水同步异常')
  } finally {
    loading.value = false
  }
}

const handleFilter = () => { page.value = 1; fetchAlerts(); }
const resetFilter = () => { filterParams.severity = ''; filterParams.status = ''; handleFilter(); }

const markResolved = async (id: number) => {
  try {
    await updateAlertStatus(id, 'resolved')
    ElMessage.success('威胁事件已标记为处理完成')
    fetchAlerts()
  } catch (error) {
    ElMessage.error('状态更新指令下发失败')
  }
}

const handleClearAll = async () => {
  try {
    await ElMessageBox.confirm(
      '此操作将永久抹除所有历史告警审计记录。确定要执行此危险操作吗?', 
      '核心审计清理确认', 
      { type: 'error', confirmButtonText: '确定清空', confirmButtonClass: 'el-button--danger' }
    )
    await clearAllAlerts()
    ElMessage.success('历史告警库已重置')
    page.value = 1; fetchAlerts()
  } catch {}
}

onMounted(fetchAlerts)
</script>

<style scoped>
.alerts-wrapper {
  padding: 30px;
  background-color: #f1f5f9;
  min-height: calc(100vh - 60px);
}

/* 头部样式 */
.alerts-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 30px;
}
.header-left { display: flex; align-items: center; gap: 20px; }
.header-icon-bg {
  width: 56px; height: 56px; border-radius: 16px;
  background: linear-gradient(135deg, #f87171, #dc2626);
  display: flex; align-items: center; justify-content: center;
  font-size: 30px; color: white; box-shadow: 0 8px 16px rgba(220, 38, 38, 0.2);
}
.main-title { font-size: 28px; font-weight: 800; color: #1e293b; margin: 0; }
.status-indicator { display: flex; align-items: center; gap: 8px; margin-top: 5px; }
.pulse-dot { width: 8px; height: 8px; border-radius: 50%; }
.pulse-dot.warning { background-color: #f59e0b; animation: pulse-orange 2s infinite; }
@keyframes pulse-orange {
  0% { box-shadow: 0 0 0 0px rgba(245, 158, 11, 0.7); }
  70% { box-shadow: 0 0 0 10px rgba(245, 158, 11, 0); }
  100% { box-shadow: 0 0 0 0px rgba(245, 158, 11, 0); }
}
.status-text { font-size: 13px; color: #64748b; }

/* 统计概要 */
.stat-summary-row { margin-bottom: 25px; }
.mini-stat-card {
  background: white; border-radius: 16px; padding: 20px; display: flex; justify-content: space-between; align-items: center;
  box-shadow: 0 4px 15px -3px rgba(0, 0, 0, 0.04); border-left: 5px solid transparent;
}
.mini-stat-card.border-primary { border-left-color: #3b82f6; }
.mini-stat-card.border-danger { border-left-color: #ef4444; }
.mini-stat-card.border-success { border-left-color: #10b981; }
.m-label { font-size: 13px; color: #64748b; font-weight: 600; }
.m-value { font-size: 28px; font-weight: 800; margin-top: 4px; display: block; }
.m-icon { font-size: 32px; opacity: 0.15; }

/* 玻璃拟态卡片 */
.glass-card {
  background: white; border-radius: 20px; padding: 25px; margin-bottom: 25px;
  box-shadow: 0 10px 25px -5px rgba(0,0,0,0.05); border: 1px solid rgba(255,255,255,0.8);
}

/* 筛选器 */
.filter-item { display: flex; flex-direction: column; gap: 8px; }
.filter-label { font-size: 12px; color: #64748b; font-weight: 700; padding-left: 2px; }
.flex-end { display: flex; align-items: flex-end; justify-content: flex-end; gap: 10px; }
.action-btn { font-weight: 700; height: 40px; }
.shadow-primary { box-shadow: 0 4px 12px rgba(59, 130, 246, 0.3); }

/* 表格定制 */
.level-indicator { display: flex; align-items: center; justify-content: center; gap: 6px; font-weight: 800; font-size: 13px; }
.level-indicator.danger { color: #ef4444; }
.level-indicator.warning { color: #f59e0b; }
.level-indicator.info { color: #3b82f6; }

.ip-display { display: flex; align-items: center; gap: 8px; color: #475569; }
.ip-display .is-active { color: #ef4444; }
.font-mono { font-family: 'JetBrains Mono', 'Fira Code', monospace; font-weight: 700; }

.event-details { display: flex; align-items: center; gap: 10px; }
.type-tag { font-weight: 700; border-radius: 6px; }
.desc-text { color: #1e293b; font-weight: 500; font-size: 13px; }

.time-text { color: #94a3b8; font-size: 12px; }

.status-dot-text { display: flex; align-items: center; gap: 6px; font-weight: 700; font-size: 13px; }
.status-dot-text .dot { width: 6px; height: 6px; border-radius: 50%; }
.is-success { color: #10b981; }
.is-success .dot { background-color: #10b981; }
.is-pending { color: #ef4444; }
.is-pending .dot { background-color: #ef4444; animation: blink 1.5s infinite; }

@keyframes blink { 0% { opacity: 1; } 50% { opacity: 0.4; } 100% { opacity: 1; } }

:deep(.row-critical-highlight) { background-color: rgba(239, 68, 68, 0.03) !important; }

.pagination-container { margin-top: 25px; display: flex; justify-content: flex-end; }
.full-width { width: 100%; }
</style>