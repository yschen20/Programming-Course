<template>
  <div class="defense-wrapper">
    <div class="defense-header">
      <div class="header-left">
        <h1 class="main-title">安全防御管理</h1>
        <div class="status-indicator">
          <span class="shield-icon"><el-icon><HelpFilled /></el-icon></span>
          <span class="status-text">智能防火墙引擎运行中</span>
        </div>
      </div>
      <div class="header-right">
        <el-button 
          type="primary" 
          class="refresh-btn" 
          @click="fetchCurrentTabData" 
          :loading="loading.blocked || loading.whitelist || loading.history"
          round
        >
          <el-icon><Refresh /></el-icon> 同步最新策略
        </el-button>
      </div>
    </div>

    <el-row :gutter="20" class="stat-summary-row">
      <el-col :xs="24" :sm="8">
        <div class="mini-stat-card border-danger">
          <div class="m-stat-info">
            <span class="m-label">实时封禁 IP</span>
            <span class="m-value text-danger">{{ blockedIps.length }}</span>
          </div>
          <el-icon class="m-icon color-danger"><Lock /></el-icon>
        </div>
      </el-col>
      <el-col :xs="24" :sm="8">
        <div class="mini-stat-card border-success">
          <div class="m-stat-info">
            <span class="m-label">受信白名单</span>
            <span class="m-value text-success">{{ whitelist.length }}</span>
          </div>
          <el-icon class="m-icon color-success"><CircleCheck /></el-icon>
        </div>
      </el-col>
      <el-col :xs="24" :sm="8">
        <div class="mini-stat-card border-primary">
          <div class="m-stat-info">
            <span class="m-label">历史防御总计</span>
            <span class="m-value text-primary">{{ historyTotal }}</span>
          </div>
          <el-icon class="m-icon color-primary"><Checked /></el-icon>
        </div>
      </el-col>
    </el-row>

    <div class="glass-card main-content">
      <el-tabs v-model="activeTab" @tab-change="handleTabChange" class="modern-tabs">
        
        <el-tab-pane name="blocked">
          <template #label>
            <span class="tab-label"><el-icon><Warning /></el-icon> 实时拦截名单</span>
          </template>
          
          <div class="tab-toolbar">
            <el-button type="danger" @click="openBlockDialog" icon="Lock" class="action-btn shadow-danger">
              手动拦截恶意 IP
            </el-button>
          </div>

          <el-table :data="blockedIps" v-loading="loading.blocked" class="custom-table" stripe>
            <el-table-column prop="ip" label="被拦截 IP" width="180">
              <template #default="{ row }">
                <div class="ip-cell">
                  <el-icon><Monitor /></el-icon>
                  <span class="font-mono text-danger">{{ row.ip }}</span>
                </div>
              </template>
            </el-table-column>
            <el-table-column prop="attack_type" label="威胁判定" width="140">
              <template #default="{ row }">
                <el-tag :type="getAttackTagType(row.attack_type)" effect="dark" round>
                  {{ row.attack_type || '风险流量' }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="reason" label="拦截依据" show-overflow-tooltip />
            <el-table-column label="封禁时间" width="180">
              <template #default="{ row }"><span class="time-text">{{ formatTime(row.blocked_at) }}</span></template>
            </el-table-column>
            <el-table-column label="自动解封" width="180">
              <template #default="{ row }">
                <span :class="['time-text', isExpiringSoon(row.expires_at) ? 'expire-urgent' : '']">
                  {{ row.expires_at ? formatTime(row.expires_at) : '永久封禁' }}
                </span>
              </template>
            </el-table-column>
            <el-table-column label="管理操作" width="120" fixed="right">
              <template #default="{ row }">
                <el-button type="success" link @click="handleUnblock(row.ip)" icon="Unlock">立即解封</el-button>
              </template>
            </el-table-column>
            <template #empty><el-empty description="当前网络环境纯净，暂无拦截对象" /></template>
          </el-table>
        </el-tab-pane>

        <el-tab-pane name="whitelist">
          <template #label>
            <span class="tab-label"><el-icon><CircleCheck /></el-icon> 安全受信白名单</span>
          </template>
          <div class="tab-toolbar">
            <el-button type="primary" @click="openWhitelistDialog" icon="Plus" class="action-btn shadow-primary">
              添加受信任 IP
            </el-button>
          </div>
          <el-table :data="whitelist" v-loading="loading.whitelist" class="custom-table">
            <el-table-column label="受信 IP 地址">
              <template #default="{ row }">
                <div class="ip-cell">
                  <el-icon><CircleCheckFilled /></el-icon>
                  <span class="font-mono text-success">{{ row }}</span>
                </div>
              </template>
            </el-table-column>
            <el-table-column label="操作" width="120" fixed="right">
              <template #default="{ row }">
                <el-button type="danger" link @click="handleRemoveWhitelist(row)" icon="Delete">移除信任</el-button>
              </template>
            </el-table-column>
            <template #empty><el-empty description="暂未配置任何信任 IP" /></template>
          </el-table>
        </el-tab-pane>

        <el-tab-pane name="history">
          <template #label>
            <span class="tab-label"><el-icon><Checked /></el-icon> 历史拦截溯源</span>
          </template>
          <el-table :data="historyLogs" v-loading="loading.history" class="custom-table" stripe>
            <el-table-column prop="ip" label="拦截 IP" width="180">
              <template #default="{ row }"><span class="font-mono">{{ row.ip }}</span></template>
            </el-table-column>
            <el-table-column prop="attack_type" label="风险类型" width="140">
              <template #default="{ row }">
                <el-tag :type="getAttackTagType(row.attack_type)" effect="plain">{{ row.attack_type }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="reason" label="触发防御动作" show-overflow-tooltip />
            <el-table-column label="发生时间" width="200">
              <template #default="{ row }"><span class="time-text">{{ formatTime(row.blocked_at) }}</span></template>
            </el-table-column>
          </el-table>
          <div class="pagination-container">
            <el-pagination
              v-if="historyTotal > 0"
              v-model:current-page="historyParams.page"
              :page-size="historyParams.limit"
              :total="historyTotal"
              @current-change="fetchHistory"
              background
              layout="total, prev, pager, next"
            />
          </div>
        </el-tab-pane>
      </el-tabs>
    </div>

    <el-dialog v-model="showBlockDialog" title="手动封禁恶意 IP" width="480px" class="glass-dialog">
      <el-form :model="blockForm" label-position="top">
        <el-form-item label="目标 IP 地址" required>
          <el-input v-model="blockForm.ip" placeholder="请输入合法的 IPv4 地址..." />
        </el-form-item>
        <el-form-item label="执行动作 / 封禁时长">
          <el-select v-model="blockForm.duration" class="full-width">
            <el-option label="拦截 1 小时 (警告)" :value="3600" />
            <el-option label="拦截 24 小时 (常规攻击)" :value="86400" />
            <el-option label="拦截 7 天 (严重威胁)" :value="604800" />
            <el-option label="永久加入黑名单" :value="315360000" />
          </el-select>
        </el-form-item>
        <el-form-item label="封禁原因备注">
          <el-input v-model="blockForm.reason" type="textarea" :rows="3" placeholder="可选，输入本次拦截的技术说明..." />
        </el-form-item>
      </el-form>
      <template #footer>
        <div class="dialog-footer">
          <el-button @click="showBlockDialog = false">放弃</el-button>
          <el-button type="danger" @click="submitBlockIp" class="shadow-danger">下发拦截策略</el-button>
        </div>
      </template>
    </el-dialog>

    <el-dialog v-model="showWhitelistDialog" title="配置信任 IP" width="420px" class="glass-dialog">
      <el-form :model="whitelistForm" label-position="top">
        <el-form-item label="白名单 IP" required>
          <el-input v-model="whitelistForm.ip" placeholder="该 IP 将绕过所有 AI 异常检测..." />
        </el-form-item>
      </el-form>
      <template #footer>
        <div class="dialog-footer">
          <el-button @click="showWhitelistDialog = false">取消</el-button>
          <el-button type="primary" @click="submitWhitelist" class="shadow-primary">确认放行</el-button>
        </div>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, reactive } from 'vue'
import { getBlockedIps, unblockIp, blockIp, getWhitelist, addWhitelist, removeWhitelist, getDefenseHistory } from '@/api'
import { ElMessage, ElMessageBox } from 'element-plus'
import { 
  HelpFilled, Refresh, Lock, CircleCheck, Checked, Monitor, CircleCheckFilled, Warning
} from '@element-plus/icons-vue'

const activeTab = ref('blocked')
const blockedIps = ref<any[]>([]); const whitelist = ref<string[]>([]); const historyLogs = ref<any[]>([])
const historyTotal = ref(0)
const historyParams = reactive({ limit: 12, page: 1 })
const loading = reactive({ blocked: false, whitelist: false, history: false })

const showBlockDialog = ref(false); const showWhitelistDialog = ref(false)
const blockForm = reactive({ ip: '', duration: 86400, reason: '管理员手动拦截' })
const whitelistForm = reactive({ ip: '' })

const openBlockDialog = () => { blockForm.ip = ''; blockForm.duration = 86400; blockForm.reason = '管理员手动拦截'; showBlockDialog.value = true }
const openWhitelistDialog = () => { whitelistForm.ip = ''; showWhitelistDialog.value = true }

const formatTime = (ts: number) => {
  if (!ts) return '-'
  return new Date(ts > 1e11 ? ts : ts * 1000).toLocaleString()
}
const isExpiringSoon = (ts: number) => {
  if (!ts) return false
  const diff = (ts > 1e11 ? ts / 1000 : ts) - (Date.now() / 1000)
  return diff > 0 && diff < 3600 
}

// IP地址格式验证
const validateIpAddress = (ip: string): boolean => {
  const ipRegex = /^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/
  return ipRegex.test(ip)
}

const getAttackTagType = (type: string) => {
  if (!type) return 'info'
  const t = type.toLowerCase()
  if (t.includes('ddos') || t.includes('注入') || t.includes('高危')) return 'danger'
  if (t.includes('cc') || t.includes('扫描')) return 'warning'
  return 'primary'
}

const fetchBlockedIps = async () => {
  loading.blocked = true; try { const res: any = await getBlockedIps(); blockedIps.value = res.blocked_ips || [] } catch { ElMessage.error('封禁名单同步失败') } finally { loading.blocked = false }
}
const fetchWhitelist = async () => {
  loading.whitelist = true; try { const res: any = await getWhitelist(); whitelist.value = res.whitelist || [] } catch { ElMessage.error('白名单同步失败') } finally { loading.whitelist = false }
}
const fetchHistory = async () => {
  loading.history = true; try { 
    const res: any = await getDefenseHistory({ limit: historyParams.limit, offset: (historyParams.page - 1) * historyParams.limit })
    historyLogs.value = res.history || []; historyTotal.value = res.total || 0
  } catch { ElMessage.error('历史记录同步失败') } finally { loading.history = false }
}

const fetchCurrentTabData = () => { activeTab.value === 'blocked' ? fetchBlockedIps() : activeTab.value === 'whitelist' ? fetchWhitelist() : fetchHistory() }
const handleTabChange = () => fetchCurrentTabData()

const handleUnblock = async (ip: string) => {
  try {
    await ElMessageBox.confirm(`解除对 ${ip} 的封禁后，该 IP 将恢复网络访问。是否下发指令?`, '解除拦截', { 
      confirmButtonText: '立即解封',
      cancelButtonText: '保持拦截',
      type: 'warning' 
    })
    await unblockIp({ ip }); ElMessage.success('解封策略已成功下发'); fetchBlockedIps()
  } catch (e) {}
}

const submitBlockIp = async () => {
  if (!blockForm.ip) return ElMessage.warning('请输入目标 IP 地址')
  if (!validateIpAddress(blockForm.ip)) return ElMessage.warning('请输入有效的 IPv4 地址')
  try { await blockIp(blockForm); ElMessage.success('IP 封禁策略已提交到队列，将在后台生效'); showBlockDialog.value = false; fetchBlockedIps() } catch { ElMessage.error('拦截失败') } }

const submitWhitelist = async () => {
  if (!whitelistForm.ip) return ElMessage.warning('请输入放行 IP 地址')
  if (!validateIpAddress(whitelistForm.ip)) return ElMessage.warning('请输入有效的 IPv4 地址')
  try { await addWhitelist({ ip: whitelistForm.ip }); ElMessage.success('白名单已提交到队列，将在后台生效'); showWhitelistDialog.value = false; fetchWhitelist() } catch { ElMessage.error('添加失败') } }

const handleRemoveWhitelist = async (ip: string) => {
  try { await ElMessageBox.confirm(`确定将 ${ip} 从信任名单移除?`, '移除确认', { type: 'warning' }); await removeWhitelist({ ip }); ElMessage.success('信任关系已解除'); fetchWhitelist() } catch (e) {}
}

onMounted(fetchCurrentTabData)
</script>

<style scoped>
.defense-wrapper {
  padding: 30px;
  background-color: #f1f5f9;
  min-height: calc(100vh - 60px);
}

/* 头部美化 */
.defense-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 25px;
}
.main-title {
  font-size: 28px;
  font-weight: 800;
  color: #1e293b;
  margin: 0;
}
.status-indicator {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-top: 6px;
}
.shield-icon {
  color: #10b981;
  font-size: 18px;
  display: flex;
}
.status-text {
  font-size: 13px;
  color: #64748b;
  font-weight: 500;
}

/* 统计概要卡片 */
.stat-summary-row { margin-bottom: 25px; }
.mini-stat-card {
  background: white;
  border-radius: 16px;
  padding: 20px;
  display: flex;
  justify-content: space-between;
  align-items: center;
  box-shadow: 0 4px 15px -3px rgba(0, 0, 0, 0.04);
  border-left: 5px solid transparent;
}
.mini-stat-card.border-danger { border-left-color: #ef4444; }
.mini-stat-card.border-success { border-left-color: #10b981; }
.mini-stat-card.border-primary { border-left-color: #3b82f6; }

.m-stat-info { display: flex; flex-direction: column; }
.m-label { font-size: 13px; color: #64748b; font-weight: 600; }
.m-value { font-size: 28px; font-weight: 800; margin-top: 4px; }
.m-icon { font-size: 32px; opacity: 0.15; }

/* 主体容器 (玻璃拟态) */
.glass-card {
  background: white;
  border-radius: 20px;
  padding: 25px;
  box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.05);
  border: 1px solid rgba(255, 255, 255, 0.8);
}

/* 选项卡美化 */
.modern-tabs :deep(.el-tabs__header) { margin-bottom: 25px; }
.modern-tabs :deep(.el-tabs__nav-wrap::after) { height: 1px; background-color: #e2e8f0; }
.modern-tabs :deep(.el-tabs__item) { height: 50px; font-size: 15px; font-weight: 600; color: #64748b; }
.modern-tabs :deep(.el-tabs__item.is-active) { color: #3b82f6; }
.tab-label { display: flex; align-items: center; gap: 8px; }

/* 工具栏 */
.tab-toolbar { margin-bottom: 20px; }
.action-btn { font-weight: 700; padding: 12px 20px; }
.shadow-danger { box-shadow: 0 4px 12px rgba(239, 68, 68, 0.2); }
.shadow-primary { box-shadow: 0 4px 12px rgba(59, 130, 246, 0.2); }

/* 表格定制 */
.custom-table :deep(.el-table__header) { background-color: #f8fafc; }
.ip-cell { display: flex; align-items: center; gap: 8px; font-size: 15px; }
.font-mono { font-family: 'JetBrains Mono', 'Fira Code', monospace; font-weight: 700; }
.time-text { color: #64748b; font-size: 13px; }
.expire-urgent { color: #f59e0b; font-weight: 800; animation: blink 2s infinite; }

@keyframes blink {
  0% { opacity: 1; }
  50% { opacity: 0.6; }
  100% { opacity: 1; }
}

.pagination-container {
  margin-top: 25px;
  display: flex;
  justify-content: flex-end;
}

/* 辅助样式 */
.full-width { width: 100%; }
.dialog-footer { display: flex; justify-content: flex-end; gap: 12px; }
</style>