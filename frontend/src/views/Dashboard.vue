<template>
  <div class="dashboard-wrapper">
    <div class="dashboard-header">
      <div class="header-left">
        <h1 class="main-title">监控大盘</h1>
        <div class="status-indicator">
          <span class="pulse-dot"></span>
          <span class="status-text">实时系统监控中</span>
        </div>
      </div>
      <div class="header-right">
        <el-button 
          type="primary" 
          class="refresh-btn" 
          :loading="isRefreshing" 
          @click="manualRefresh"
          round
        >
          <el-icon><Refresh /></el-icon> 立即刷新数据
        </el-button>
      </div>
    </div>

    <el-row :gutter="20" class="stat-cards">
      <el-col :xs="24" :sm="12" :lg="6" v-for="(card, index) in topCards" :key="index">
        <div class="glass-card stat-item" :class="'border-' + card.type">
          <div class="stat-icon" :class="'bg-' + card.type">
            <el-icon><component :is="card.icon" /></el-icon>
          </div>
          <div class="stat-info">
            <div class="stat-label">{{ card.title }}</div>
            <div class="stat-value">{{ card.value }}</div>
            <el-tag :type="card.tagType" size="small" effect="light" class="stat-tag">
              {{ card.tagText }}
            </el-tag>
          </div>
        </div>
      </el-col>
    </el-row>

    <el-row :gutter="20" class="content-row">
      <el-col :span="24">
        <div class="glass-card service-section">
          <div class="section-header">
            <div class="title-with-icon">
              <el-icon><Cpu /></el-icon>
              <span>核心服务引擎状态</span>
            </div>
            <div class="service-badge">
              运行中: <strong>{{ runningServicesCount }}</strong> / {{ Object.keys(services).length }}
            </div>
          </div>
          <div class="service-list">
            <div 
              v-for="(info, name) in services" 
              :key="name" 
              class="service-card"
              :class="info.status === 'running' || info.status === 'enabled' ? 'active' : 'inactive'"
            >
              <div class="service-status-icon">
                <el-icon v-if="info.status === 'running' || info.status === 'enabled'"><CircleCheck /></el-icon>
                <el-icon v-else><CircleClose /></el-icon>
              </div>
              <div class="service-details">
                <div class="service-name">{{ name }}</div>
                <div class="service-state-text">{{ info.status === 'enabled' ? '已启用防护' : (info.status === 'running' ? '正在运行' : '已停止') }}</div>
              </div>
            </div>
          </div>
        </div>
      </el-col>
    </el-row>

    <el-row :gutter="20" class="content-row">
      <el-col :xs="24" :md="12" :lg="8">
        <div class="glass-card chart-container">
          <div class="section-header">
            <div class="title-with-icon">
              <el-icon><TrendCharts /></el-icon>
              <span>CPU 负载趋势</span>
            </div>
          </div>
          <div id="cpuTrendChart" style="width: 100%; height: 280px;"></div>
        </div>
      </el-col>

      <el-col :xs="24" :md="12" :lg="8">
        <div class="glass-card chart-container">
          <div class="section-header">
            <div class="title-with-icon">
              <el-icon><PieChart /></el-icon>
              <span>内存使用趋势</span>
            </div>
          </div>
          <div id="memTrendChart" style="width: 100%; height: 280px;"></div>
        </div>
      </el-col>

      <el-col :xs="24" :lg="8">
        <div class="glass-card resource-details">
          <div class="section-header">
            <div class="title-with-icon">
              <el-icon><Odometer /></el-icon>
              <span>硬件与网络概览</span>
            </div>
          </div>
          <div class="resource-content">
            <div class="resource-block">
              <div class="label-row">
                <span>磁盘存储容量</span>
                <span class="value">{{ monitorData.disk?.percent || 0 }}%</span>
              </div>
              <el-progress 
                :percentage="monitorData.disk?.percent || 0" 
                :color="getDiskStatusColor(monitorData.disk?.percent || 0)"
                :stroke-width="12"
                :show-text="false"
              />
            </div>
            
            <div class="network-stats">
              <div class="net-item">
                <div class="net-icon down"><el-icon><Download /></el-icon></div>
                <div class="net-info">
                  <span class="net-label">入网流量</span>
                  <span class="net-val">{{ (monitorData.network?.bytes_recv / 1024 / 1024).toFixed(2) }} <small>MB</small></span>
                </div>
              </div>
              <div class="net-item">
                <div class="net-icon up"><el-icon><Upload /></el-icon></div>
                <div class="net-info">
                  <span class="net-label">出网流量</span>
                  <span class="net-val">{{ (monitorData.network?.bytes_sent / 1024 / 1024).toFixed(2) }} <small>MB</small></span>
                </div>
              </div>
            </div>

            <div class="realtime-metrics">
              <div class="metric-box">
                <div class="m-val text-blue">{{ summary.capture_stats?.packets_per_second || 0 }}</div>
                <div class="m-label">实时抓包 (pps)</div>
              </div>
              <div class="metric-box">
                <div class="m-val text-green">{{ monitorData.active_connections || 0 }}</div>
                <div class="m-label">活跃连接</div>
              </div>
            </div>
          </div>
        </div>
      </el-col>
    </el-row>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, onBeforeUnmount, computed, markRaw } from 'vue'
import { getStatsSummary, getMonitorSummary, getServicesStatus } from '@/api'
import * as echarts from 'echarts'
import { ElMessage } from 'element-plus'
import { 
  Refresh, CircleCheck, TrendCharts, Cpu, Odometer, Download, Upload, CircleClose, PieChart
} from '@element-plus/icons-vue'

// 数据状态映射自 API 接口
const summary = ref<any>({})
const monitorData = ref<any>({})
const services = ref<any>({})
const isRefreshing = ref(false)

// 趋势图数据缓存
const MAX_HISTORY = 20
const historyLabels = ref<string[]>([])
const cpuHistory = ref<number[]>([])
const memHistory = ref<number[]>([])

// ECharts 实例
let cpuChart: echarts.ECharts | null = null
let memChart: echarts.ECharts | null = null
let pollTimer: any = null

// 统计逻辑
const runningServicesCount = computed(() => {
  return Object.values(services.value).filter((info: any) => 
    info.status === 'running' || info.status === 'enabled'
  ).length
})

const topCards = computed(() => [
  { title: '累计检测流量', value: `${summary.value.traffic_count || 0}`, icon: 'DataAnalysis', type: 'primary', tagText: '包量统计', tagType: 'info' },
  { title: '安全告警总数', value: `${summary.value.alert_count || 0}`, icon: 'Warning', type: 'danger', tagText: summary.value.alert_count > 0 ? '需处理' : '无威胁', tagType: summary.value.alert_count > 0 ? 'danger' : 'success' },
  { title: '当前拦截黑名单', value: `${summary.value.blacklist_count || 0}`, icon: 'Lock', type: 'warning', tagText: '实时封禁', tagType: 'warning' },
  { title: '系统拦截次数', value: `${summary.value.block_count || 0}`, icon: 'CircleCheck', type: 'success', tagText: '防护记录', tagType: 'success' }
])

const getDiskStatusColor = (p: number) => p > 85 ? '#f56c6c' : (p > 60 ? '#e6a23c' : '#10b981')

// 初始化与更新图表
const updateCpuChart = () => {
  const dom = document.getElementById('cpuTrendChart')
  if (!dom) return
  if (!cpuChart) cpuChart = markRaw(echarts.init(dom))

  cpuChart.setOption({
    tooltip: { trigger: 'axis' },
    grid: { left: '3%', right: '4%', bottom: '3%', containLabel: true },
    xAxis: { type: 'category', boundaryGap: false, data: historyLabels.value },
    yAxis: { type: 'value', max: 100, axisLabel: { formatter: '{value}%' } },
    series: [{
      name: 'CPU负载', type: 'line', smooth: true, data: cpuHistory.value,
      itemStyle: { color: '#ff7f0e' },
      areaStyle: { color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [{offset: 0, color: 'rgba(255,127,14,0.3)'}, {offset: 1, color: 'transparent'}]) }
    }],
    animation: false
  })
}

const updateMemChart = () => {
  const dom = document.getElementById('memTrendChart')
  if (!dom) return
  if (!memChart) memChart = markRaw(echarts.init(dom))

  memChart.setOption({
    tooltip: { trigger: 'axis' },
    grid: { left: '3%', right: '4%', bottom: '3%', containLabel: true },
    xAxis: { type: 'category', boundaryGap: false, data: historyLabels.value },
    yAxis: { type: 'value', max: 100, axisLabel: { formatter: '{value}%' } },
    series: [{
      name: '内存使用', type: 'line', smooth: true, data: memHistory.value,
      itemStyle: { color: '#1890ff' },
      areaStyle: { color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [{offset: 0, color: 'rgba(24,144,255,0.3)'}, {offset: 1, color: 'transparent'}]) }
    }],
    animation: false
  })
}

// 获取后端真实数据
const fetchData = async () => {
  try {
    const [stats, monitor, svcs] = await Promise.all([
      getStatsSummary(),
      getMonitorSummary(),
      getServicesStatus()
    ])
    summary.value = stats || {}
    monitorData.value = monitor || {}
    services.value = (svcs as any)?.services || {}

    // 推送实时指标
    const now = new Date().toTimeString().slice(0, 8)
    historyLabels.value.push(now)
    cpuHistory.value.push(monitorData.value.cpu?.percent || 0)
    memHistory.value.push(monitorData.value.memory?.percent || 0)

    if (historyLabels.value.length > MAX_HISTORY) {
      historyLabels.value.shift(); cpuHistory.value.shift(); memHistory.value.shift()
    }
    
    updateCpuChart()
    updateMemChart()
  } catch (e) {
    console.error('Data error', e)
  }
}

const manualRefresh = async () => {
  isRefreshing.value = true
  await fetchData()
  isRefreshing.value = false
  ElMessage.success('监控数据已刷新')
}

onMounted(() => {
  fetchData()
  pollTimer = setInterval(fetchData, 1000)
  window.addEventListener('resize', () => {
    cpuChart?.resize()
    memChart?.resize()
  })
})

onBeforeUnmount(() => {
  clearInterval(pollTimer)
  cpuChart?.dispose()
  memChart?.dispose()
})
</script>

<style scoped>
/* 核心容器 */
.dashboard-wrapper {
  padding: 30px;
  background-color: #f0f4f8;
  min-height: calc(100vh - 60px);
}

/* 头部样式 */
.dashboard-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 30px;
}
.main-title {
  font-size: 28px;
  font-weight: 800;
  color: #1a202c;
  margin: 0;
}
.status-indicator {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-top: 5px;
}
.pulse-dot {
  width: 8px;
  height: 8px;
  background-color: #10b981;
  border-radius: 50%;
  animation: pulse 2s infinite;
}
@keyframes pulse {
  0% { box-shadow: 0 0 0 0px rgba(16, 185, 129, 0.7); }
  70% { box-shadow: 0 0 0 10px rgba(16, 185, 129, 0); }
  100% { box-shadow: 0 0 0 0px rgba(16, 185, 129, 0); }
}
.status-text { font-size: 13px; color: #718096; }

/* 玻璃拟态卡片 */
.glass-card {
  background: white;
  border-radius: 20px;
  padding: 24px;
  box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.05);
  border: 1px solid rgba(255, 255, 255, 0.8);
  height: 100%;
  box-sizing: border-box;
  transition: transform 0.3s;
}
.glass-card:hover { transform: translateY(-5px); }

/* 统计卡片 */
.stat-cards { margin-bottom: 25px; }
.stat-item { display: flex; align-items: center; gap: 20px; }
.stat-icon {
  width: 60px;
  height: 60px;
  border-radius: 16px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 28px;
  color: white;
}
.bg-primary { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }
.bg-danger { background: linear-gradient(135deg, #f56565 0%, #c53030 100%); }
.bg-warning { background: linear-gradient(135deg, #ed8936 0%, #dd6b20 100%); }
.bg-success { background: linear-gradient(135deg, #48bb78 0%, #2f855a 100%); }
.stat-value { font-size: 28px; font-weight: 800; color: #2d3748; margin: 4px 0; }
.stat-label { font-size: 14px; color: #718096; font-weight: 600; }

/* 服务列表 */
.section-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 20px;
}
.title-with-icon {
  display: flex;
  align-items: center;
  gap: 10px;
  font-size: 17px;
  font-weight: 700;
  color: #2d3748;
}
.service-list {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
  gap: 15px;
}
.service-card {
  display: flex;
  align-items: center;
  padding: 15px 20px;
  border-radius: 14px;
  background: #f7fafc;
  border-left: 5px solid transparent;
}
.service-card.active { border-left-color: #10b981; }
.service-card.inactive { border-left-color: #f56565; }
.service-status-icon { font-size: 22px; margin-right: 15px; }
.active .service-status-icon { color: #10b981; }
.inactive .service-status-icon { color: #f56565; }

/* 资源块 */
.resource-block { margin-bottom: 25px; }
.label-row {
  display: flex;
  justify-content: space-between;
  margin-bottom: 10px;
  font-size: 14px;
  font-weight: 600;
}
.network-stats {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 15px;
  margin-bottom: 25px;
}
.net-item {
  display: flex;
  align-items: center;
  gap: 12px;
  background: #f8fafc;
  padding: 12px;
  border-radius: 12px;
}
.net-icon {
  width: 32px; height: 32px; border-radius: 8px;
  display: flex; align-items: center; justify-content: center; color: white;
}
.net-icon.down { background-color: #3182ce; }
.net-icon.up { background-color: #805ad5; }
.net-val { font-weight: 700; color: #2d3748; }
.net-label { font-size: 12px; color: #718096; }

.realtime-metrics {
  display: flex;
  justify-content: space-around;
  border-top: 1px dashed #e2e8f0;
  padding-top: 20px;
}
.metric-box { text-align: center; }
.m-val { font-size: 22px; font-weight: 800; }
.text-blue { color: #3182ce; }
.text-green { color: #38a169; }

.content-row { margin-top: 25px; }
</style>