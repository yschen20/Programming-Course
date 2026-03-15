<template>
  <div class="ai-model-wrapper">
    <div class="ai-header">
      <div class="header-left">
        <div class="header-icon-bg">
          <el-icon><Cpu /></el-icon>
        </div>
        <div class="header-content">
          <h1 class="main-title">AI 智能检测引擎</h1>
          <div class="status-indicator">
            <span :class="['pulse-dot', aiStats.is_trained ? 'online' : 'offline']"></span>
            <span class="status-text">{{ aiStats.is_trained ? '机器学习引擎已就绪' : '内核未训练或模型丢失' }}</span>
          </div>
        </div>
      </div>
      <div class="header-right">
        <el-button 
          type="primary" 
          class="refresh-btn" 
          :icon="Refresh" 
          @click="fetchAiStats" 
          round
        >
          刷新引擎状态
        </el-button>
      </div>
    </div>

    <el-row :gutter="25" class="main-content">
      <el-col :xs="24" :lg="9">
        <div class="glass-card status-section">
          <div class="section-title">
            <el-icon><DataAnalysis /></el-icon> 引擎内核状态
          </div>
          
          <div class="status-grid">
            <div class="status-item">
              <span class="label">当前算法</span>
              <span class="value algo">Isolation Forest</span>
            </div>
            <div class="status-item">
              <span class="label">激活版本</span>
              <span class="value font-mono">{{ aiStats.active_model || 'None' }}</span>
            </div>
          </div>

          <div class="stats-counter">
            <div class="counter-box">
              <span class="counter-label">分析流量总数</span>
              <span class="counter-val">{{ aiStats.total_detections || 0 }}</span>
            </div>
            <div class="counter-box danger">
              <span class="counter-label">判定异常次数</span>
              <span class="counter-val">{{ aiStats.anomalies_found || 0 }}</span>
            </div>
          </div>

          <el-divider><span class="divider-text">数据集训练与热更新</span></el-divider>

          <div class="upload-area">
            <el-upload
              class="custom-drag-upload"
              drag
              :http-request="customUpload"
              :on-success="handleUploadSuccess"
              :before-upload="beforeUpload"
            >
              <el-icon class="el-icon--upload"><CloudUpload /></el-icon>
              <div class="el-upload__text">
                拖拽 CSV/JSON 数据集到此处 <br /> <em>或者点击选择文件</em>
              </div>
            </el-upload>
            
            <div class="form-item-modern mt-20">
              <span class="form-label">指定模型版本名称</span>
              <el-input 
                v-model="uploadForm.modelName" 
                placeholder="例如: campus_v2_isolation" 
                class="modern-input"
              >
                <template #prefix><el-icon><CollectionTag /></el-icon></template>
              </el-input>
            </div>
            <p class="upload-tip">模型训练大约需要 30-60 秒，完成后将自动切换至新版本。</p>
          </div>
        </div>
      </el-col>

      <el-col :xs="24" :lg="15">
        <div class="glass-card sandbox-section">
          <div class="section-header-flex">
            <div class="section-title">
              <el-icon><Odometer /></el-icon> 特征演练沙盒
            </div>
            <el-tag effect="plain" type="info" round>Debug Mode</el-tag>
          </div>

          <div class="editor-container">
            <div class="editor-header">
              <span class="lang">JSON PAYLOAD</span>
              <div class="editor-dots"><span></span><span></span><span></span></div>
            </div>
            <el-input 
              v-model="testForm.payload" 
              type="textarea" 
              :rows="12" 
              class="code-textarea"
              placeholder='{"bytes_sent": 5000...}' 
            />
          </div>

          <div class="sandbox-actions">
            <el-button 
              type="primary" 
              size="large" 
              class="execute-btn shadow-primary" 
              @click="runDetection" 
              :icon="Monitor"
            >
              执行 AI 特征识别
            </el-button>
          </div>

          <transition name="el-zoom-in-top">
            <div v-if="detectResult" :class="['result-panel', detectResult.is_anomaly ? 'danger' : 'success']">
              <div class="result-header">
                <el-icon class="result-icon">
                  <component :is="detectResult.is_anomaly ? 'WarningFilled' : 'CircleCheckFilled'" />
                </el-icon>
                <div class="result-title">
                  <h3>{{ detectResult.is_anomaly ? '警报：检测到异常流量特征' : '检测结论：特征模式正常' }}</h3>
                  <p>基于当前激活模型 {{ detectResult.model_used }} 的分析结果</p>
                </div>
              </div>

              <div class="result-body">
                <div class="result-item">
                  <span class="res-label">判定置信度</span>
                  <el-progress 
                    :percentage="Math.round(detectResult.confidence * 100)" 
                    :color="detectResult.is_anomaly ? '#ef4444' : '#10b981'"
                    :stroke-width="12"
                    class="res-progress"
                  />
                </div>
                <div class="result-meta">
                  <div class="meta-box">
                    <span class="m-label">异常得分 (Score)</span>
                    <span class="m-val">{{ detectResult.score }}</span>
                  </div>
                  <div class="meta-box">
                    <span class="m-label">攻击分类判定</span>
                    <span class="m-val">{{ detectResult.attack_type }}</span>
                  </div>
                </div>
              </div>
            </div>
          </transition>
        </div>
      </el-col>
    </el-row>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { getAiStats, detectTrafficByAi } from '@/api'
import request from '@/api/request'
import { ElMessage } from 'element-plus'
import { 
  Refresh, Cpu, DataAnalysis, CollectionTag, 
  Odometer, Monitor, Upload as CloudUpload
} from '@element-plus/icons-vue'

const aiStats = ref<any>({})
const uploading = ref(false)
const testForm = ref({ payload: '{\n  "bytes_sent": 50000,\n  "bytes_recv": 100,\n  "packets": 4000,\n  "connection_duration": 0.2,\n  "packet_rate": 20000\n}' })
const detectResult = ref<any>(null)
const uploadForm = ref({
  modelName: `model_v${Math.floor(Date.now() / 1000)}`
})

const fetchAiStats = async () => {
  try { const res = await getAiStats(); aiStats.value = res || {} } catch {}
}

const runDetection = async () => {
  try {
    const data = JSON.parse(testForm.value.payload)
    const res: any = await detectTrafficByAi(data)
    detectResult.value = res
  } catch (e) {
    ElMessage.error('Payload 格式有误，请确保为合法 JSON')
  }
}

const beforeUpload = (file: File) => {
  const isOk = file.name.endsWith('.csv') || file.name.endsWith('.json')
  if (!isOk) return ElMessage.error('仅支持 .csv 或 .json 数据集文件')
  uploading.value = true
  return true
}

const customUpload = async (options: any) => {
  try {
    const formData = new FormData()
    formData.append('file', options.file)
    formData.append('model_name', uploadForm.value.modelName)
    const res: any = await request.post('/ai/upload-dataset', formData, {
      headers: { 'Content-Type': 'multipart/form-data' }
    })
    options.onSuccess(res)
  } catch (err: any) {
    options.onError(err)
  }
}

const handleUploadSuccess = (response: any) => {
  uploading.value = false
  ElMessage.success(response.message || '数据集已上传，后端开始离线训练')
  setTimeout(fetchAiStats, 5000)
}

onMounted(fetchAiStats)
</script>

<style scoped>
.ai-model-wrapper {
  padding: 30px;
  background-color: #f1f5f9;
  min-height: calc(100vh - 60px);
}

/* 头部设计 */
.ai-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 30px;
}
.header-left { display: flex; align-items: center; gap: 20px; }
.header-icon-bg {
  width: 56px; height: 56px; border-radius: 16px;
  background: linear-gradient(135deg, #3b82f6, #1d4ed8);
  display: flex; align-items: center; justify-content: center;
  font-size: 30px; color: white; box-shadow: 0 8px 16px rgba(59, 130, 246, 0.3);
}
.main-title { font-size: 28px; font-weight: 800; color: #1e293b; margin: 0; }
.status-indicator { display: flex; align-items: center; gap: 8px; margin-top: 5px; }
.pulse-dot { width: 8px; height: 8px; border-radius: 50%; }
.pulse-dot.online { background-color: #10b981; animation: pulse-green 2s infinite; }
.pulse-dot.offline { background-color: #f56565; }

@keyframes pulse-green {
  0% { box-shadow: 0 0 0 0px rgba(16, 185, 129, 0.7); }
  70% { box-shadow: 0 0 0 10px rgba(16, 185, 129, 0); }
  100% { box-shadow: 0 0 0 0px rgba(16, 185, 129, 0); }
}

/* 玻璃拟态卡片 */
.glass-card {
  background: white; border-radius: 20px; padding: 25px;
  box-shadow: 0 10px 25px -5px rgba(0,0,0,0.05); border: 1px solid rgba(255,255,255,0.8);
  height: 100%; box-sizing: border-box;
}

.section-title {
  display: flex; align-items: center; gap: 10px;
  font-size: 18px; font-weight: 700; color: #2d3748; margin-bottom: 25px;
}

/* 状态网格 */
.status-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 25px; }
.status-item { background: #f8fafc; padding: 15px; border-radius: 12px; border: 1px solid #edf2f7; }
.label { font-size: 12px; color: #64748b; font-weight: 600; display: block; }
.value { font-size: 16px; font-weight: 700; color: #2d3748; margin-top: 5px; display: block; }
.value.algo { color: #3b82f6; }

/* 计数器 */
.stats-counter { display: flex; gap: 15px; margin-bottom: 30px; }
.counter-box {
  flex: 1; padding: 20px; border-radius: 16px; background: #eff6ff;
  border-bottom: 4px solid #3b82f6;
}
.counter-box.danger { background: #fef2f2; border-bottom-color: #ef4444; }
.counter-label { font-size: 13px; color: #64748b; font-weight: 600; }
.counter-val { font-size: 32px; font-weight: 800; color: #1e293b; display: block; margin-top: 5px; }
.danger .counter-val { color: #ef4444; }

/* 上传区 */
.custom-drag-upload :deep(.el-upload-dragger) {
  border-radius: 14px; background: #f8fafc; border: 2px dashed #cbd5e1;
}
.divider-text { font-size: 12px; color: #94a3b8; font-weight: 600; }
.form-label { font-size: 14px; color: #4a5568; font-weight: 700; margin-bottom: 8px; display: block; }
.upload-tip { font-size: 12px; color: #94a3b8; margin-top: 15px; text-align: center; line-height: 1.5; }

/* 沙盒区编辑器 */
.section-header-flex { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
.editor-container { border-radius: 12px; overflow: hidden; background: #1e1e1e; border: 1px solid #333; }
.editor-header {
  background: #2d2d2d; padding: 10px 15px; display: flex; justify-content: space-between; align-items: center;
}
.editor-header .lang { color: #9cdcfe; font-size: 12px; font-weight: 800; }
.editor-dots { display: flex; gap: 6px; }
.editor-dots span { width: 10px; height: 10px; border-radius: 50%; background: #ff5f56; }
.editor-dots span:nth-child(2) { background: #ffbd2e; }
.editor-dots span:nth-child(3) { background: #27c93f; }

.code-textarea :deep(.el-textarea__inner) {
  background: transparent; color: #d4d4d4; font-family: 'JetBrains Mono', monospace;
  border: none; padding: 20px; font-size: 14px; line-height: 1.6;
}

.sandbox-actions { margin-top: 25px; display: flex; justify-content: flex-end; }
.execute-btn { padding: 25px 40px; font-weight: 800; border-radius: 14px; }
.shadow-primary { box-shadow: 0 8px 20px rgba(59, 130, 246, 0.3); }

/* 结果面板 */
.result-panel { margin-top: 25px; padding: 25px; border-radius: 18px; border-left: 8px solid; }
.result-panel.success { background: #f0fdf4; border-color: #10b981; color: #166534; }
.result-panel.danger { background: #fef2f2; border-color: #ef4444; color: #991b1b; }

.result-header { display: flex; align-items: center; gap: 15px; margin-bottom: 20px; }
.result-icon { font-size: 32px; }
.result-title h3 { margin: 0; font-size: 18px; font-weight: 800; }
.result-title p { margin: 5px 0 0 0; font-size: 13px; opacity: 0.8; }

.res-label { font-size: 14px; font-weight: 700; margin-bottom: 10px; display: block; }
.result-meta { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-top: 25px; }
.meta-box { background: rgba(255,255,255,0.6); padding: 15px; border-radius: 12px; }
.m-label { font-size: 12px; opacity: 0.8; display: block; }
.m-val { font-size: 18px; font-weight: 800; margin-top: 5px; display: block; }

.mt-20 { margin-top: 20px; }
.font-mono { font-family: 'JetBrains Mono', monospace; }
</style>