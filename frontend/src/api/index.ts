// src/api/index.ts
import request from './request'

// Auth
export const login = (data: any) => request.post('/auth/login', data)
export const changePassword = (data: any) => request.post('/auth/change-password', data)

// Dashboard / Status / Monitor
export const getSystemStatus = () => request.get('/status')
export const getStatsSummary = () => request.get('/stats/summary')
export const getMonitorSummary = () => request.get('/monitor/summary')
export const getServicesStatus = () => request.get('/monitor/services') 

// Traffic (新增：获取流量日志明细接口)
export const getTrafficStats = () => request.get('/traffic/stats', { params: { _t: Date.now() } })
export const getTrafficAnalysis = (hours: number = 24) => request.get(`/traffic/analysis?hours=${hours}&_t=${Date.now()}`)
export const getTrafficLogs = (params: any): Promise<any> => {
  const newParams = { ...params, _t: Date.now() };
  return request.get('/traffic', { params: newParams }) as Promise<any>;
} // <--- 关键补充

// Defense
export const getDefenseStatus = () => request.get('/defense/status') 
export const getBlockedIps = () => request.get('/defense/blocked') 
export const blockIp = (data: any) => request.post('/defense/block', data) 
export const unblockIp = (data: any) => request.post('/defense/unblock', data) 

export const getWhitelist = () => request.get('/defense/whitelist') 
export const addWhitelist = (data: any) => request.post('/defense/whitelist', data) 
export const removeWhitelist = (data: any) => request.delete('/defense/whitelist', { data }) 

export const getDefenseHistory = (params: any) => request.get('/defense/history', { params }) 

// Alert
export const getAlerts = (params: any) => request.get('/alerts', { params })
export const updateAlertStatus = (id: number, status: string) => request.put(`/alerts/${id}`, { status })
export const clearAllAlerts = () => request.delete('/monitor/alerts')

// AI
export const getAiStats = () => request.get('/ai/stats')
export const trainAiModel = (data: any) => request.post('/ai/train', data)
export const detectTrafficByAi = (data: any) => request.post('/ai/detect', data)

// Defense Config
export const getDefenseConfig = () => request.get('/defense/config')
export const updateDefenseConfig = (data: any) => request.put('/defense/config', data)
export const getCleanupConfig = () => request.get('/cleanup/config')
export const updateCleanupConfig = (data: any) => request.put('/cleanup/config', data)
export const manualDataCleanup = () => request.post('/cleanup')

// 兼容旧版的黑名单API
export const getBlacklist = () => request.get('/blacklist')
export const addBlacklist = (data: any) => request.post('/blacklist', data)
export const removeBlacklist = (ip: string) => request.delete(`/blacklist/${ip}`)