<template>
  <div class="traffic-audit-page">
    <!-- 筛选栏：时间+IP+流量类型+导出 -->
    <div class="filter-bar">
      <el-row :gutter="20" align="middle">
        <el-col :xs="24" :sm="12" :md="6">
          <el-date-picker
            v-model="dateRange"
            type="datetimerange"
            range-separator="至"
            start-placeholder="开始时间"
            end-placeholder="结束时间"
            format="YYYY-MM-DD HH:mm:ss"
            value-format="YYYY-MM-DD HH:mm:ss"
            style="width: 100%;"
          />
        </el-col>
        <el-col :xs="24" :sm="12" :md="5">
          <el-input
            v-model="filterIp"
            placeholder="请输入IP地址筛选"
            clearable
            style="width: 100%;"
          />
        </el-col>
        <el-col :xs="24" :sm="12" :md="5">
          <el-select
            v-model="filterType"
            placeholder="流量类型筛选"
            clearable
            style="width: 100%;"
          >
            <el-option label="全部" value="" />
            <el-option label="正常流量" value="normal" />
            <el-option label="异常流量" value="abnormal" />
            <el-option label="拦截流量" value="blocked" />
          </el-select>
        </el-col>
        <el-col :xs="12" :sm="6" :md="4">
          <el-button type="primary" @click="handleFilter" style="margin-right: 8px;">查询</el-button>
          <el-button @click="resetFilter">重置</el-button>
        </el-col>
        <el-col :xs="12" :sm="6" :md="4">
          <el-button type="success" @click="exportData" icon="el-icon-download" >导出数据</el-button>
        </el-col>
      </el-row>
    </div>

    <!-- 流量表格：异常行高亮+状态标签 -->
    <el-table
      v-loading="loading"
      :data="tableData"
      border
      stripe
      :row-class-name="tableRowClassName"
      style="width: 100%; margin-bottom: 20px;"
    >
      <el-table-column prop="id" label="序号" width="80" align="center" />
      <el-table-column prop="ip" label="源IP地址" min-width="120" />
      <el-table-column prop="targetIp" label="目标IP" min-width="120" />
      <el-table-column prop="flowSize" label="流量大小" width="100" />
      <el-table-column prop="protocol" label="协议类型" width="100" />
      <el-table-column prop="status" label="流量状态" width="100">
        <template #default="scope">
          <el-tag 
            :type="scope.row.status === '异常' ? 'danger' : scope.row.status === '拦截' ? 'warning' : 'success'"
            size="small"
          >
            {{ scope.row.status }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column prop="time" label="访问时间" min-width="180" />
      <el-table-column prop="remark" label="备注" min-width="150" />
      <el-table-column label="操作" width="120" align="center">
        <template #default="scope">
          <el-button type="text" @click="viewDetail(scope.row)">详情</el-button>
          <el-button type="danger" link @click="blockIp(scope.row)">封禁</el-button>
        </template>
      </el-table-column>
    </el-table>

    <!-- 分页组件 -->
    <el-pagination
      @size-change="handleSizeChange"
      @current-change="handleCurrentChange"
      :current-page="currentPage"
      :page-sizes="[10, 20, 50, 100]"
      :page-size="pageSize"
      layout="total, sizes, prev, pager, next, jumper"
      :total="total"
      style="text-align: right;"
    />
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { ElMessage, ElMessageBox } from 'element-plus';
import { getTrafficLogs } from '@/api';

// 加载状态
const loading = ref(false);
// 筛选条件
const dateRange = ref<string[]>([]); // 时间范围
const filterIp = ref(''); // IP筛选
const filterType = ref(''); // 流量类型筛选
// 分页参数
const currentPage = ref(1);
const pageSize = ref(20);
const total = ref(0);
// 表格数据
const tableData = ref<any[]>([]);

// 过滤后的数据（根据筛选条件动态计算）
const filteredData = computed(() => {
  return tableData.value;
});

// 页面初始化加载数据
onMounted(() => {
  fetchTrafficData();
});

// 从后端获取流量数据
const fetchTrafficData = async () => {
  loading.value = true;
  try {
    console.log('开始获取流量数据...');
    // 构建请求参数
    const params = {
      limit: pageSize.value,
      offset: (currentPage.value - 1) * pageSize.value,
      src_ip: filterIp.value || undefined,
      // 时间范围参数
      start_time: dateRange.value.length === 2 ? dateRange.value[0] : undefined,
      end_time: dateRange.value.length === 2 ? dateRange.value[1] : undefined,
      // 流量类型参数
      status: filterType.value || undefined
    };
    console.log('请求参数：', params);
    
    const data = await getTrafficLogs(params);
    console.log('API 响应：', data);
    
    // 检查响应结构是否正确
    if (data && Array.isArray(data.logs)) {
      console.log('logs 数据：', data.logs);
      console.log('total 数据：', data.total);
      tableData.value = data.logs.map((log: any) => ({
        id: log.id,
        ip: log.src_ip,
        targetIp: log.dst_ip,
        flowSize: `${log.length} bytes`,
        protocol: log.protocol,
        status: log.is_anomaly ? '异常' : '正常',
        time: new Date(log.timestamp * 1000).toLocaleString(),
        remark: ''
      }));
      
      // 检查 total 字段是否存在
      if (typeof data.total === 'number') {
        total.value = data.total;
      } else {
        total.value = data.logs.length;
        console.warn('后端未返回 total 字段，使用 logs 长度作为替代');
      }
    } else {
      // 响应结构不正确，使用空数据
      tableData.value = [];
      total.value = 0;
      ElMessage.warning('获取的流量数据格式不正确');
      console.warn('响应结构不正确：', data);
    }
  } catch (error) {
    ElMessage.error('获取流量数据失败，请重试');
    console.error('获取流量数据失败：', error);
    // 发生错误时清空数据
    tableData.value = [];
    total.value = 0;
  } finally {
    loading.value = false;
  }
};

// 处理筛选查询
const handleFilter = () => {
  currentPage.value = 1; // 筛选后重置页码到第一页
  fetchTrafficData();
};

// 重置筛选条件
const resetFilter = () => {
  dateRange.value = [];
  filterIp.value = '';
  filterType.value = '';
  handleFilter(); // 重置后重新查询
};

// 表格行样式：异常/拦截行高亮
const tableRowClassName = ({ row }: { row: any }) => {
  if (row.status === '异常') return 'abnormal-row';
  if (row.status === '拦截') return 'blocked-row';
  return '';
};

// 导出数据为CSV
const exportData = () => {
  loading.value = true;
  setTimeout(() => {
    try {
      // 格式化导出数据（更友好的列名）
      const exportData = filteredData.value.map(item => ({
        '序号': item.id,
        '源IP地址': item.ip,
        '目标IP地址': item.targetIp,
        '流量大小': item.flowSize,
        '协议类型': item.protocol,
        '流量状态': item.status,
        '访问时间': item.time,
        '备注信息': item.remark || '无'
      }));
      
      // 检查是否有数据可导出
      if (exportData.length === 0) {
        ElMessage.warning('没有数据可导出');
        loading.value = false;
        return;
      }
      
      // 创建CSV内容
      const headers = Object.keys(exportData[0]);
      const csvContent = [
        headers.join(','),
        ...exportData.map(row => headers.map(header => {
          const value = row[header as keyof typeof row];
          // 处理包含逗号或引号的值
          return typeof value === 'string' && (value.includes(',') || value.includes('"'))
            ? `"${value.replace(/"/g, '""')}"`
            : value;
        }).join(','))
      ].join('\n');
      
      // 创建Blob并下载
      const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
      const link = document.createElement('a');
      const url = URL.createObjectURL(blob);
      link.setAttribute('href', url);
      link.setAttribute('download', `校园网流量审计_${new Date().toLocaleDateString().replace(/\//g, '-')}.csv`);
      link.style.visibility = 'hidden';
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      
      ElMessage.success('数据导出成功！文件已下载');
    } catch (error) {
      ElMessage.error('数据导出失败，请重试');
      console.error('导出失败：', error);
    } finally {
      loading.value = false;
    }
  }, 600);
};

// 分页：每页条数变化
const handleSizeChange = (val: number) => {
  pageSize.value = val;
  currentPage.value = 1; // 切换每页条数后重置到第一页
  fetchTrafficData();
};

// 分页：页码变化
const handleCurrentChange = (val: number) => {
  currentPage.value = val;
  fetchTrafficData();
};

// 查看流量详情（示例）
const viewDetail = (row: any) => {
  ElMessageBox.alert(`
    <div style="text-align: left;">
      <p><strong>源IP：</strong>${row.ip}</p>
      <p><strong>目标IP：</strong>${row.targetIp}</p>
      <p><strong>流量大小：</strong>${row.flowSize}</p>
      <p><strong>协议类型：</strong>${row.protocol}</p>
      <p><strong>状态：</strong>${row.status}</p>
      <p><strong>访问时间：</strong>${row.time}</p>
      <p><strong>备注：</strong>${row.remark || '无'}</p>
    </div>
  `, `流量详情 - ID: ${row.id}`, {
    dangerouslyUseHTMLString: true,
    confirmButtonText: '关闭'
  });
};

// 封禁IP（示例）
const blockIp = (row: any) => {
  ElMessageBox.confirm(
    `确定要封禁IP ${row.ip} 吗？封禁后该IP将无法访问校园网`,
    '警告',
    {
      confirmButtonText: '确定',
      cancelButtonText: '取消',
      type: 'warning'
    }
  ).then(() => {
    ElMessage.success(`IP ${row.ip} 已封禁`);
    // 真实场景：调用后端封禁接口
  }).catch(() => {
    ElMessage.info('已取消封禁操作');
  });
};
</script>

<style scoped>
/* 页面整体样式 */
.traffic-audit-page {
  padding: 20px;
  background: #f5f7fa;
  min-height: calc(100vh - 120px);
}

/* 筛选栏样式 */
.filter-bar {
  background: #ffffff;
  padding: 16px;
  border-radius: 8px;
  box-shadow: 0 2px 12px rgba(0, 0, 0, 0.06);
  margin-bottom: 20px;
}

/* 异常行高亮样式 */
.el-table .abnormal-row {
  background-color: rgba(255, 77, 79, 0.05) !important;
}
.el-table .blocked-row {
  background-color: rgba(230, 162, 60, 0.05) !important;
}

/* 表格样式优化 */
.el-table {
  --el-table-header-text-color: #333;
  --el-table-row-hover-bg-color: #f8f9fa;
}
</style>