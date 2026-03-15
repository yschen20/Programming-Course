# 基于AI的校园网异常检测与防御平台

## 项目概述

本项目是一个基于AI的校园网异常检测与防御平台，旨在实时监控网络流量，检测异常行为，并自动采取防御措施，保障校园网络安全。

## 系统架构

### 1. 整体架构

系统采用分层架构设计，包含以下层次：

```
┌───────────────────────┐
│      前端展示层        │
│  (Vue 3 + TypeScript) │
├───────────────────────┤
│      后端API层        │
│  (Flask + RESTful API)│
├───────────────────────┤
│      业务逻辑层       │
│  (API服务器 + 守护进程)│
├───────────────────────┤
│      数据处理层       │
│  (AI检测 + 特征提取)  │
├───────────────────────┤
│      数据采集层       │
│  (网络抓包 + 流量分析) │
├───────────────────────┤
│      数据存储层       │
│  (SQLite数据库)       │
└───────────────────────┘
```

### 2. 核心模块

- **前端应用**：基于Vue 3 + TypeScript的现代化前端界面，提供直观的监控和管理功能
- **API服务器**：提供RESTful API接口，处理前端请求，实现无状态设计
- **守护进程**：后台运行的核心服务，负责实时监控和防御
- **网络捕获**：基于Scapy实现的网络数据包捕获和分析
- **AI检测**：基于机器学习的异常行为检测，支持多种算法
- **防御管理**：实现IP拦截和安全策略管理，与系统防火墙集成
- **数据库管理**：处理数据存储和查询，支持线程安全
- **配置管理**：管理系统配置和热更新
- **监控模块**：监控系统状态和资源使用，包括数据清理和系统监控

### 3. 数据流

1. **数据采集**：网络捕获模块实时采集网络数据包
2. **特征提取**：提取数据包的关键特征
3. **AI检测**：将特征输入AI模型进行异常检测
4. **防御处理**：根据检测结果采取防御措施
5. **数据存储**：将流量数据和告警信息存入数据库
6. **API响应**：通过API接口提供数据查询和管理功能
7. **前端展示**：前端应用展示监控数据和提供管理界面

## 技术栈

- **后端**：Python 3.8+、Flask、SQLite
- **网络库**：Scapy、psutil
- **AI框架**：scikit-learn
- **安全**：JWT、iptables/netsh
- **工具**：threading、queue、logging
- **前端**：Vue 3、TypeScript、Element Plus、Vue Router、Pinia
- **数据可视化**：ECharts、Vue-ECharts
- **构建工具**：Vite

## 目录结构

```
├── backend/                # 后端代码
│   ├── __init__.py         # 模块导出
│   ├── api_server.py       # API服务器
│   ├── daemon.py           # 守护进程
│   ├── config/             # 配置管理
│   │   └── __init__.py
│   ├── database/           # 数据库管理
│   │   ├── db_manager.py   # 数据库管理器
│   │   └── models.py       # 数据模型
│   ├── ai/                 # AI检测
│   │   └── ai_detector.py  # AI检测器
│   ├── capture/            # 网络捕获
│   │   └── capture.py      # 网络数据包捕获和分析
│   ├── defense/            # 防御管理
│   │   └── __init__.py     # 防御管理器
│   ├── monitor/            # 系统监控
│   │   ├── __init__.py     # 监控模块初始化
│   │   ├── data_cleanup.py # 数据清理管理器
│   │   └── system_monitor.py # 系统监控管理器
│   ├── data/               # 数据存储
│   └── requirements.txt    # 依赖管理
├── frontend/               # 前端代码
│   ├── public/             # 静态资源
│   ├── src/                # 源代码
│   │   ├── api/            # API请求
│   │   ├── layout/         # 布局组件
│   │   ├── router/         # 路由配置
│   │   ├── store/          # 状态管理
│   │   ├── views/          # 页面组件
│   │   ├── App.vue         # 根组件
│   │   ├── main.ts         # 入口文件
│   │   └── env.d.ts        # 类型声明
│   ├── index.html          # HTML模板
│   ├── package.json        # 前端依赖
│   ├── tsconfig.json       # TypeScript配置
│   ├── tsconfig.node.json  # Node.js TypeScript配置
│   └── vite.config.ts      # Vite配置
└── README.md               # 项目说明
```

## 核心功能

### 1. 网络流量采集与特征提取
- 实时捕获网络数据包
- 解析TCP/UDP/ICMP/HTTP等协议
- 提取流量特征（IP、端口、包长、时间戳等）
- 统计流量数据（带宽、连接数、包量）

### 2. AI异常行为检测
- 基于孤立森林算法的异常检测
- 实时异常评分和攻击类型判定
- 支持模型热更新
- 批量检测提高性能
- 攻击类型分类（DDoS、端口扫描、SQL注入等）

### 3. 智能拦截与访问控制
- 基于IP的自动拦截
- 支持白名单和黑名单管理
- 与系统防火墙集成（iptables/netsh）
- 拦截记录和统计
- 自动封禁/解封机制

### 4. 安全日志审计
- 流量日志和告警记录
- 支持日志查询和导出
- 数据库存储保证数据完整性
- 拦截操作记录

### 5. 系统监控
- 资源使用监控（CPU、内存、磁盘）
- 系统状态监控
- 数据清理和维护
- 服务状态管理

### 6. 配置管理
- 支持配置文件热更新
- 配置备份和恢复
- 环境变量支持
- 配置验证

### 7. 前端界面
- 监控大盘：实时展示系统状态和关键指标
- 流量分析：展示网络流量趋势和异常检测结果
- 安全防御：管理IP拦截和白名单
- 告警管理：查看和处理系统告警
- AI模型管理：查看AI模型状态和性能
- 系统设置：管理系统配置和用户信息

## 部署说明

### 1. 后端部署

#### 1.1 依赖安装

```bash
# 进入项目根目录
cd 基于AI的校园网异常检测与防御平台

# 安装后端依赖
pip install -r backend/requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
```

#### 1.2 启动后端服务

```bash
# 启动API服务器
python backend/api_server.py

# 启动守护进程（新终端）
python backend/daemon.py
```

### 2. 前端部署

#### 2.1 依赖安装

```bash
# 进入前端目录
cd frontend

# 安装前端依赖
npm install
```

#### 2.2 开发环境运行

```bash
# 启动前端开发服务器
npm run dev
```

#### 2.3 生产环境构建

```bash
# 构建前端项目
npm run build

# 预览构建结果
npm run preview
```

## 运行说明

### 1. 完整运行流程

1. **启动后端服务**：
   - 首先启动守护进程（负责实时监控和防御）
   - 然后启动API服务器（负责处理前端请求）

2. **启动前端应用**：
   - 启动前端开发服务器或部署构建结果

3. **访问系统**：
   - 前端地址：默认 http://localhost:3000
   - 后端API地址：默认 http://localhost:5000/api

### 2. 开发环境运行

**步骤1：启动守护进程**
```bash
# 终端1
python backend/daemon.py
```

**步骤2：启动API服务器**
```bash
# 终端2
python backend/api_server.py
```

**步骤3：启动前端开发服务器**
```bash
# 终端3
cd frontend
npm run dev
```

**步骤4：访问系统**
- 打开浏览器访问 http://localhost:3000
- 默认登录信息：
   - 用户名：admin
   - 密码：admin123

### 3. 生产环境部署

**后端部署**：
- 使用Gunicorn等WSGI服务器部署API服务
- 配置守护进程为系统服务

**前端部署**：
- 构建前端项目：`npm run build`
- 将构建产物部署到Nginx或其他静态文件服务器
- 配置反向代理指向后端API

## 配置说明

### 1. 后端配置
- 配置文件：`backend/data/config.json`
- 环境变量：`CONFIG_PATH` 可指定配置文件路径
- JWT密钥：首次启动自动生成，存储在 `backend/data/.jwt_secret`

### 2. 前端配置
- API基础路径：在 `frontend/src/api/request.ts` 中配置
- 开发服务器配置：在 `frontend/vite.config.ts` 中配置

## 安全特性

- JWT身份验证
- 随机生成密钥，避免硬编码
- 日志轮转，防止日志文件过大
- 异常处理和错误日志
- 输入验证和安全检查
- 模型签名验证，防止模型被篡改

## 性能优化

- 多线程并行处理
- 批量操作减少数据库压力
- LRU缓存减少内存使用
- 队列机制平衡处理负载
- 异步写入提高吞吐量
- 特征提取优化
- 前端代码分割和懒加载
- 图表渲染优化

## API接口

### 系统状态
- `GET /api/status` - 获取系统运行状态
- `GET /api/stats/summary` - 获取统计汇总

### 流量数据
- `GET /api/traffic` - 获取流量日志
- `GET /api/traffic/stats` - 获取流量统计信息
- `GET /api/traffic/analysis` - 获取流量分析结果

### 告警管理
- `GET /api/alerts` - 获取告警列表
- `PUT /api/alerts/<id>` - 更新告警状态

### 黑名单管理
- `GET /api/blacklist` - 获取黑名单列表
- `POST /api/blacklist` - 添加IP到黑名单
- `DELETE /api/blacklist/<ip>` - 从黑名单移除IP

### 防御管理
- `GET /api/defense/status` - 获取防御状态
- `GET /api/defense/blocked` - 获取被拦截的IP列表
- `POST /api/defense/block` - 手动拦截IP
- `POST /api/defense/unblock` - 手动解除IP拦截
- `GET /api/defense/whitelist` - 获取白名单
- `POST /api/defense/whitelist` - 添加IP到白名单
- `DELETE /api/defense/whitelist` - 从白名单移除IP
- `GET /api/defense/config` - 获取防御配置
- `PUT /api/defense/config` - 更新防御配置
- `GET /api/defense/history` - 获取拦截历史

### AI检测
- `POST /api/ai/detect` - 使用AI检测流量
- `POST /api/ai/train` - 训练AI模型
- `GET /api/ai/stats` - 获取AI模型统计信息

### 用户认证
- `POST /api/auth/login` - 用户登录
- `POST /api/auth/change-password` - 修改密码

### 系统监控
- `GET /api/monitor/metrics` - 获取系统监控指标
- `GET /api/monitor/summary` - 获取监控摘要
- `GET /api/monitor/services` - 获取服务状态
- `GET /api/monitor/alerts` - 获取监控告警
- `DELETE /api/monitor/alerts` - 清除监控告警

### 数据清理
- `POST /api/cleanup` - 手动执行数据清理

### 配置管理
- `GET /api/config` - 获取配置
- `PUT /api/config` - 更新配置
- `GET /api/config/section/<section>` - 获取指定配置节

## 系统运行状态

### 后端服务
- API服务器：默认运行在 http://127.0.0.1:5000
- 守护进程：后台运行，处理网络抓包、AI检测和防御任务

### 前端应用
- 开发环境：默认运行在 http://localhost:3000
- 生产环境：部署后根据服务器配置访问

## 日志管理

- API服务器日志：`backend/data/api.log`
- 守护进程日志：`backend/data/daemon.log`
- AI检测日志：`backend/data/ai.log`
- 数据库日志：`backend/data/database.log`

## 注意事项

- 确保系统有足够的权限运行网络抓包功能
- 首次运行时，系统会自动创建数据库和必要的表结构
- 守护进程需要持续运行以实现实时监控和防御功能
- 生产环境建议使用Gunicorn等WSGI服务器部署API服务
- 定期备份数据库和配置文件
- 前端开发环境需要Node.js 16+版本
- 构建前端项目时需要确保网络连接正常，以便下载依赖

## 技术亮点

1. **实时异常检测**：基于机器学习的实时异常检测，能够快速识别各种网络攻击
2. **智能防御**：自动识别并拦截恶意流量，支持白名单和黑名单管理
3. **系统监控**：全面的系统资源监控和数据清理功能
4. **安全认证**：基于JWT的身份验证机制，确保API访问安全
5. **现代化前端**：基于Vue 3 + TypeScript的现代化前端界面，提供直观的监控和管理功能
6. **数据可视化**：使用ECharts实现丰富的数据可视化效果
7. **可扩展性**：模块化设计，易于添加新的检测算法和功能模块
8. **性能优化**：多线程处理、批量操作和缓存机制，提高系统性能
9. **配置灵活**：支持配置文件热更新和环境变量配置
10. **跨平台兼容**：支持Windows和Linux系统
