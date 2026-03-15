import os
import sys
import time
import threading
import logging
import psutil
from pathlib import Path
from dataclasses import dataclass

# 添加项目路径
sys.path.append(str(Path(__file__).parent.parent))

logger = logging.getLogger(__name__)


@dataclass
class SystemMetrics:
    """系统监控指标"""
    timestamp: float
    cpu_percent: float
    memory_percent: float
    memory_used_mb: float
    memory_available_mb: float
    disk_percent: float
    disk_used_gb: float
    network_sent_mb: float
    network_recv_mb: float
    active_connections: int
    thread_count: int


class SystemMonitor:
    """系统监控管理器"""
    
    def __init__(self, db_manager=None, interval_seconds=60):
        """
        初始化系统监控管理器
        
        Args:
            db_manager: 数据库管理器实例
            interval_seconds: 监控间隔（秒）
        """
        self.db_manager = db_manager
        self.interval = interval_seconds
        self.running = False
        self.monitor_thread = None
        self._current_metrics = None
        self._service_status = {}
    
    def start(self):
        """启动系统监控"""
        self.running = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        logger.info("系统监控已启动")
    
    def stop(self):
        """停止系统监控"""
        self.running = False
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=5)
        logger.info("系统监控已停止")
    
    def _monitor_loop(self):
        """监控循环"""
        while self.running:
            try:
                metrics = self._collect_metrics()
                self._current_metrics = metrics
                
                # 保存到数据库
                if self.db_manager and hasattr(self.db_manager, 'save_system_metrics'):
                    try:
                        metrics_dict = {
                            'timestamp': metrics.timestamp,
                            'cpu_percent': metrics.cpu_percent,
                            'memory_percent': metrics.memory_percent,
                            'memory_used_mb': metrics.memory_used_mb,
                            'memory_available_mb': metrics.memory_available_mb,
                            'disk_percent': metrics.disk_percent,
                            'disk_used_gb': metrics.disk_used_gb,
                            'network_sent_mb': metrics.network_sent_mb,
                            'network_recv_mb': metrics.network_recv_mb,
                            'active_connections': metrics.active_connections,
                            'thread_count': metrics.thread_count
                        }
                        self.db_manager.save_system_metrics(metrics_dict)
                    except Exception as e:
                        logger.error(f"保存系统监控指标失败: {e}")
            except Exception as e:
                logger.error(f"执行系统监控时出错: {e}")
            
            # 等待下一次监控
            for _ in range(self.interval):
                if not self.running:
                    break
                time.sleep(1)
    
    def _collect_metrics(self):
        """收集系统指标"""
        timestamp = time.time()
        
        # 收集CPU使用率
        cpu_percent = psutil.cpu_percent(interval=0.1)
        
        # 收集内存使用率
        memory = psutil.virtual_memory()
        memory_percent = memory.percent
        memory_used_mb = memory.used / (1024 * 1024)
        memory_available_mb = memory.available / (1024 * 1024)
        
        # 收集磁盘使用率
        disk = psutil.disk_usage('/')
        disk_percent = disk.percent
        disk_used_gb = disk.used / (1024 * 1024 * 1024)
        
        # 检查磁盘空间并生成告警
        if disk_percent > 85:
            self._generate_disk_alert(disk_percent, disk_used_gb)
        
        # 收集网络流量
        network = psutil.net_io_counters()
        network_sent_mb = network.bytes_sent / (1024 * 1024)
        network_recv_mb = network.bytes_recv / (1024 * 1024)
        
        # 收集活动连接数
        active_connections = 0
        try:
            connections = psutil.net_connections()
            active_connections = len([c for c in connections if c.status == 'ESTABLISHED'])
        except Exception:
            pass
        
        # 收集线程数
        thread_count = threading.active_count()
        
        return SystemMetrics(
            timestamp=timestamp,
            cpu_percent=cpu_percent,
            memory_percent=memory_percent,
            memory_used_mb=memory_used_mb,
            memory_available_mb=memory_available_mb,
            disk_percent=disk_percent,
            disk_used_gb=disk_used_gb,
            network_sent_mb=network_sent_mb,
            network_recv_mb=network_recv_mb,
            active_connections=active_connections,
            thread_count=thread_count
        )
    
    def _generate_disk_alert(self, disk_percent, disk_used_gb):
        """生成磁盘空间告警"""
        if not self.db_manager or not hasattr(self.db_manager, 'insert_alert'):
            return
        
        try:
            from database.models import Alert
            
            # 检查是否已经存在未处理的磁盘告警
            if hasattr(self.db_manager, 'get_alerts'):
                alerts = self.db_manager.get_alerts(type='磁盘空间告警', status='未处理', limit=1)
                if alerts:
                    return  # 已有未处理的告警，不再重复生成
            
            alert = Alert(
                timestamp=time.time(),
                level='高',
                type='磁盘空间告警',
                description=f'磁盘空间使用率过高: {disk_percent:.1f}%, 已使用 {disk_used_gb:.1f}GB',
                status='未处理',
                vulnerability_type='系统资源异常'
            )
            self.db_manager.insert_alert(alert)
            logger.warning(f'生成磁盘空间告警: {disk_percent:.1f}%')
        except Exception as e:
            logger.error(f'生成磁盘告警失败: {e}')
    
    def get_current_metrics(self):
        """获取当前系统指标"""
        return self._current_metrics
    
    def update_service_status(self, service_name, status, error_count=0):
        """更新服务状态"""
        self._service_status[service_name] = {
            'status': 'running' if status else 'stopped',
            'error_count': error_count,
            'last_update': time.time()
        }
    
    def get_service_status(self, service_name):
        """获取服务状态"""
        return self._service_status.get(service_name, {'status': 'unknown', 'error_count': 0, 'last_update': 0})
    
    def get_all_service_status(self):
        """获取所有服务状态"""
        return self._service_status