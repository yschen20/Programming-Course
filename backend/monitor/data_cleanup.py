import os
import sys
import time
import threading
import logging
from pathlib import Path

# 添加项目路径
sys.path.append(str(Path(__file__).parent.parent))

logger = logging.getLogger(__name__)


class DataCleanupManager:
    """数据清理管理器"""
    
    def __init__(self, db_manager=None, interval_hours=24, retention_days=30):
        """
        初始化数据清理管理器
        
        Args:
            db_manager: 数据库管理器实例
            interval_hours: 清理间隔（小时）
            retention_days: 数据保留天数
        """
        self.db_manager = db_manager
        self.interval = interval_hours * 3600  # 转换为秒
        self.retention_days = retention_days
        self.running = False
        self.cleanup_thread = None
        self.config = {
            'enabled': True,
            'interval_hours': interval_hours,
            'retention_days': retention_days
        }
    
    def start(self):
        """启动数据清理管理器"""
        self.running = True
        self.cleanup_thread = threading.Thread(target=self._cleanup_loop)
        self.cleanup_thread.daemon = True
        self.cleanup_thread.start()
        logger.info("数据清理管理器已启动")
    
    def stop(self):
        """停止数据清理管理器"""
        self.running = False
        if self.cleanup_thread and self.cleanup_thread.is_alive():
            self.cleanup_thread.join(timeout=5)
        logger.info("数据清理管理器已停止")
    
    def _cleanup_loop(self):
        """清理循环"""
        while self.running:
            try:
                self._perform_cleanup()
            except Exception as e:
                logger.error(f"执行数据清理时出错: {e}")
            
            # 等待下一次清理
            for _ in range(self.interval):
                if not self.running:
                    break
                time.sleep(1)
    
    def _perform_cleanup(self):
        """执行数据清理"""
        if not self.config['enabled']:
            return
        
        try:
            logger.info(f"开始执行数据清理，保留 {self.retention_days} 天的数据")
            
            # 调用数据库管理器的清理方法
            if self.db_manager and hasattr(self.db_manager, 'cleanup_old_data'):
                result = self.db_manager.cleanup_old_data(retention_days=self.retention_days)
                logger.info(f"数据清理完成: {result}")
            else:
                logger.warning("数据库管理器没有 cleanup_old_data 方法")
            
            # 清理临时文件
            self._cleanup_temp_files()
        except Exception as e:
            logger.error(f"执行数据清理时出错: {e}")
    
    def _cleanup_temp_files(self):
        """清理临时文件"""
        try:
            # 清理模型目录中过时的模型文件
            model_dir = Path(__file__).parent.parent / 'data' / 'models'
            if model_dir.exists():
                model_files = list(model_dir.glob('*.joblib'))
                if len(model_files) > 3:
                    # 按修改时间排序，保留最新的3个模型文件
                    model_files.sort(key=lambda f: f.stat().st_mtime, reverse=True)
                    for file in model_files[3:]:
                        file.unlink()
                        logger.info(f"清理过时的模型文件: {file.name}")
            
            # 清理日志文件（如果超过大小限制）
            log_dir = Path(__file__).parent.parent / 'data'
            if log_dir.exists():
                for log_file in log_dir.glob('*.log'):
                    if log_file.stat().st_size > 50 * 1024 * 1024:  # 50MB
                        log_file.unlink()
                        logger.info(f"清理过大的日志文件: {log_file.name}")
        except Exception as e:
            logger.error(f"清理临时文件时出错: {e}")
    
    def get_stats(self):
        """获取清理统计信息"""
        return {
            'enabled': self.config['enabled'],
            'interval_hours': self.config['interval_hours'],
            'retention_days': self.retention_days
        }
    
    def update_config(self, config):
        """更新配置"""
        if 'enabled' in config:
            self.config['enabled'] = config['enabled']
        if 'interval_hours' in config:
            self.config['interval_hours'] = config['interval_hours']
            self.interval = config['interval_hours'] * 3600
        if 'retention_days' in config:
            self.retention_days = config['retention_days']
        logger.info("数据清理配置已更新")