"""
==================================================
校园网异常检测平台 - 守护进程 (最优完整版)
修复说明：
1. 手动指定 WLAN 网卡，适配 Windows 环境。
2. 修复字典属性访问导致崩溃的致命Bug。
3. 补全完整的命令队列处理 (AI训练、手动拦截、解封、白名单、配置重载)。
4. 补全完整的系统监控与抓包状态同步 (前端大屏数据源)。
==================================================
"""

import os
import sys
import time
import signal
import logging
import json
import threading
from pathlib import Path
from datetime import datetime
from logging.handlers import RotatingFileHandler

# 添加项目路径
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

# 配置日志
log_dir = project_root / 'data'
log_dir.mkdir(parents=True, exist_ok=True)
log_path = log_dir / 'daemon.log'

file_handler = RotatingFileHandler(log_path, maxBytes=10 * 1024 * 1024, backupCount=5, encoding='utf-8')
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logger.addHandler(file_handler)

class DaemonManager:
    def __init__(self):
        self.running = False
        self.db = None
        self.capture = None
        self.ai_detector = None
        self.defense_manager = None
        self.data_cleanup = None
        self.system_monitor = None
    
    def initialize(self):
        logger.info("=" * 60)
        logger.info("正在初始化守护进程...")
        
        # 1. 数据库
        from database.db_manager import DatabaseManager
        self.db = DatabaseManager()
        logger.info("数据库初始化完成")
        
        # 2. AI检测器
        try:
            from ai.ai_detector import AIDetector
            self.ai_detector = AIDetector()
            logger.info("AI检测器初始化完成")
        except Exception as e:
            logger.warning(f"AI检测器初始化失败: {e}")
            self.ai_detector = None
        
        # 3. 防御管理器
        try:
            from defense import DefenseManager
            self.defense_manager = DefenseManager(self.db, capture=None)
            self.defense_manager.start()
            logger.info("防御管理器初始化完成")
        except Exception as e:
            logger.error(f"防御管理器初始化失败: {e}")
        
        # 4. 数据清理
        try:
            from monitor import DataCleanupManager
            self.data_cleanup = DataCleanupManager(self.db)
            self.data_cleanup.start()
            logger.info("数据清理管理器初始化完成")
        except Exception as e:
            logger.error(f"数据清理管理器初始化失败: {e}")

        # 5. 系统监控
        try:
            from monitor import SystemMonitor
            self.system_monitor = SystemMonitor(db_manager=self.db)
            self.system_monitor.start()
            logger.info("系统监控初始化完成")
        except Exception as e:
            logger.error(f"系统监控初始化失败: {e}")

        # 6. 【核心修复】：初始化抓包，手动指定 WLAN
        try:
            from capture.capture import NetworkCapture
            
            selected_interface = 'WLAN' 
            
            logger.info(f"已手动锁定网络接口: {selected_interface}")
            
            self.capture = NetworkCapture(
                interface=selected_interface,
                filter='',
                db_manager=self.db,
                ai_detector=self.ai_detector,
                defense_manager=self.defense_manager
            )
            self.capture.start_capture()
            
            if self.system_monitor:
                self.system_monitor.update_service_status('抓包服务', True)
            if self.defense_manager:
                self.defense_manager.capture = self.capture
            logger.info("网络抓包服务启动成功")
        except Exception as e:
            logger.error(f"网络抓包服务启动失败: {e}")
            self.capture = None
        
        logger.info("=" * 60)

    def run(self):
        self.running = True
        while self.running:
            try:
                if self.db:
                    self._sync_system_state()
                self._process_commands()
                time.sleep(10)
            except KeyboardInterrupt:
                break
            except Exception as e:
                logger.error(f"主循环异常: {e}")
                time.sleep(5)
        self.stop()
        
    def _sync_system_state(self):
        """同步状态到数据库，确保前端Dashboard有数据"""
        try:
            daemon_status = {
                'running': self.running,
                'services': {
                    'capture': self.capture.running if self.capture else False,
                    'ai': self.ai_detector is not None,
                    'defense': self.defense_manager is not None,
                    'cleanup': self.data_cleanup is not None
                }
            }
            self.db.save_system_status('daemon', 'running', json.dumps(daemon_status))
            
            if self.capture:
                stats = self.capture.get_stats()
                self.db.save_system_status('capture', 'running', json.dumps(stats))
                
            if self.defense_manager:
                defense_status = {
                    'enabled': self.defense_manager.config.enabled,
                    'auto_block': self.defense_manager.config.auto_block,
                    'current_blocked': len(self.defense_manager.blocked_ips),
                    'whitelist_count': len(self.defense_manager.config.ip_whitelist)
                }
                self.db.save_system_status('defense', 'enabled' if self.defense_manager.config.enabled else 'disabled', json.dumps(defense_status))
                
            if self.system_monitor:
                metrics = self.system_monitor.get_current_metrics()
                if metrics:
                    self.db.save_system_metrics({
                        'timestamp': time.time(),
                        'cpu_percent': metrics.cpu_percent,
                        'memory_percent': metrics.memory_percent,
                        'memory_used_mb': metrics.memory_used_mb,
                        'disk_percent': metrics.disk_percent,
                        'network_sent_mb': metrics.network_sent_mb,
                        'network_recv_mb': metrics.network_recv_mb,
                        'active_connections': metrics.active_connections
                    })
        except Exception as e:
            logger.error(f"状态同步异常: {e}")

    def _process_commands(self):
        """处理命令队列，修复未处理白名单指令的Bug"""
        try:
            if not self.db:
                return
            
            commands = self.db.get_pending_commands(limit=5)
            for cmd in commands:
                cmd_id = cmd['id']
                try:
                    cmd_type = cmd['command_type']
                    cmd_data = json.loads(cmd['command_data'])
                    
                    logger.info(f"正在处理指令: {cmd_type}")
                    
                    if cmd_type == 'train_command' and self.ai_detector:
                        self._handle_train_command(cmd_data)
                        
                    elif cmd_type == 'defense_block' and self.defense_manager:
                        self.defense_manager.block_ip(
                            ip=cmd_data.get('ip'),
                            reason=cmd_data.get('reason', '手动拦截'),
                            duration=cmd_data.get('duration', 3600)
                        )
                        
                    elif cmd_type == 'defense_unblock' and self.defense_manager:
                        self.defense_manager.unblock_ip(cmd_data.get('ip'))

                    elif cmd_type == 'whitelist_add':
                        ip = cmd_data.get('ip')
                        if ip:
                            from database.models import Blacklist
                            self.db.remove_from_blacklist(ip)
                            bl = Blacklist(ip=ip, reason='手动白名单', create_time=time.time())
                            bl.status = 'whitelist'
                            self.db.add_to_blacklist(bl)
                            if self.defense_manager and hasattr(self.defense_manager, 'reload_config'):
                                self.defense_manager.reload_config()

                    elif cmd_type == 'whitelist_remove':
                        ip = cmd_data.get('ip')
                        if ip:
                            self.db.remove_from_blacklist(ip)
                            if self.defense_manager and hasattr(self.defense_manager, 'reload_config'):
                                self.defense_manager.reload_config()
                                
                    elif cmd_type == 'config_reload':
                        section = cmd_data.get('section')
                        if section == 'defense' and self.defense_manager and hasattr(self.defense_manager, 'reload_config'):
                            self.defense_manager.reload_config()
                        elif section == 'cleanup' and self.data_cleanup and hasattr(self.data_cleanup, 'reload_config'):
                            self.data_cleanup.reload_config()
                            
                except Exception as e:
                    logger.error(f"处理单条命令失败 (ID: {cmd_id}): {e}")
                finally:
                    self.db.mark_command_processed(cmd_id)
                    
        except Exception as e:
            logger.error(f"处理命令队列整体异常: {e}")
    
    def _handle_train_command(self, cmd_data):
        try:
            training_data_path = cmd_data.get('training_data_path')
            model_name = cmd_data.get('model_name')
            algorithm = cmd_data.get('algorithm', 'isolation_forest')
            
            if not training_data_path or not os.path.exists(training_data_path):
                logger.error(f"训练数据文件不存在: {training_data_path}")
                return
            
            with open(training_data_path, 'r', encoding='utf-8') as f:
                training_data = json.load(f)
            
            logger.info(f"开始训练模型: {model_name} 使用 {len(training_data)} 条样本")
            success, message = self.ai_detector.train_model(training_data, model_name, algorithm)
            
            if success:
                logger.info(f"模型训练成功: {message}")
            else:
                logger.error(f"模型训练失败: {message}")
            
            if os.path.exists(training_data_path):
                os.remove(training_data_path)
        except Exception as e:
            logger.error(f"处理训练命令异常: {e}")

    def stop(self):
        logger.info("正在停止守护进程...")
        self.running = False
        if self.capture: self.capture.stop_capture()
        if self.defense_manager: self.defense_manager.stop()
        if self.data_cleanup: self.data_cleanup.stop()
        if self.system_monitor: self.system_monitor.stop()
        logger.info("守护进程已完全停止")

def signal_handler(signum, frame):
    if 'daemon' in globals() and daemon:
        daemon.stop()
    sys.exit(0)

if __name__ == "__main__":
    try:
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        daemon = DaemonManager()
        try:
            daemon.initialize()
            daemon.run()
        except Exception as e:
            import traceback
            error_msg = traceback.format_exc()
            logger.error(f"启动崩溃: {e}")
            logger.error(f"详细错误信息:\n{error_msg}")
            daemon.stop()
            sys.exit(1)
    except Exception as e:
        import traceback
        error_msg = traceback.format_exc()
        print(f"致命错误: {e}")
        print(f"详细错误信息:\n{error_msg}")
        sys.exit(1)