import os
import json
import logging
import threading
from datetime import datetime
from typing import Dict, Any, Optional, List

logger = logging.getLogger(__name__)


class ConfigManager:
    """配置管理器 - 动态配置系统参数"""
    
    DEFAULT_CONFIG = {
        'capture': {
            'interface': 'eth0',
            'filter': '',
            'packet_count': 0,
            'timeout': 100,
            'buffer_size': 4096,
            'promiscuous': True
        },
        'detection': {
            'anomaly_threshold': 0.7,
            'attack_type_confidence': {
                'DDoS攻击': 0.8,
                '端口扫描': 0.7,
                'SQL注入': 0.8,
                '暴力破解': 0.8,
                'XSS攻击': 0.7,
                '命令注入': 0.8,
                'ARP欺骗': 0.7
            },
            'enable_ml': True,
            'enable_rule_based': True,
            'batch_size': 50,
            'detection_interval': 0.5
        },
        'defense': {
                'enabled': True,
                'auto_block': True,
                'block_duration': 3600,
                'confidence_threshold': 0.7,
                'rate_limit_threshold': 100,
                'ip_whitelist': [],
                'attack_type_block': {
                    'DDoS攻击': True,
                    '端口扫描': True,
                    'SQL注入': True,
                    '暴力破解': True,
                    'XSS攻击': False,
                    '命令注入': True,
                    'ARP欺骗': True
                }
            },
        'database': {
            'path': 'backend/data/security.db',
            'backup_enabled': True,
            'backup_interval': 86400,
            'retention_days': 30,
            'max_size_mb': 1000
        },
        'api': {
            'host': '0.0.0.0',
            'port': 5000,
            'debug': False,
            'rate_limit': 100,
            'cors_origins': ['http://localhost:3000', 'http://127.0.0.1:3000']
        },
        'logging': {
            'level': 'INFO',
            'max_size_mb': 10,
            'backup_count': 5,
            'log_path': 'backend/data'
        }
    }
    
    def __init__(self, config_file: str = None):
        # 支持从环境变量获取配置文件路径
        if config_file is None:
            config_file = os.environ.get('CONFIG_FILE_PATH', 'backend/data/config.json')
        self.config_file = config_file
        self.config = self.DEFAULT_CONFIG.copy()
        self.lock = threading.RLock()
        self._observers = []
        
        self._load_config()
        self._create_backup()
    
    def _load_config(self):
        """加载配置文件"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    loaded = json.load(f)
                    self._merge_config(loaded)
                logger.info(f"已从 {self.config_file} 加载配置")
            else:
                self._save_config()
                logger.info(f"已创建默认配置文件: {self.config_file}")
        except Exception as e:
            logger.error(f"加载配置文件失败: {e}")
    
    def _merge_config(self, loaded: Dict):
        """合并配置"""
        for section, values in loaded.items():
            if section in self.config:
                if isinstance(values, dict):
                    self.config[section].update(values)
                else:
                    self.config[section] = values
            else:
                self.config[section] = values
    
    def _save_config(self):
        """保存配置文件"""
        try:
            os.makedirs(os.path.dirname(self.config_file), exist_ok=True)
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error(f"保存配置文件失败: {e}")
    
    def get(self, section: str, key: Optional[str] = None, default: Any = None) -> Any:
        """获取配置值"""
        with self.lock:
            if key is None:
                return self.config.get(section, default)
            return self.config.get(section, {}).get(key, default)
    
    def set(self, section: str, key: str, value: Any):
        """设置配置值"""
        with self.lock:
            if section not in self.config:
                self.config[section] = {}
            self.config[section][key] = value
            self._save_config()
            self._notify_observers(section, key, value)
    
    def get_section(self, section: str) -> Dict:
        """获取整个配置节"""
        with self.lock:
            return self.config.get(section, {}).copy()
    
    def update_section(self, section: str, values: Dict):
        """更新整个配置节"""
        with self.lock:
            if section not in self.config:
                self.config[section] = {}
            self.config[section].update(values)
            self._save_config()
            for key, value in values.items():
                self._notify_observers(section, key, value)
    
    def reset_section(self, section: str):
        """重置配置节为默认值"""
        with self.lock:
            if section in self.DEFAULT_CONFIG:
                self.config[section] = self.DEFAULT_CONFIG[section].copy()
                self._save_config()
    
    def reset_all(self):
        """重置所有配置为默认值"""
        with self.lock:
            self.config = self.DEFAULT_CONFIG.copy()
            self._save_config()
    
    def register_observer(self, callback):
        """注册配置变更观察者"""
        if callback not in self._observers:
            self._observers.append(callback)
    
    def unregister_observer(self, callback):
        """注销配置变更观察者"""
        if callback in self._observers:
            self._observers.remove(callback)
    
    def _notify_observers(self, section: str, key: str, value: Any):
        """通知观察者配置变更"""
        for observer in self._observers:
            try:
                observer(section, key, value)
            except Exception as e:
                logger.error(f"通知配置观察者失败: {e}")
    
    def export_config(self) -> str:
        """导出配置为JSON字符串"""
        with self.lock:
            return json.dumps(self.config, ensure_ascii=False, indent=2)
    
    def import_config(self, json_str: str) -> bool:
        """从JSON字符串导入配置"""
        try:
            imported = json.loads(json_str)
            with self.lock:
                self._merge_config(imported)
                self._save_config()
            return True
        except Exception as e:
            logger.error(f"导入配置失败: {e}")
            return False
    
    def validate_config(self) -> Dict[str, List[str]]:
        """验证配置有效性"""
        errors = {}
        
        detection = self.config.get('detection', {})
        threshold = detection.get('anomaly_threshold', 0.7)
        if not 0 <= threshold <= 1:
            errors.setdefault('detection', []).append('anomaly_threshold 必须在 0-1 之间')
        
        defense = self.config.get('defense', {})
        block_duration = defense.get('block_duration', 3600)
        if block_duration < 60:
            errors.setdefault('defense', []).append('block_duration 不能小于 60 秒')
        
        api = self.config.get('api', {})
        port = api.get('port', 5000)
        if not 1 <= port <= 65535:
            errors.setdefault('api', []).append('port 必须在 1-65535 之间')
        
        return errors
    
    def _create_backup(self):
        """创建配置备份"""
        try:
            if os.path.exists(self.config_file):
                backup_file = f"{self.config_file}.backup"
                import shutil
                shutil.copy2(self.config_file, backup_file)
                logger.info(f"已创建配置备份: {backup_file}")
        except Exception as e:
            logger.error(f"创建配置备份失败: {e}")
    
    def restore_from_backup(self) -> bool:
        """从备份恢复配置"""
        try:
            backup_file = f"{self.config_file}.backup"
            if os.path.exists(backup_file):
                import shutil
                shutil.copy2(backup_file, self.config_file)
                self._load_config()
                logger.info(f"已从备份恢复配置: {backup_file}")
                return True
            else:
                logger.warning(f"备份文件不存在: {backup_file}")
                return False
        except Exception as e:
            logger.error(f"从备份恢复配置失败: {e}")
            return False
    
    def list_backups(self) -> List[str]:
        """列出所有配置备份"""
        try:
            backups = []
            backup_pattern = f"{self.config_file}.*.backup"
            import glob
            for backup_file in glob.glob(backup_pattern):
                backups.append(backup_file)
            # 也检查基本备份文件
            basic_backup = f"{self.config_file}.backup"
            if os.path.exists(basic_backup):
                backups.append(basic_backup)
            return backups
        except Exception as e:
            logger.error(f"列出备份失败: {e}")
            return []
    
    def create_timestamped_backup(self) -> str:
        """创建带时间戳的配置备份"""
        try:
            import datetime
            timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_file = f"{self.config_file}.{timestamp}.backup"
            if os.path.exists(self.config_file):
                import shutil
                shutil.copy2(self.config_file, backup_file)
                logger.info(f"已创建时间戳备份: {backup_file}")
                return backup_file
            else:
                logger.warning(f"配置文件不存在，无法创建备份: {self.config_file}")
                return ''
        except Exception as e:
            logger.error(f"创建时间戳备份失败: {e}")
            return ''


def create_config_manager(config_file: str = None) -> ConfigManager:
    """创建配置管理器实例"""
    if config_file is None:
        config_file = os.environ.get('CONFIG_FILE_PATH', 'backend/data/config.json')
    return ConfigManager(config_file)
