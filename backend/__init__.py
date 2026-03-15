"""校园网异常检测与防御平台后端模块"""

__version__ = "1.0.0"
__author__ = "Campus Network Security Team"

# 导出核心模块
from .api_server import create_app
from .daemon import DaemonManager
from .config import ConfigManager, create_config_manager
from .database.db_manager import create_db_manager
from .ai.ai_detector import create_ai_detector
from .capture.capture import NetworkCapture
from .defense import create_defense_manager, RateLimiter
from .monitor import DataCleanupManager, SystemMonitor

__all__ = [
    "create_app",
    "DaemonManager",
    "ConfigManager",
    "create_config_manager",
    "create_db_manager",
    "create_ai_detector",
    "NetworkCapture",
    "create_defense_manager",
    "RateLimiter",
    "DataCleanupManager",
    "SystemMonitor"
]
