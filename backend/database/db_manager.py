"""
数据库管理器
负责所有数据库操作
"""

import sqlite3
import json
import time
import bcrypt
import logging
import threading
from pathlib import Path
from database.models import TrafficLog, Alert, Blacklist, BlockLog, User

# 配置日志
log_dir = Path(__file__).parent.parent / 'data'
log_dir.mkdir(parents=True, exist_ok=True)
log_path = log_dir / 'database.log'

# 配置日志（使用RotatingFileHandler避免日志文件过大）
from logging.handlers import RotatingFileHandler
file_handler = RotatingFileHandler(
    log_path,
    maxBytes=10*1024*1024,  # 10MB
    backupCount=5,  # 保留5个备份
    encoding='utf-8'
)

# 配置日志格式
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)

# 获取日志记录器
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logger.addHandler(file_handler)


class DatabaseManager:
    """数据库管理器 - 支持多线程的版本"""

    _local = threading.local()
    _lock = threading.Lock()
    _initialized = False

    def __init__(self, db_path=None):
        """
        初始化数据库管理器
        
        Args:
            db_path: 数据库文件路径
        """
        # 使用绝对路径
        if db_path is None:
            self.db_path = str(Path(__file__).parent.parent / 'data' / 'security.db')
        else:
            self.db_path = db_path
        
        # 确保data目录存在
        Path(self.db_path).parent.mkdir(exist_ok=True)
        
        # 确保只初始化一次表结构
        with self._lock:
            if not self._initialized:
                self._init_tables()
                self._initialized = True

    def _get_connection(self):
        """获取当前线程的数据库连接"""
        if not hasattr(self._local, 'conn') or self._local.conn is None:
            try:
                self._local.conn = sqlite3.connect(
                    self.db_path,
                    check_same_thread=False,
                    timeout=30.0
                )
                self._local.conn.row_factory = sqlite3.Row
                self._local.conn.execute('PRAGMA foreign_keys = ON')
                self._local.conn.execute('PRAGMA journal_mode = WAL')
                self._local.conn.execute('PRAGMA busy_timeout = 30000')
                logger.debug(f"线程 {threading.current_thread().name} 已创建数据库连接")
            except Exception as e:
                logger.error(f"创建数据库连接失败: {e}")
                raise
        return self._local.conn

    def _get_cursor(self):
        """获取当前线程的数据库游标"""
        conn = self._get_connection()
        if not hasattr(self._local, 'cursor') or self._local.cursor is None:
            self._local.cursor = conn.cursor()
        return self._local.cursor

    def _close_connection(self):
        """关闭当前线程的数据库连接"""
        if hasattr(self._local, 'cursor') and self._local.cursor is not None:
            try:
                self._local.cursor.close()
            except Exception as e:
                logger.error(f"关闭游标失败: {e}")
            finally:
                self._local.cursor = None
        
        if hasattr(self._local, 'conn') and self._local.conn is not None:
            try:
                self._local.conn.close()
                logger.debug(f"线程 {threading.current_thread().name} 已关闭数据库连接")
            except Exception as e:
                logger.error(f"关闭数据库连接失败: {e}")
            finally:
                self._local.conn = None

    def close(self):
        """关闭当前线程的数据库连接"""
        self._close_connection()

    def get_stats(self):
        """获取数据库统计信息"""
        conn = None
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            # 总流量数
            cursor.execute('SELECT COUNT(*) as count FROM traffic_logs')
            total_traffic = cursor.fetchone()['count']
            
            # 异常流量数
            cursor.execute('SELECT COUNT(*) as count FROM traffic_logs WHERE is_anomaly = 1')
            anomaly_count = cursor.fetchone()['count']
            
            # 今日流量数
            import datetime
            today_start = time.mktime(datetime.date.today().timetuple())  # 本地时区今天0点
            cursor.execute('SELECT COUNT(*) as count FROM traffic_logs WHERE timestamp >= ?', (today_start,))
            today_traffic = cursor.fetchone()['count']
            
            # 今日异常数
            cursor.execute('SELECT COUNT(*) as count FROM traffic_logs WHERE is_anomaly = 1 AND timestamp >= ?', (today_start,))
            today_anomaly = cursor.fetchone()['count']
            
            # 最近1小时流量数
            hour_ago = time.time() - 3600
            cursor.execute('SELECT COUNT(*) as count FROM traffic_logs WHERE timestamp >= ?', (hour_ago,))
            hour_traffic = cursor.fetchone()['count']
            
            # 告警统计
            cursor.execute('SELECT COUNT(*) as count FROM alerts')
            total_alerts = cursor.fetchone()['count']
            
            cursor.execute('SELECT COUNT(*) as count FROM alerts WHERE status = "未处理"')
            pending_alerts = cursor.fetchone()['count']
            
            # 黑名单统计
            cursor.execute('SELECT COUNT(*) as count FROM blacklist WHERE status = "封禁中"')
            blacklist_count = cursor.fetchone()['count']
            
            # 协议分布
            cursor.execute('''
                SELECT protocol, COUNT(*) as count 
                FROM traffic_logs 
                WHERE timestamp >= ?
                GROUP BY protocol 
                ORDER BY count DESC 
                LIMIT 10
            ''', (hour_ago,))
            protocol_dist = {row['protocol']: row['count'] for row in cursor.fetchall()}
            
            return {
                'total_traffic': total_traffic,
                'anomaly_count': anomaly_count,
                'today_traffic': today_traffic,
                'today_anomaly': today_anomaly,
                'hour_traffic': hour_traffic,
                'total_alerts': total_alerts,
                'pending_alerts': pending_alerts,
                'blacklist_count': blacklist_count,
                'protocol_distribution': protocol_dist
            }
        except Exception as e:
            logger.error(f"获取统计信息失败: {e}")
            return {
                'total_traffic': 0,
                'anomaly_count': 0,
                'today_traffic': 0,
                'today_anomaly': 0,
                'hour_traffic': 0,
                'total_alerts': 0,
                'pending_alerts': 0,
                'blacklist_count': 0,
                'protocol_distribution': {}
            }

    def get_traffic_stats_by_time(self, hours=24):
        """获取按时间分组的流量统计"""
        conn = None
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            start_time = time.time() - hours * 3600
            
            # 按小时分组统计
            cursor.execute('''
                SELECT 
                    CAST((timestamp - ?) / 3600 AS INTEGER) as hour_offset,
                    COUNT(*) as count,
                    SUM(CASE WHEN is_anomaly = 1 THEN 1 ELSE 0 END) as anomaly_count
                FROM traffic_logs
                WHERE timestamp >= ?
                GROUP BY hour_offset
                ORDER BY hour_offset
            ''', (start_time, start_time))
            
            results = []
            for row in cursor.fetchall():
                results.append({
                    'hour_offset': row['hour_offset'],
                    'count': row['count'],
                    'anomaly_count': row['anomaly_count']
                })
            
            return results
        except Exception as e:
            logger.error(f"获取时间分组统计失败: {e}")
            return []

    def get_top_talkers(self, limit=10, hours=24):
        """获取流量最多的IP地址"""
        conn = None
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            start_time = time.time() - hours * 3600
            
            # 源IP统计
            cursor.execute('''
                SELECT src_ip, COUNT(*) as count, SUM(length) as bytes
                FROM traffic_logs
                WHERE timestamp >= ?
                GROUP BY src_ip
                ORDER BY count DESC
                LIMIT ?
            ''', (start_time, limit))
            
            top_sources = []
            for row in cursor.fetchall():
                top_sources.append({
                    'ip': row['src_ip'],
                    'count': row['count'],
                    'bytes': row['bytes']
                })
            
            # 目的IP统计
            cursor.execute('''
                SELECT dst_ip, COUNT(*) as count, SUM(length) as bytes
                FROM traffic_logs
                WHERE timestamp >= ?
                GROUP BY dst_ip
                ORDER BY count DESC
                LIMIT ?
            ''', (start_time, limit))
            
            top_destinations = []
            for row in cursor.fetchall():
                top_destinations.append({
                    'ip': row['dst_ip'],
                    'count': row['count'],
                    'bytes': row['bytes']
                })
            
            return {
                'top_sources': top_sources,
                'top_destinations': top_destinations
            }
        except Exception as e:
            logger.error(f"获取Top Talkers失败: {e}")
            return {'top_sources': [], 'top_destinations': []}

    def _init_tables(self):
        """初始化所有表（只在主线程调用一次）"""
        for attempt in range(5):
            try:
                conn = sqlite3.connect(self.db_path, timeout=10.0)
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                # 流量记录表
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS traffic_logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp REAL NOT NULL,
                        src_ip VARCHAR(45) NOT NULL,
                        dst_ip VARCHAR(45) NOT NULL,
                        src_port INTEGER,
                        dst_port INTEGER,
                        protocol VARCHAR(10) NOT NULL,
                        length INTEGER NOT NULL,
                        ttl INTEGER,
                        flags VARCHAR(20),
                        feature_json TEXT,
                        is_anomaly INTEGER DEFAULT 0
                    )
                ''')

                # 告警记录表
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS alerts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp REAL NOT NULL,
                        level VARCHAR(10) NOT NULL,
                        type VARCHAR(50) NOT NULL,
                        src_ip VARCHAR(45),
                        dst_ip VARCHAR(45),
                        description TEXT,
                        status VARCHAR(20) DEFAULT '未处理',
                        vulnerability_type VARCHAR(100),
                        handled_time REAL
                    )
                ''')

                # 黑名单表
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS blacklist (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ip VARCHAR(45) UNIQUE NOT NULL,
                        reason VARCHAR(200),
                        create_time REAL NOT NULL,
                        expire_time REAL,
                        status VARCHAR(20) DEFAULT '封禁中'
                    )
                ''')

                # 拦截记录表
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS block_logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp REAL NOT NULL,
                        ip VARCHAR(45) NOT NULL,
                        rule VARCHAR(100),
                        action VARCHAR(20) NOT NULL,
                        result VARCHAR(20) NOT NULL,
                        alert_id INTEGER
                    )
                ''')

                # 系统状态表
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS system_status (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp REAL NOT NULL,
                        service_name VARCHAR(50) NOT NULL,
                        status VARCHAR(20) NOT NULL,
                        metrics TEXT,
                        UNIQUE(service_name)
                    )
                ''')

                # 系统监控表
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS system_metrics (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp REAL NOT NULL,
                        cpu_percent REAL,
                        memory_percent REAL,
                        memory_used_mb REAL,
                        memory_available_mb REAL,
                        disk_percent REAL,
                        disk_used_gb REAL,
                        network_sent_mb REAL,
                        network_recv_mb REAL,
                        active_connections INTEGER,
                        thread_count INTEGER
                    )
                ''')

                # 命令队列表 - 用于处理API指令，避免并发覆盖
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS command_queue (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp REAL NOT NULL,
                        command_type VARCHAR(50) NOT NULL,
                        command_data TEXT NOT NULL,
                        status VARCHAR(20) DEFAULT 'pending',
                        processed_at REAL
                    )
                ''')

                # 用户表
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username VARCHAR(50) UNIQUE NOT NULL,
                        password VARCHAR(100) NOT NULL,
                        role VARCHAR(20) DEFAULT 'user',
                        created_at REAL NOT NULL,
                        created_by VARCHAR(50),
                        status VARCHAR(20) DEFAULT '正常'
                    )
                ''')

                # 创建索引
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_traffic_time ON traffic_logs(timestamp)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_traffic_src ON traffic_logs(src_ip)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_time ON alerts(timestamp)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_level ON alerts(level)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_blacklist_ip ON blacklist(ip)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_block_time ON block_logs(timestamp)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_users_name ON users(username)')

                # 添加默认管理员
                hashed_password = bcrypt.hashpw('admin123'.encode('utf-8'), bcrypt.gensalt())
                hashed_password_str = hashed_password.decode('utf-8')
                
                try:
                    cursor.execute('''
                        INSERT OR IGNORE INTO users (username, password, role, created_at, created_by, status)
                        VALUES (?, ?, ?, ?, ?, ?)
                    ''', ('admin', hashed_password_str, 'admin', time.time(), 'system', '正常'))
                    if cursor.rowcount > 0:
                        logger.info("已创建默认管理员账号: admin/admin123")
                except Exception as e:
                    logger.warning(f"创建默认管理员时出错（可能是并发创建）: {e}")

                conn.commit()
                conn.close()
                logger.info("数据表初始化完成（包含用户表）")
                break # 成功则跳出循环
            except sqlite3.OperationalError as e:
                if 'locked' in str(e).lower():
                    time.sleep(0.5 * (attempt + 1))
                    continue
                raise
            except Exception as e:
                logger.error(f"初始化数据表失败: {e}")
                if 'conn' in locals():
                    try:
                        conn.rollback()
                        conn.close()
                    except:
                        pass
                raise

    # ========== 流量记录操作 ==========

    def insert_traffic(self, traffic_log, max_retries=5):
        """插入一条流量记录"""
        conn = None
        for attempt in range(max_retries):
            try:
                conn = self._get_connection()
                cursor = conn.cursor()
                
                sql = '''
                    INSERT INTO traffic_logs 
                    (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, length, ttl, flags, feature_json, is_anomaly)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                '''
                cursor.execute(sql, (
                    traffic_log.timestamp,
                    traffic_log.src_ip,
                    traffic_log.dst_ip,
                    traffic_log.src_port,
                    traffic_log.dst_port,
                    traffic_log.protocol,
                    traffic_log.length,
                    traffic_log.ttl,
                    traffic_log.flags,
                    traffic_log.feature_json,
                    traffic_log.is_anomaly
                ))
                conn.commit()
                traffic_log.id = cursor.lastrowid
                return traffic_log.id
            except sqlite3.OperationalError as e:
                if 'locked' in str(e).lower():
                    if attempt < max_retries - 1:
                        time.sleep(0.1 * (attempt + 1))
                        continue
                    else:
                        if conn: conn.rollback()
                        raise
                else:
                    if conn: conn.rollback()
                    raise
            except Exception as e:
                if conn: conn.rollback()
                raise
        return None

    def insert_traffic_batch(self, traffic_logs, max_retries=5):
        """批量插入流量记录"""
        if not traffic_logs:
            return 0
            
        conn = None
        for attempt in range(max_retries):
            try:
                conn = self._get_connection()
                cursor = conn.cursor()
                
                sql = '''
                    INSERT INTO traffic_logs 
                    (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, length, ttl, flags, feature_json, is_anomaly)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                '''
                
                batch_data = []
                for log in traffic_logs:
                    batch_data.append((
                        log.timestamp, log.src_ip, log.dst_ip, log.src_port, log.dst_port,
                        log.protocol, log.length, log.ttl, log.flags, log.feature_json, log.is_anomaly
                    ))
                
                cursor.executemany(sql, batch_data)
                conn.commit()
                return len(traffic_logs)
                
            except sqlite3.OperationalError as e:
                if 'locked' in str(e).lower():
                    if attempt < max_retries - 1:
                        time.sleep(0.1 * (attempt + 1))
                        continue
                    else:
                        if conn: conn.rollback()
                        raise
                else:
                    if conn: conn.rollback()
                    raise
            except Exception as e:
                if conn: conn.rollback()
                raise
        return 0

    def get_recent_traffic(self, limit=100, offset=0, src_ip=None, protocol=None, start_time=None, end_time=None, status=None, max_retries=5):
        """获取最近的流量记录"""
        conn = None
        for attempt in range(max_retries):
            try:
                conn = self._get_connection()
                cursor = conn.cursor()
                
                query = 'SELECT * FROM traffic_logs WHERE 1=1'
                params = []
                
                if src_ip:
                    query += ' AND src_ip = ?'
                    params.append(src_ip)
                if protocol:
                    query += ' AND protocol = ?'
                    params.append(protocol)
                if start_time:
                    query += ' AND timestamp >= ?'
                    params.append(start_time)
                if end_time:
                    query += ' AND timestamp <= ?'
                    params.append(end_time)
                if status:
                    if status == 'abnormal':
                        query += ' AND is_anomaly = 1'
                    elif status == 'normal':
                        query += ' AND is_anomaly = 0'
                
                query += ' ORDER BY timestamp DESC LIMIT ? OFFSET ?'
                params.extend([limit, offset])
                
                cursor.execute(query, params)
                rows = cursor.fetchall()
                return [self._row_to_traffic(row) for row in rows]
            except sqlite3.OperationalError as e:
                if 'locked' in str(e).lower():
                    if attempt < max_retries - 1:
                        time.sleep(0.1 * (attempt + 1))
                        continue
                    else:
                        raise
                else:
                    raise
            except Exception as e:
                raise
        return []

    # 这里是修复的关键：带参查询总数的方法
    def get_traffic_count(self, src_ip=None, protocol=None, start_time=None, end_time=None, status=None, max_retries=5):
        """获取流量记录总数（支持过滤）"""
        conn = None
        for attempt in range(max_retries):
            try:
                conn = self._get_connection()
                cursor = conn.cursor()
                
                query = 'SELECT COUNT(*) FROM traffic_logs WHERE 1=1'
                params = []
                
                if src_ip:
                    query += ' AND src_ip = ?'
                    params.append(src_ip)
                if protocol:
                    query += ' AND protocol = ?'
                    params.append(protocol)
                if start_time:
                    query += ' AND timestamp >= ?'
                    params.append(start_time)
                if end_time:
                    query += ' AND timestamp <= ?'
                    params.append(end_time)
                if status:
                    if status == 'abnormal':
                        query += ' AND is_anomaly = 1'
                    elif status == 'normal':
                        query += ' AND is_anomaly = 0'
                
                cursor.execute(query, params)
                result = cursor.fetchone()
                return result[0] if result else 0
            except sqlite3.OperationalError as e:
                if 'locked' in str(e).lower():
                    if attempt < max_retries - 1:
                        time.sleep(0.1 * (attempt + 1))
                        continue
                    else:
                        raise
                else:
                    raise
            except Exception as e:
                raise
        return 0

    def get_anomaly_traffic(self, start_time=None, end_time=None):
        """获取异常流量记录"""
        conn = None
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            if start_time is None:
                start_time = time.time() - 24 * 3600
            if end_time is None:
                end_time = time.time()

            cursor.execute('''
                SELECT * FROM traffic_logs 
                WHERE is_anomaly = 1 
                AND timestamp BETWEEN ? AND ?
                ORDER BY timestamp DESC
            ''', (start_time, end_time))

            rows = cursor.fetchall()
            return [self._row_to_traffic(row) for row in rows]
        except Exception as e:
            logger.error(f"获取异常流量记录失败: {e}")
            raise

    def _row_to_traffic(self, row):
        """将数据库行转为TrafficLog对象"""
        log = TrafficLog(
            timestamp=row['timestamp'],
            src_ip=row['src_ip'],
            dst_ip=row['dst_ip'],
            protocol=row['protocol'],
            length=row['length'],
            src_port=row['src_port'],
            dst_port=row['dst_port'],
            ttl=row['ttl'],
            flags=row['flags'],
            feature_json=row['feature_json'],
            is_anomaly=row['is_anomaly']
        )
        log.id = row['id']
        return log

    # ========== 告警记录操作 ==========

    def insert_alert(self, alert, max_retries=5):
        """插入一条告警记录"""
        conn = None
        for attempt in range(max_retries):
            try:
                conn = self._get_connection()
                cursor = conn.cursor()
                
                sql = '''
                    INSERT INTO alerts 
                    (timestamp, level, type, src_ip, dst_ip, description, status, vulnerability_type)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                '''
                cursor.execute(sql, (
                    alert.timestamp, alert.level, alert.type, alert.src_ip,
                    alert.dst_ip, alert.description, alert.status, alert.vulnerability_type
                ))
                conn.commit()
                alert.id = cursor.lastrowid
                return alert.id
            except sqlite3.OperationalError as e:
                if 'locked' in str(e).lower():
                    if attempt < max_retries - 1:
                        time.sleep(0.1 * (attempt + 1))
                        continue
                    else:
                        if conn: conn.rollback()
                        raise
                else:
                    if conn: conn.rollback()
                    raise
            except Exception as e:
                if conn: conn.rollback()
                raise
        return None

    def get_alerts(self, level=None, status=None, type=None, limit=100, offset=0):
        """获取告警记录"""
        conn = None
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            sql = 'SELECT * FROM alerts WHERE 1=1'
            params = []

            if level:
                sql += ' AND level = ?'
                params.append(level)
            if status:
                sql += ' AND status = ?'
                params.append(status)
            if type:
                sql += ' AND type = ?'
                params.append(type)

            sql += ' ORDER BY timestamp DESC LIMIT ? OFFSET ?'
            params.extend([limit, offset])

            cursor.execute(sql, params)
            rows = cursor.fetchall()

            alerts = []
            for row in rows:
                vulnerability_type = row['vulnerability_type'] if 'vulnerability_type' in row else None
                alert = Alert(
                    timestamp=row['timestamp'],
                    level=row['level'],
                    type=row['type'],
                    src_ip=row['src_ip'],
                    description=row['description'],
                    dst_ip=row['dst_ip'],
                    status=row['status'],
                    vulnerability_type=vulnerability_type
                )
                alert.id = row['id']
                alert.handled_time = row['handled_time']
                alerts.append(alert)

            return alerts
        except Exception as e:
            logger.error(f"获取告警记录失败: {e}")
            raise

    def get_alert_count(self, level=None, status=None, type=None, max_retries=5):
        """获取告警记录总数（支持过滤）"""
        conn = None
        for attempt in range(max_retries):
            try:
                conn = self._get_connection()
                cursor = conn.cursor()
                
                sql = 'SELECT COUNT(*) FROM alerts WHERE 1=1'
                params = []

                if level:
                    sql += ' AND level = ?'
                    params.append(level)
                if status:
                    sql += ' AND status = ?'
                    params.append(status)
                if type:
                    sql += ' AND type = ?'
                    params.append(type)

                cursor.execute(sql, params)
                result = cursor.fetchone()
                return result[0] if result else 0
            except sqlite3.OperationalError as e:
                if 'locked' in str(e).lower():
                    if attempt < max_retries - 1:
                        time.sleep(0.1 * (attempt + 1))
                        continue
                    else:
                        raise
                else:
                    raise
            except Exception as e:
                raise
        return 0

    def update_alert_status(self, alert_id, status):
        """更新告警状态"""
        conn = None
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            handled_time = time.time() if status == '已处理' else None
            cursor.execute('''
                UPDATE alerts 
                SET status = ?, handled_time = ?
                WHERE id = ?
            ''', (status, handled_time, alert_id))
            conn.commit()
            return cursor.rowcount > 0
        except Exception as e:
            logger.error(f"更新告警状态失败: {e}")
            if conn:
                conn.rollback()
            raise
    
    def clear_all_alerts(self):
        """清除所有告警"""
        conn = None
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute('DELETE FROM alerts')
            conn.commit()
            return cursor.rowcount
        except Exception as e:
            logger.error(f"清除告警失败: {e}")
            if conn:
                conn.rollback()
            raise

    # ========== 黑名单操作 ==========

    def add_to_blacklist(self, blacklist_item):
        conn = None
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            sql = '''
                INSERT OR REPLACE INTO blacklist 
                (ip, reason, create_time, expire_time, status)
                VALUES (?, ?, ?, ?, ?)
            '''
            cursor.execute(sql, (
                blacklist_item.ip, blacklist_item.reason, blacklist_item.create_time,
                blacklist_item.expire_time, blacklist_item.status
            ))
            conn.commit()
            blacklist_item.id = cursor.lastrowid
            return blacklist_item.id
        except Exception as e:
            if conn: conn.rollback()
            raise

    def remove_from_blacklist(self, ip):
        conn = None
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute('DELETE FROM blacklist WHERE ip = ?', (ip,))
            conn.commit()
            return cursor.rowcount > 0
        except Exception as e:
            if conn: conn.rollback()
            raise

    def get_blacklist(self, active_only=True, limit=None):
        conn = None
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            sql = 'SELECT * FROM blacklist'
            params = []
            if active_only:
                sql += ' WHERE status = "封禁中"'
            if limit:
                sql += ' LIMIT ?'
                params.append(limit)

            cursor.execute(sql, params)
            rows = cursor.fetchall()

            blacklist = []
            for row in rows:
                item = Blacklist(
                    ip=row['ip'], reason=row['reason'],
                    create_time=row['create_time'], expire_time=row['expire_time']
                )
                item.id = row['id']
                item.status = row['status']
                blacklist.append(item)
            return blacklist
        except Exception as e:
            raise

    def check_blacklist(self, ip):
        conn = None
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM blacklist WHERE ip = ? AND status = '封禁中'", (ip,))
            row = cursor.fetchone()

            if row:
                if row['expire_time'] and time.time() > row['expire_time']:
                    self.remove_from_blacklist(ip)
                    return None
                item = Blacklist(
                    ip=row['ip'], reason=row['reason'],
                    create_time=row['create_time'], expire_time=row['expire_time']
                )
                item.id = row['id']
                item.status = row['status']
                return item
            return None
        except Exception as e:
            raise

    # ========== 拦截记录操作 ==========

    def insert_block_log(self, block_log, max_retries=5):
        conn = None
        for attempt in range(max_retries):
            try:
                conn = self._get_connection()
                cursor = conn.cursor()
                
                sql = '''
                    INSERT INTO block_logs 
                    (timestamp, ip, rule, action, result, alert_id)
                    VALUES (?, ?, ?, ?, ?, ?)
                '''
                cursor.execute(sql, (
                    block_log.timestamp, block_log.ip, block_log.rule,
                    block_log.action, block_log.result, block_log.alert_id
                ))
                conn.commit()
                block_log.id = cursor.lastrowid
                return block_log.id
            except sqlite3.OperationalError as e:
                if 'locked' in str(e).lower():
                    if attempt < max_retries - 1:
                        time.sleep(0.1 * (attempt + 1))
                        continue
                    else:
                        if conn: conn.rollback()
                        raise
                else:
                    if conn: conn.rollback()
                    raise
            except Exception as e:
                if conn: conn.rollback()
                raise
        return None

    def get_block_logs(self, ip=None, limit=100, offset=0):
        conn = None
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            sql = 'SELECT * FROM block_logs'
            params = []
            if ip:
                sql += ' WHERE ip = ?'
                params.append(ip)
            sql += ' ORDER BY timestamp DESC LIMIT ? OFFSET ?'
            params.extend([limit, offset])

            cursor.execute(sql, params)
            rows = cursor.fetchall()

            logs = []
            for row in rows:
                log = BlockLog(
                    timestamp=row['timestamp'], ip=row['ip'], action=row['action'],
                    result=row['result'], rule=row['rule'], alert_id=row['alert_id']
                )
                log.id = row['id']
                logs.append(log)
            return logs
        except Exception as e:
            raise

    def get_block_log_count(self, ip=None):
        conn = None
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            sql = 'SELECT COUNT(*) FROM block_logs'
            params = []
            if ip:
                sql += ' WHERE ip = ?'
                params.append(ip)

            cursor.execute(sql, params)
            result = cursor.fetchone()
            return result[0] if result else 0
        except Exception as e:
            raise

    # ========== 用户操作 ==========

    def create_user(self, username, password, role='user', created_by=None):
        conn = None
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            hashed_password_str = hashed_password.decode('utf-8')
            
            cursor.execute('''
                INSERT INTO users (username, password, role, created_at, created_by, status)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (username, hashed_password_str, role, time.time(), created_by, '正常'))
            conn.commit()
            return cursor.lastrowid
        except Exception as e:
            if conn: conn.rollback()
            raise

    def get_user_by_username(self, username):
        conn = None
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
            row = cursor.fetchone()
            if row:
                user = User(username=row['username'], password=row['password'], role=row['role'], created_by=row['created_by'])
                user.id = row['id']; user.created_at = row['created_at']; user.status = row['status']
                return user
            return None
        except Exception as e:
            raise

    def check_user(self, username, password):
        conn = None
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
            row = cursor.fetchone()
            
            if row:
                if bcrypt.checkpw(password.encode('utf-8'), row['password'].encode('utf-8')):
                    user = User(username=row['username'], password=row['password'], role=row['role'], created_by=row['created_by'])
                    user.id = row['id']; user.created_at = row['created_at']; user.status = row['status']
                    return user
            return None
        except Exception as e:
            raise

    def update_password(self, username, new_password):
        conn = None
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            cursor.execute('UPDATE users SET password = ? WHERE username = ?', (hashed_password, username))
            conn.commit()
            return cursor.rowcount > 0
        except Exception as e:
            if conn: conn.rollback()
            raise

    def get_all_users(self):
        conn = None
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users')
            rows = cursor.fetchall()
            users = []
            for row in rows:
                user = User(username=row['username'], password=row['password'], role=row['role'], created_by=row['created_by'])
                user.id = row['id']; user.created_at = row['created_at']; user.status = row['status']
                users.append(user)
            return users
        except Exception as e:
            raise

    def delete_user(self, username):
        conn = None
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute('DELETE FROM users WHERE username = ?', (username,))
            conn.commit()
            return cursor.rowcount > 0
        except Exception as e:
            if conn: conn.rollback()
            raise

    # ========== 统计信息与系统维护 ==========

    def get_statistics(self):
        conn = None
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            today_start = time.mktime(time.localtime(time.time())[:3] + (0, 0, 0, -1, -1, -1))
            
            cursor.execute('SELECT COUNT(*) FROM alerts WHERE timestamp >= ?', (today_start,))
            today_alerts = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM blacklist WHERE status = '封禁中'")
            blacklist_count = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM block_logs WHERE timestamp >= ? AND action = '封禁'", (today_start,))
            today_blocks = cursor.fetchone()[0]

            cursor.execute('SELECT COUNT(*) FROM traffic_logs WHERE timestamp >= ?', (today_start,))
            today_traffic = cursor.fetchone()[0]

            return {
                'today_alerts': today_alerts,
                'blacklist_count': blacklist_count,
                'today_blocks': today_blocks,
                'today_traffic': today_traffic
            }
        except Exception as e:
            raise

    def cleanup_old_data(self, retention_days=30, retention_config=None):
        conn = None
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            # 默认保留期限配置
            default_config = {
                'traffic_logs': 7,      # 流量日志保留7天
                'alerts': 30,           # 告警记录保留30天
                'block_logs': 14,       # 拦截记录保留14天
                'system_metrics': 7,    # 系统指标保留7天
                'command_queue': 3      # 命令队列保留3天
            }
            
            # 合并用户配置
            if retention_config:
                default_config.update(retention_config)
            
            result = {
                'traffic_logs_deleted': 0, 'alerts_deleted': 0, 'block_logs_deleted': 0,
                'system_metrics_deleted': 0, 'command_queue_deleted': 0
            }
            
            # 清理流量日志
            traffic_cutoff = time.time() - (default_config['traffic_logs'] * 86400)
            deleted_traffic = 0
            while True:
                cursor.execute('''
                    DELETE FROM traffic_logs 
                    WHERE id IN (SELECT id FROM traffic_logs WHERE timestamp < ? LIMIT 5000)
                ''', (traffic_cutoff,))
                if cursor.rowcount == 0: break
                deleted_traffic += cursor.rowcount
                conn.commit()
                time.sleep(0.1)
            result['traffic_logs_deleted'] = deleted_traffic
            
            # 清理告警记录
            alerts_cutoff = time.time() - (default_config['alerts'] * 86400)
            cursor.execute('DELETE FROM alerts WHERE timestamp < ?', (alerts_cutoff,))
            result['alerts_deleted'] = cursor.rowcount
            
            # 清理拦截记录
            block_logs_cutoff = time.time() - (default_config['block_logs'] * 86400)
            cursor.execute('DELETE FROM block_logs WHERE timestamp < ?', (block_logs_cutoff,))
            result['block_logs_deleted'] = cursor.rowcount
            
            # 清理系统指标
            system_metrics_cutoff = time.time() - (default_config['system_metrics'] * 86400)
            cursor.execute('DELETE FROM system_metrics WHERE timestamp < ?', (system_metrics_cutoff,))
            result['system_metrics_deleted'] = cursor.rowcount
            
            # 清理命令队列
            command_queue_cutoff = time.time() - (default_config['command_queue'] * 86400)
            cursor.execute('DELETE FROM command_queue WHERE status IN ("processed", "failed") AND processed_at < ?', (command_queue_cutoff,))
            result['command_queue_deleted'] = cursor.rowcount
            
            conn.commit()
            return result
        except Exception as e:
            if conn: conn.rollback()
            raise

    def save_system_status(self, service_name, status, metrics=None):
        conn = None
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO system_status (service_name, timestamp, status, metrics)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(service_name) DO UPDATE SET
                    timestamp = excluded.timestamp,
                    status = excluded.status,
                    metrics = excluded.metrics
            ''', (service_name, time.time(), status, metrics))
            conn.commit()
            return True
        except Exception as e:
            if conn:
                try:
                    conn.rollback()
                except:
                    pass
            return False

    def get_system_status(self, service_name=None):
        try:
            conn = self._get_connection()
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            if service_name:
                cursor.execute('SELECT * FROM system_status WHERE service_name = ?', (service_name,))
                row = cursor.fetchone()
                if row:
                    return {'service_name': row['service_name'], 'timestamp': row['timestamp'], 'status': row['status'], 'metrics': row['metrics']}
                return None
            else:
                cursor.execute('SELECT * FROM system_status')
                return [{'service_name': r['service_name'], 'timestamp': r['timestamp'], 'status': r['status'], 'metrics': r['metrics']} for r in cursor.fetchall()]
        except Exception as e:
            return []

    def save_system_metrics(self, metrics):
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO system_metrics (
                    timestamp, cpu_percent, memory_percent, memory_used_mb, 
                    memory_available_mb, disk_percent, disk_used_gb, 
                    network_sent_mb, network_recv_mb, active_connections, thread_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                metrics.get('timestamp', time.time()), metrics.get('cpu_percent'), metrics.get('memory_percent'),
                metrics.get('memory_used_mb'), metrics.get('memory_available_mb'), metrics.get('disk_percent'),
                metrics.get('disk_used_gb'), metrics.get('network_sent_mb'), metrics.get('network_recv_mb'),
                metrics.get('active_connections'), metrics.get('thread_count')
            ))
            conn.commit()
            return True
        except Exception as e:
            conn = self._get_connection()
            conn.rollback()
            return False

    def get_system_metrics(self, limit=100):
        try:
            conn = self._get_connection()
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM system_metrics ORDER BY timestamp DESC LIMIT ?', (limit,))
            return [{
                'timestamp': r['timestamp'], 'cpu_percent': r['cpu_percent'], 'memory_percent': r['memory_percent'],
                'memory_used_mb': r['memory_used_mb'], 'memory_available_mb': r['memory_available_mb'],
                'disk_percent': r['disk_percent'], 'disk_used_gb': r['disk_used_gb'],
                'network_sent_mb': r['network_sent_mb'], 'network_recv_mb': r['network_recv_mb'],
                'active_connections': r['active_connections'], 'thread_count': r['thread_count']
            } for r in cursor.fetchall()]
        except Exception as e:
            return []

    # 这里需要保留，因为在 /api/stats/summary 中被使用
    def get_blacklist_count(self):
        """获取黑名单总数"""
        conn = None
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM blacklist WHERE status = '封禁中'")
            return cursor.fetchone()[0]
        except Exception as e:
            return 0

    def get_block_count(self):
        """获取拦截总数"""
        conn = None
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute('SELECT COUNT(*) FROM block_logs')
            return cursor.fetchone()[0]
        except Exception as e:
            return 0

    # ========== 命令队列操作 ==========

    def add_command(self, command_type, command_data, max_retries=5):
        conn = None
        for attempt in range(max_retries):
            try:
                conn = self._get_connection()
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO command_queue (timestamp, command_type, command_data, status)
                    VALUES (?, ?, ?, ?)
                ''', (time.time(), command_type, command_data, 'pending'))
                conn.commit()
                return cursor.lastrowid
            except sqlite3.OperationalError as e:
                if 'locked' in str(e).lower():
                    if attempt < max_retries - 1:
                        time.sleep(0.1 * (attempt + 1))
                        continue
                    else:
                        if conn: conn.rollback()
                        raise
                else:
                    if conn: conn.rollback()
                    raise
            except Exception as e:
                if conn: conn.rollback()
                raise
        return None

    def get_pending_commands(self, limit=10):
        conn = None
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM command_queue 
                WHERE status = 'pending' 
                ORDER BY timestamp ASC 
                LIMIT ?
            ''', (limit,))
            return [{'id': r['id'], 'timestamp': r['timestamp'], 'command_type': r['command_type'], 
                     'command_data': r['command_data'], 'status': r['status']} for r in cursor.fetchall()]
        except Exception as e:
            return []

    def mark_command_processed(self, command_id):
        conn = None
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("UPDATE command_queue SET status = 'processed', processed_at = ? WHERE id = ?", (time.time(), command_id))
            conn.commit()
            return cursor.rowcount > 0
        except Exception as e:
            if conn: conn.rollback()
            return False

    def delete_command(self, command_id):
        conn = None
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute('DELETE FROM command_queue WHERE id = ?', (command_id,))
            conn.commit()
            return cursor.rowcount > 0
        except Exception as e:
            if conn: conn.rollback()
            return False


def create_db_manager(db_path=None):
    if db_path is None:
        db_path = 'backend/data/security.db'
    return DatabaseManager(db_path)