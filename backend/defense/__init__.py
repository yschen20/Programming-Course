import os
import sys
import time
import json
import logging
import threading
from datetime import datetime
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Callable

logger = logging.getLogger(__name__)


@dataclass
class DefenseConfig:
    enabled: bool = True
    auto_block: bool = True
    block_duration: int = 3600
    confidence_threshold: float = 0.7
    rate_limit_threshold: int = 100
    ip_whitelist: List[str] = field(default_factory=list)
    attack_type_block: Dict[str, bool] = field(default_factory=lambda: {
        'DDoS攻击': True,
        '端口扫描': True,
        'SQL注入': True,
        '暴力破解': True,
        'XSS攻击': False,
        '命令注入': True,
        'ARP欺骗': True,
    })


@dataclass
class BlockRecord:
    ip: str
    reason: str
    attack_type: str
    confidence: float
    blocked_at: float
    expires_at: float
    manual: bool = False


class DefenseManager:
    """防御管理器 - 实现实时拦截、策略管理和自动响应"""
    
    def __init__(self, db_manager=None, capture=None):
        self.db_manager = db_manager
        self.capture = capture  # 网络抓包实例引用
        self.blocked_ips: Dict[str, BlockRecord] = {}
        self.block_history: List[BlockRecord] = []
        self.lock = threading.Lock()
        
        self.config = DefenseConfig()
        
        self.callbacks: List[Callable] = []
        
        self.stats = {
            'total_blocks': 0,
            'auto_blocks': 0,
            'manual_blocks': 0,
            'expired_blocks': 0,
            'blocked_ips_count': 0
        }
        
        self._cleanup_thread = None
        self._running = False
    
    def start(self):
        """启动防御管理器"""
        self._running = True
        
        # 从数据库加载白名单
        if self.db_manager:
            try:
                # 获取所有黑名单记录（包括白名单）
                all_records = self.db_manager.get_blacklist(active_only=False)
                whitelist_count = 0
                
                for item in all_records:
                    status = getattr(item, 'status', '封禁中')
                    if status == 'whitelist':
                        ip = getattr(item, 'ip', '')
                        if ip:
                            self.config.ip_whitelist.append(ip)
                            whitelist_count += 1
                
                if whitelist_count > 0:
                    logger.info(f"从数据库加载了 {whitelist_count} 个白名单记录")
            except Exception as e:
                logger.error(f"从数据库加载白名单失败: {e}")
        
        # 从数据库加载未过期的黑名单
        if self.db_manager:
            try:
                blacklist = self.db_manager.get_blacklist()
                now = time.time()
                loaded_count = 0
                expired_count = 0
                
                for item in blacklist:
                    # 检查是否是封禁状态
                    status = getattr(item, 'status', '封禁中')
                    expire_time = getattr(item, 'expire_time', 0)
                    ip = getattr(item, 'ip', '')
                    
                    if status == '封禁中':
                        if expire_time > now:
                            # 未过期，恢复拦截
                            reason = getattr(item, 'reason', '从数据库加载')
                            
                            if ip:
                                duration = int(expire_time - now)
                                self.block_ip(
                                    ip=ip,
                                    reason=reason,
                                    attack_type='手动拦截',
                                    duration=duration,
                                    manual=True
                                )
                                loaded_count += 1
                        else:
                            # 已过期，解除拦截并更新状态
                            if ip:
                                self.unblock_ip(ip)
                                # 更新数据库状态
                                try:
                                    conn = self.db_manager._get_connection()
                                    cursor = conn.cursor()
                                    cursor.execute('''
                                        UPDATE blacklist 
                                        SET status = '已过期' 
                                        WHERE ip = ? AND status = '封禁中'
                                    ''', (ip,))
                                    conn.commit()
                                    expired_count += 1
                                except Exception as db_error:
                                    logger.error(f"更新过期黑名单状态失败: {db_error}")
                
                if loaded_count > 0:
                    logger.info(f"从数据库加载了 {loaded_count} 个未过期的黑名单记录")
                if expired_count > 0:
                    logger.info(f"已清理 {expired_count} 个过期的黑名单记录")
            except Exception as e:
                logger.error(f"从数据库加载黑名单失败: {e}")
        
        self._cleanup_thread = threading.Thread(target=self._cleanup_expired_blocks, daemon=True)
        self._cleanup_thread.start()
        logger.info("防御管理器已启动")
    
    def stop(self):
        """停止防御管理器"""
        self._running = False
        if self._cleanup_thread:
            self._cleanup_thread.join(timeout=2)
        logger.info("防御管理器已停止")
    
    def register_callback(self, callback: Callable):
        """注册回调函数 - 当发生拦截时调用"""
        self.callbacks.append(callback)
    
    def unregister_callback(self, callback: Callable):
        """注销回调函数"""
        if callback in self.callbacks:
            self.callbacks.remove(callback)
    
    def _notify_callbacks(self, block_record: BlockRecord):
        """通知所有回调函数"""
        for callback in self.callbacks:
            try:
                callback(block_record)
            except Exception as e:
                logger.error(f"执行拦截回调时出错: {e}")
    
    def is_blocked(self, ip: str) -> bool:
        """检查IP是否被拦截"""
        if ip in self.config.ip_whitelist:
            return False
        
        with self.lock:
            if ip in self.blocked_ips:
                record = self.blocked_ips[ip]
                if time.time() < record.expires_at:
                    return True
                else:
                    del self.blocked_ips[ip]
                    self.stats['expired_blocks'] += 1
                    self.stats['blocked_ips_count'] = len(self.blocked_ips)
        return False
    
    def block_ip(self, ip: str, reason: str, attack_type: str = 'Unknown', 
                 confidence: float = 0.0, duration: int = None, manual: bool = False) -> bool:
        """拦截IP"""
        if ip in self.config.ip_whitelist:
            logger.info(f"IP {ip} 在白名单中，跳过拦截")
            return False
        
        if not self.config.enabled:
            logger.info(f"防御已禁用，跳过拦截 {ip}")
            return False
        
        duration = duration or self.config.block_duration
        
        with self.lock:
            if ip in self.blocked_ips:
                existing = self.blocked_ips[ip]
                if time.time() < existing.expires_at:
                    existing.expires_at = time.time() + duration
                    existing.reason = reason
                    logger.info(f"已更新IP {ip} 的拦截信息，有效期延长至 {duration}秒")
                    return True
            
            now = time.time()
            record = BlockRecord(
                ip=ip,
                reason=reason,
                attack_type=attack_type,
                confidence=confidence,
                blocked_at=now,
                expires_at=now + duration,
                manual=manual
            )
            self.blocked_ips[ip] = record
            self.block_history.append(record)
            
            self.stats['total_blocks'] += 1
            if manual:
                self.stats['manual_blocks'] += 1
            else:
                self.stats['auto_blocks'] += 1
            self.stats['blocked_ips_count'] = len(self.blocked_ips)
        
        if self.db_manager:
            try:
                # 只对非手动操作保存日志，避免重复记录
                if not manual:
                    self._save_block_log(record)
                    # 对于非手动拦截，也写入blacklist表，确保前端能看到
                    from database.models import Blacklist
                    blacklist_item = Blacklist(
                        ip=ip,
                        reason=reason,
                        create_time=record.blocked_at,
                        expire_time=record.expires_at,
                        status='封禁中'
                    )
                    self.db_manager.add_to_blacklist(blacklist_item)
                    logger.info(f"已将自动拦截的IP {ip} 写入blacklist表")
            except Exception as e:
                logger.error(f"保存拦截日志失败: {e}")
        
        self._notify_callbacks(record)
        
        # 调用系统防火墙进行实际拦截
        try:
            import subprocess
            import platform
            import ipaddress
            
            # 验证IP格式
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                logger.error(f"无效的IP地址: {ip}")
                return False
            
            os_type = platform.system()
            
            if os_type == 'Linux':
                # 根据IP版本选择合适的防火墙工具
                try:
                    import ipaddress
                    addr = ipaddress.ip_address(ip)
                    cmd_tool = "ip6tables" if addr.version == 6 else "iptables"
                    # 【修复】：无论是否存在，先尝试删除（静默忽略错误），再插入，确保规则绝对唯一
                    subprocess.run([cmd_tool, "-D", "INPUT", "-s", ip, "-j", "DROP"], stderr=subprocess.DEVNULL, check=False)
                    subprocess.run([cmd_tool, "-D", "FORWARD", "-s", ip, "-j", "DROP"], stderr=subprocess.DEVNULL, check=False)

                    subprocess.run([cmd_tool, "-I", "INPUT", "-s", ip, "-j", "DROP"], check=False)
                    subprocess.run([cmd_tool, "-I", "FORWARD", "-s", ip, "-j", "DROP"], check=False)
                    logger.info(f"已通过 {cmd_tool} 拦截 IP: {ip}")
                except ValueError:
                    # IP地址格式错误，使用iptables作为默认
                    # 【修复】：无论是否存在，先尝试删除（静默忽略错误），再插入，确保规则绝对唯一
                    subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], stderr=subprocess.DEVNULL, check=False)
                    subprocess.run(["iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP"], stderr=subprocess.DEVNULL, check=False)

                    subprocess.run(["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"], check=False)
                    subprocess.run(["iptables", "-I", "FORWARD", "-s", ip, "-j", "DROP"], check=False)
                    logger.info(f"已通过 iptables 拦截 IP: {ip}")
            elif os_type == 'Windows':
                # Windows 环境下调用 netsh 拦截
                subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule", f"name=BlockIP-{ip}", "dir=in", "action=block", f"remoteip={ip}"], check=False)
                logger.info(f"已通过 Windows 防火墙拦截 IP: {ip}")
            else:
                logger.warning(f"不支持的操作系统 {os_type}，无法进行网络拦截")
        except Exception as e:
            logger.error(f"执行防火墙命令时出错: {e}")
        
        logger.warning(f"已拦截IP: {ip}, 原因: {reason}, 攻击类型: {attack_type}, "
                     f"置信度: {confidence:.2f}, 有效期: {duration}秒")
        return True
    
    def unblock_ip(self, ip: str) -> bool:
        """手动解除IP拦截"""
        removed_from_memory = False
        
        # 从内存中移除IP
        with self.lock:
            if ip in self.blocked_ips:
                del self.blocked_ips[ip]
                self.stats['blocked_ips_count'] = len(self.blocked_ips)
                removed_from_memory = True
                logger.info(f"已从内存中解除IP {ip} 的拦截")
        
        # 从快速黑名单中移除IP（移出锁的范围，避免死锁）
        if self.capture and hasattr(self.capture, 'remove_from_fast_drop'):
            try:
                self.capture.remove_from_fast_drop(ip)
            except Exception as e:
                logger.error(f"从快速黑名单移除IP时出错: {e}")
        
        # 调用系统防火墙解除拦截（无论内存中是否存在）
        try:
            import subprocess
            import platform
            import ipaddress
            
            # 验证IP格式
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                logger.error(f"无效的IP地址: {ip}")
                return removed_from_memory
            
            os_type = platform.system()
            
            if os_type == 'Linux':
                # 根据IP版本选择合适的防火墙工具
                try:
                    import ipaddress
                    addr = ipaddress.ip_address(ip)
                    cmd_tool = "ip6tables" if addr.version == 6 else "iptables"
                    subprocess.run([cmd_tool, "-D", "INPUT", "-s", ip, "-j", "DROP"], check=False)
                    # 【修复】：解除FORWARD链的拦截
                    subprocess.run([cmd_tool, "-D", "FORWARD", "-s", ip, "-j", "DROP"], check=False)
                    logger.info(f"已从 {cmd_tool} 中解除 IP: {ip}")
                except ValueError:
                    # IP地址格式错误，使用iptables作为默认
                    subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=False)
                    # 【修复】：解除FORWARD链的拦截
                    subprocess.run(["iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP"], check=False)
                    logger.info(f"已从 iptables 中解除 IP: {ip}")
            elif os_type == 'Windows':
                # Windows 环境下从防火墙中移除规则
                subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name=BlockIP-{ip}"], check=False)
                logger.info(f"已从 Windows 防火墙中解除 IP: {ip}")
        except Exception as e:
            logger.error(f"执行防火墙解除命令时出错: {e}")
        
        return removed_from_memory
    
    def get_blocked_ips(self) -> List[Dict]:
        """获取当前被拦截的IP列表"""
        with self.lock:
            now = time.time()
            result = []
            for ip, record in list(self.blocked_ips.items()):
                if time.time() < record.expires_at:
                    result.append({
                        'ip': ip,
                        'reason': record.reason,
                        'attack_type': record.attack_type,
                        'confidence': record.confidence,
                        'blocked_at': record.blocked_at,
                        'expires_at': record.expires_at,
                        'remaining_seconds': int(record.expires_at - now),
                        'manual': record.manual
                    })
                else:
                    del self.blocked_ips[ip]
                    self.stats['expired_blocks'] += 1
            return result
    
    def get_block_history(self, limit: int = 100) -> List[Dict]:
        """获取拦截历史"""
        with self.lock:
            sorted_history = sorted(
                self.block_history,
                key=lambda x: x.blocked_at,
                reverse=True
            )
            return [
                {
                    'ip': r.ip,
                    'reason': r.reason,
                    'attack_type': r.attack_type,
                    'confidence': r.confidence,
                    'blocked_at': r.blocked_at,
                    'expires_at': r.expires_at,
                    'manual': r.manual
                }
                for r in sorted_history[:limit]
            ]
    
    def _save_block_log(self, record: BlockRecord):
        """保存拦截日志到数据库"""
        if hasattr(self.db_manager, 'insert_block_log'):
            try:
                from database.models import BlockLog
                log = BlockLog(
                    timestamp=record.blocked_at,
                    ip=record.ip,
                    action='block',
                    result='success' if record.expires_at > time.time() else 'expired',
                    rule=record.reason
                )
                self.db_manager.insert_block_log(log)
            except Exception as e:
                logger.error(f"插入拦截日志到数据库失败: {e}")
    
    def _cleanup_expired_blocks(self):
        """定期清理过期的拦截记录"""
        while self._running:
            time.sleep(60)
            expired = []
            try:
                with self.lock:
                    now = time.time()
                    for ip, record in list(self.blocked_ips.items()):
                        if now >= record.expires_at:
                            expired.append(ip)
                    
                    for ip in expired:
                        del self.blocked_ips[ip]
                        self.stats['expired_blocks'] += 1
                    
                    if expired:
                        self.stats['blocked_ips_count'] = len(self.blocked_ips)
                        logger.info(f"已清理 {len(expired)} 个过期拦截记录")
                    
                    if len(self.block_history) > 10000:
                        self.block_history = self.block_history[-5000:]
            except Exception as e:
                logger.error(f"清理过期拦截记录时出错: {e}")
            
            # 对过期的IP执行完整的解封操作
            for ip in expired:
                try:
                    # 调用完整的解封方法，会解除防火墙限制
                    self.unblock_ip(ip)
                    
                    # 更新数据库状态为已过期
                    if self.db_manager:
                        # 【修复】：增加针对SQLite锁的微型重试兜底
                        import sqlite3
                        for _ in range(5):
                            try:
                                conn = self.db_manager._get_connection()
                                conn.execute('''
                                    UPDATE blacklist 
                                    SET status = '已过期' 
                                    WHERE ip = ? AND status = '封禁中'
                                ''', (ip,))
                                conn.commit()
                                logger.info(f"已将IP {ip} 的数据库状态更新为已过期")
                                break
                            except sqlite3.OperationalError:
                                time.sleep(0.2) # 避开锁冲突
                            except Exception as db_error:
                                logger.error(f"更新过期黑名单状态失败: {db_error}")
                                break
                except Exception as e:
                    logger.error(f"执行过期IP解封操作时出错: {e}")
    
    def should_block(self, attack_type: str, confidence: float) -> bool:
        """判断是否应该拦截"""
        if not self.config.auto_block:
            return False
        
        if confidence < self.config.confidence_threshold:
            return False
        
        return self.config.attack_type_block.get(attack_type, True)
    
    def process_detection_result(self, src_ip: str, attack_type: str, confidence: float, 
                                 details: str = "") -> bool:
        """处理AI检测结果，自动拦截"""
        if not self.should_block(attack_type, confidence):
            return False
        
        reason = f"AI检测到{attack_type}"
        if details:
            reason += f": {details}"
        
        return self.block_ip(
            ip=src_ip,
            reason=reason,
            attack_type=attack_type,
            confidence=confidence
        )
    
    def get_stats(self) -> Dict:
        """获取防御统计信息"""
        with self.lock:
            return {
                **self.stats,
                'current_blocked': len(self.blocked_ips),
                'whitelist_count': len(self.config.ip_whitelist),
                'enabled': self.config.enabled,
                'auto_block': self.config.auto_block
            }
    
    def update_config(self, config: DefenseConfig):
        """更新防御配置"""
        self.config = config
        logger.info("防御配置已更新")
    
    def add_to_whitelist(self, ip: str):
        """添加到白名单"""
        if ip not in self.config.ip_whitelist:
            self.config.ip_whitelist.append(ip)
            if ip in self.blocked_ips:
                self.unblock_ip(ip)
            logger.info(f"已将IP {ip} 添加到白名单")
    
    def remove_from_whitelist(self, ip: str):
        """从白名单移除"""
        if ip in self.config.ip_whitelist:
            self.config.ip_whitelist.remove(ip)
            logger.info(f"已将IP {ip} 从白名单移除")
    
    def get_config(self) -> Dict:
        """获取当前配置"""
        return {
            'enabled': self.config.enabled,
            'auto_block': self.config.auto_block,
            'block_duration': self.config.block_duration,
            'confidence_threshold': self.config.confidence_threshold,
            'rate_limit_threshold': self.config.rate_limit_threshold,
            'ip_whitelist': self.config.ip_whitelist.copy(),
            'attack_type_block': self.config.attack_type_block.copy()
        }
    
    def set_attack_type_block(self, attack_type: str, enabled: bool):
        """设置特定攻击类型的拦截开关"""
        self.config.attack_type_block[attack_type] = enabled
        logger.info(f"已设置攻击类型 {attack_type} 拦截: {enabled}")


class RateLimiter:
    """基于IP的速率限制器"""
    
    def __init__(self, max_requests: int = 100, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests: Dict[str, List[float]] = defaultdict(list)
        self.lock = threading.Lock()
    
    def is_allowed(self, ip: str) -> bool:
        """检查请求是否允许"""
        now = time.time()
        
        with self.lock:
            if ip not in self.requests:
                self.requests[ip] = []
            
            self.requests[ip] = [
                t for t in self.requests[ip]
                if now - t < self.window_seconds
            ]
            
            if len(self.requests[ip]) >= self.max_requests:
                return False
            
            self.requests[ip].append(now)
            return True
    
    def get_request_count(self, ip: str) -> int:
        """获取IP在窗口期内的请求数"""
        now = time.time()
        with self.lock:
            if ip not in self.requests:
                return 0
            return len([
                t for t in self.requests[ip]
                if now - t < self.window_seconds
            ])
    
    def cleanup(self):
        """清理过期的记录"""
        now = time.time()
        with self.lock:
            for ip in list(self.requests.keys()):
                self.requests[ip] = [
                    t for t in self.requests[ip]
                    if now - t < self.window_seconds
                ]
                if not self.requests[ip]:
                    del self.requests[ip]


def create_defense_manager(db_manager=None) -> DefenseManager:
    """创建防御管理器实例"""
    return DefenseManager(db_manager)
