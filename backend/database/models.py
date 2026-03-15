"""
数据模型定义
"""
import time


class TrafficLog:
    """流量记录模型
    
    记录网络流量的详细信息，包括源IP、目标IP、端口、协议等
    
    Attributes:
        id (int): 记录ID
        timestamp (float): 时间戳
        src_ip (str): 源IP地址
        dst_ip (str): 目标IP地址
        src_port (int): 源端口
        dst_port (int): 目标端口
        protocol (str): 协议类型
        length (int): 数据包长度
        ttl (int): 生存时间
        flags (str): TCP标志位
        feature_json (str): 特征JSON字符串
        is_anomaly (int): 是否为异常流量 (0: 正常, 1: 异常)
    """

    def __init__(self, timestamp, src_ip, dst_ip, protocol, length,
                 src_port=None, dst_port=None, ttl=None, flags=None,
                 feature_json=None, is_anomaly=0):
        """初始化流量记录
        
        Args:
            timestamp (float): 时间戳
            src_ip (str): 源IP地址
            dst_ip (str): 目标IP地址
            protocol (str): 协议类型
            length (int): 数据包长度
            src_port (int, optional): 源端口. 默认值为None
            dst_port (int, optional): 目标端口. 默认值为None
            ttl (int, optional): 生存时间. 默认值为None
            flags (str, optional): TCP标志位. 默认值为None
            feature_json (str, optional): 特征JSON字符串. 默认值为None
            is_anomaly (int, optional): 是否为异常流量. 默认值为0
        """
        self.id = None
        self.timestamp = timestamp
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        self.length = length
        self.ttl = ttl
        self.flags = flags
        self.feature_json = feature_json
        self.is_anomaly = is_anomaly

    def __repr__(self):
        """返回对象的字符串表示"""
        return f"<TrafficLog {self.src_ip}->{self.dst_ip} {self.protocol}>"

    def to_dict(self):
        """转为字典（用于API返回）
        
        Returns:
            dict: 流量记录的字典表示
        """
        return {
            'id': self.id,
            'timestamp': self.timestamp,
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'protocol': self.protocol,
            'length': self.length,
            'is_anomaly': self.is_anomaly
        }


class Alert:
    """告警记录模型
    
    记录系统检测到的异常行为告警
    
    Attributes:
        id (int): 告警ID
        timestamp (float): 告警时间戳
        level (str): 告警级别 (高危/中危/低危)
        type (str): 告警类型
        src_ip (str): 源IP地址
        dst_ip (str): 目标IP地址
        description (str): 告警描述
        status (str): 处理状态 (未处理/已处理/忽略)
        handled_time (float): 处理时间
    """

    def __init__(self, timestamp, level, type, src_ip, description,
                 dst_ip=None, status='未处理', vulnerability_type=None):
        """初始化告警记录
        
        Args:
            timestamp (float): 告警时间戳
            level (str): 告警级别 (高危/中危/低危)
            type (str): 告警类型
            src_ip (str): 源IP地址
            description (str): 告警描述
            dst_ip (str, optional): 目标IP地址. 默认值为None
            status (str, optional): 处理状态. 默认值为'未处理'
            vulnerability_type (str, optional): 漏洞类型. 默认值为None
        """
        self.id = None
        self.timestamp = timestamp
        self.level = level  # 高危/中危/低危
        self.type = type
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.description = description
        self.status = status  # 未处理/已处理/忽略
        self.vulnerability_type = vulnerability_type
        self.handled_time = None

    def __repr__(self):
        """返回对象的字符串表示"""
        return f"<Alert {self.level} {self.type} from {self.src_ip}>"

    def to_dict(self):
        """转为字典（用于API返回）
        
        Returns:
            dict: 告警记录的字典表示
        """
        return {
            'id': self.id,
            'timestamp': self.timestamp,
            'level': self.level,
            'type': self.type,
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'description': self.description,
            'status': self.status,
            'vulnerability_type': self.vulnerability_type
        }


class Blacklist:
    """黑名单模型
    
    记录被封禁的IP地址信息
    
    Attributes:
        id (int): 黑名单ID
        ip (str): IP地址
        reason (str): 封禁原因
        create_time (float): 创建时间
        expire_time (float): 过期时间
        status (str): 状态 (封禁中)
    """

    def __init__(self, ip, reason, create_time, expire_time=None):
        """初始化黑名单记录
        
        Args:
            ip (str): IP地址
            reason (str): 封禁原因
            create_time (float): 创建时间
            expire_time (float, optional): 过期时间. 默认值为None
        """
        self.id = None
        self.ip = ip
        self.reason = reason
        self.create_time = create_time
        self.expire_time = expire_time
        self.status = '封禁中'

    def __repr__(self):
        """返回对象的字符串表示"""
        return f"<Blacklist {self.ip} {self.status}>"

    def to_dict(self):
        """转为字典（用于API返回）
        
        Returns:
            dict: 黑名单记录的字典表示
        """
        return {
            'id': self.id,
            'ip': self.ip,
            'reason': self.reason,
            'create_time': self.create_time,
            'expire_time': self.expire_time,
            'status': self.status
        }


class User:
    """用户模型
    
    记录系统用户信息
    
    Attributes:
        id (int): 用户ID
        username (str): 用户名
        password (str): 密码（加密存储）
        role (str): 角色 (admin/user)
        created_at (float): 创建时间
        created_by (str): 创建者
        status (str): 状态 (正常)
    """

    def __init__(self, username, password, role='user', created_by=None):
        """初始化用户
        
        Args:
            username (str): 用户名
            password (str): 密码（加密存储）
            role (str, optional): 角色. 默认值为'user'
            created_by (str, optional): 创建者. 默认值为None
        """
        self.id = None
        self.username = username
        self.password = password  # 实际应该存加密后的密码
        self.role = role  # admin/user
        self.created_at = time.time()
        self.created_by = created_by
        self.status = '正常'

    def __repr__(self):
        """返回对象的字符串表示"""
        return f"<User {self.username} ({self.role})>"

    def to_dict(self):
        """转为字典（用于API返回）
        
        Returns:
            dict: 用户的字典表示
        """
        return {
            'id': self.id,
            'username': self.username,
            'role': self.role,
            'created_at': self.created_at,
            'created_by': self.created_by,
            'status': self.status
        }


class BlockLog:
    """拦截记录模型
    
    记录IP地址的拦截操作记录
    
    Attributes:
        id (int): 记录ID
        timestamp (float): 操作时间戳
        ip (str): IP地址
        rule (str): 规则名称
        action (str): 操作类型 (封禁/解封)
        result (str): 操作结果 (成功/失败)
        alert_id (int): 关联的告警ID
    """

    def __init__(self, timestamp, ip, action, result, rule=None, alert_id=None):
        """初始化拦截记录
        
        Args:
            timestamp (float): 操作时间戳
            ip (str): IP地址
            action (str): 操作类型 (封禁/解封)
            result (str): 操作结果 (成功/失败)
            rule (str, optional): 规则名称. 默认值为None
            alert_id (int, optional): 关联的告警ID. 默认值为None
        """
        self.id = None
        self.timestamp = timestamp
        self.ip = ip
        self.rule = rule
        self.action = action  # 封禁/解封
        self.result = result  # 成功/失败
        self.alert_id = alert_id

    def __repr__(self):
        """返回对象的字符串表示"""
        return f"<BlockLog {self.ip} {self.action}>"

    def to_dict(self):
        """转为字典（用于API返回）
        
        Returns:
            dict: 拦截记录的字典表示
        """
        return {
            'id': self.id,
            'timestamp': self.timestamp,
            'ip': self.ip,
            'rule': self.rule,
            'action': self.action,
            'result': self.result,
            'alert_id': self.alert_id
        }