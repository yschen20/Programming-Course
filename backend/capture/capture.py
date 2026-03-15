import os
import sys
import time
import threading
import queue
import json
import signal
import re
import logging
import urllib.parse  # 【新增】用于URL解码，防止攻击载荷编码绕过
from collections import OrderedDict, deque
from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP

# 添加项目路径
sys.path.append(str(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

# 导入数据库模型
from database.models import Alert

# 获取日志记录器
logger = logging.getLogger(__name__)

# 导入统一的特征提取器
try:
    from ai.ai_detector import FeatureExtractor
    _feature_extractor_available = True
except ImportError:
    _feature_extractor_available = False
    logger.warning("无法导入FeatureExtractor，将使用基本特征提取")


class LRUCache:
    """LRU缓存实现，用于限制内存使用"""
    
    def __init__(self, capacity=10000):
        self.cache = OrderedDict()
        self.capacity = capacity
        self.lock = threading.Lock()
    
    def get(self, key):
        with self.lock:
            if key not in self.cache:
                return None
            self.cache.move_to_end(key)
            return self.cache[key]
    
    def put(self, key, value):
        with self.lock:
            if key in self.cache:
                self.cache.move_to_end(key)
            self.cache[key] = value
            if len(self.cache) > self.capacity:
                self.cache.popitem(last=False)
    
    def remove(self, key):
        with self.lock:
            if key in self.cache:
                del self.cache[key]
    
    def __contains__(self, key):
        with self.lock:
            return key in self.cache
    
    def __len__(self):
        with self.lock:
            return len(self.cache)
    
    def items(self):
        with self.lock:
            return list(self.cache.items())


class NetworkCapture:
    """网络流量采集类 - 集成AI检测和数据库存储"""
    
    def __init__(self, interface=None, filter=None, packet_queue_size=10000, 
                 connection_timeout=300, max_analysis_results=10000,
                 db_manager=None, ai_detector=None, defense_manager=None):
        self.interface = interface
        self.filter = filter
        self.packet_queue = queue.Queue(maxsize=packet_queue_size)
        self.running = False
        self.capture_thread = None
        self.connections_cleanup_thread = None
        self.analysis_thread = None
        self.ai_detection_thread = None
        self.db_writer_thread = None
        self.connection_timeout = connection_timeout
        
        # 外部依赖
        self.db_manager = db_manager
        self.ai_detector = ai_detector
        self.defense_manager = defense_manager
        
        # 初始化特征提取器
        if _feature_extractor_available:
            self.feature_extractor = FeatureExtractor()
            logger.info("使用统一的FeatureExtractor进行特征提取")
        else:
            self.feature_extractor = None
            logger.warning("FeatureExtractor不可用，使用基本特征提取")
        
        # 统计信息
        self.stats = {
            'total_packets': 0,
            'tcp_packets': 0,
            'udp_packets': 0,
            'icmp_packets': 0,
            'http_packets': 0,
            'dns_packets': 0,
            'bytes_transferred': 0,
            'start_time': time.time(),
            'last_update': time.time(),
            'dropped_packets': 0,  
            'ai_detections': 0,    
            'db_inserts': 0        
        }
        
        # 滑动窗口队列，用于计算实时速率（最近5秒）
        self.sliding_window = deque()
        self.sliding_window_lock = threading.Lock()
        self.window_size = 5
        
        # 使用LRU缓存限制内存使用
        self.connections = LRUCache(10000) 
        self.analysis_results = LRUCache(max_analysis_results)
        
        # 内存级别的快速黑名单
        self.local_fast_drop_set = LRUCache(10000)
        self.fast_drop_lock = threading.Lock()
        self.fast_drop_expiry = 3600
        self.fast_drop_cleanup_thread = None
        
        # 队列
        self.analysis_queue = queue.Queue(maxsize=5000)
        self.ai_detection_queue = queue.Queue(maxsize=2000)
        self.db_write_queue = queue.Queue(maxsize=5000)
        
        self.lock = threading.Lock()
        
        try:
            from defense import RateLimiter
            self.rate_limiter = RateLimiter(max_requests=100, window_seconds=60)
        except Exception as e:
            logger.error(f"初始化速率限制器失败: {e}")
            self.rate_limiter = None
        
        self.protocol_stats = {
            'HTTP': {'requests': 0, 'responses': 0, 'methods': {}, 'status_codes': {}},
            'DNS': {'queries': 0, 'responses': 0, 'query_types': {}},
            'TCP': {'connections': 0, 'flags': {}},
            'UDP': {'packets': 0, 'ports': {}},
            'ICMP': {'packets': 0, 'types': {}}
        }

    def packet_handler(self, packet):
        """处理捕获到的数据包"""
        try:
            ip_layer = packet.getlayer(IP) or packet.getlayer(IPv6)
            arp_layer = packet.getlayer(ARP)
            
            if arp_layer:
                src_ip = arp_layer.psrc
                with self.fast_drop_lock:
                    if self.local_fast_drop_set.get(src_ip) is not None:
                        return
                
                self.stats['total_packets'] += 1
                self.stats['last_update'] = time.time()
                
                features = {
                    'timestamp': time.time(),
                    'packet_length': len(packet),
                    'protocol': 'ARP',
                    'src_ip': src_ip,
                    'dst_ip': arp_layer.pdst,
                    'arp_op': arp_layer.op,
                    'bytes_sent': len(packet),
                    'bytes_recv': 0,
                    'packets': 1
                }
                
                self._put_to_queue(self.analysis_queue, features, 'analysis_queue')
                
                if self.ai_detector:
                    self._put_to_queue(self.ai_detection_queue, features, 'ai_detection_queue')
                else:
                    self._put_to_queue(self.db_write_queue, features, 'db_write_queue')
                return
                
            elif ip_layer:
                src_ip = ip_layer.src
            else:
                return
            
            with self.fast_drop_lock:
                if src_ip in self.local_fast_drop_set:
                    return
            
            self.stats['total_packets'] += 1
            self.stats['last_update'] = time.time()

            features = {
                'timestamp': time.time(),
                'packet_length': len(packet),
                'protocol': 'Other',
                'src_ip': src_ip,
                'dst_ip': ip_layer.dst,
                'bytes_sent': len(packet),
                'bytes_recv': 0,
                'packets': 1
            }
            
            if isinstance(ip_layer, IP):
                features['ttl'] = ip_layer.ttl
                features['ip_version'] = ip_layer.version
                features['ip_id'] = ip_layer.id
                features['ip_flags'] = str(ip_layer.flags)
                features['ip_frag'] = ip_layer.frag
            elif isinstance(ip_layer, IPv6):
                features['ttl'] = ip_layer.hlim
                features['ip_version'] = 6
                features['ip_id'] = 0
                features['ip_flags'] = ''
                features['ip_frag'] = 0

            tcp_layer = packet.getlayer(TCP)
            udp_layer = packet.getlayer(UDP)
            icmp_layer = packet.getlayer(ICMP)
            
            if tcp_layer is not None:
                features['protocol'] = 'TCP'
                features['src_port'] = tcp_layer.sport
                features['dst_port'] = tcp_layer.dport
                features['seq'] = tcp_layer.seq
                features['ack'] = tcp_layer.ack
                features['flags'] = int(tcp_layer.flags)
                features['window'] = tcp_layer.window
                features['urgptr'] = tcp_layer.urgptr
                self.stats['tcp_packets'] += 1

                with self.lock:
                    flags_str = features['flags']
                    if flags_str not in self.protocol_stats['TCP']['flags']:
                        self.protocol_stats['TCP']['flags'][flags_str] = 0
                    self.protocol_stats['TCP']['flags'][flags_str] += 1

                payload = bytes(tcp_layer.payload) if tcp_layer.payload else b''
                if payload:
                    payload_start = payload[:20].upper() if len(payload) >= 4 else payload.upper()
                    if payload_start.startswith(b'GET ') or payload_start.startswith(b'POST ') or \
                       payload_start.startswith(b'PUT ') or payload_start.startswith(b'DELETE ') or \
                       payload_start.startswith(b'HEAD ') or payload_start.startswith(b'OPTIONS ') or \
                       payload_start.startswith(b'HTTP/'):
                        features['application_protocol'] = 'HTTP'
                        features['is_http'] = True
                        self.stats['http_packets'] += 1
                        
                        method_end = payload.find(b' ')
                        if method_end > 0:
                            features['http_method'] = payload[:method_end].decode('utf-8', errors='ignore')
                        else:
                            features['http_method'] = 'Unknown'
                        
                        status_match = re.search(rb'HTTP/\d\.\d\s+(\d+)', payload_start)
                        if status_match:
                            features['http_status_code'] = int(status_match.group(1))
                        
                        features['payload'] = payload
                        
                        with self.lock:
                            method = features.get('http_method', 'Unknown').upper()
                            valid_methods = {'GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH', 'TRACE', 'CONNECT'}
                            if method not in valid_methods:
                                method = 'UNKNOWN_METHOD'
                            if method not in self.protocol_stats['HTTP']['methods']:
                                self.protocol_stats['HTTP']['methods'][method] = 0
                            self.protocol_stats['HTTP']['methods'][method] += 1
                            self.protocol_stats['HTTP']['requests'] += 1
                    else:
                        features['is_http'] = False
                        features['payload'] = payload
                else:
                    features['is_http'] = False
                    features['payload'] = b''

            elif udp_layer is not None:
                features['protocol'] = 'UDP'
                features['src_port'] = udp_layer.sport
                features['dst_port'] = udp_layer.dport
                features['udp_length'] = udp_layer.len
                self.stats['udp_packets'] += 1

                with self.lock:
                    port = features['dst_port']
                    if port not in self.protocol_stats['UDP']['ports']:
                        self.protocol_stats['UDP']['ports'][port] = 0
                    self.protocol_stats['UDP']['ports'][port] += 1

                if features['src_port'] == 53 or features['dst_port'] == 53:
                    features['application_protocol'] = 'DNS'
                    features['is_dns'] = True
                    self.stats['dns_packets'] += 1
                else:
                    features['is_dns'] = False
                    payload = bytes(udp_layer.payload) if udp_layer.payload else b''
                    features['payload'] = payload

            elif icmp_layer is not None:
                features['protocol'] = 'ICMP'
                features['icmp_type'] = icmp_layer.type
                features['icmp_code'] = icmp_layer.code
                self.stats['icmp_packets'] += 1

                with self.lock:
                    icmp_type = features['icmp_type']
                    if icmp_type not in self.protocol_stats['ICMP']['types']:
                        self.protocol_stats['ICMP']['types'][icmp_type] = 0
                    self.protocol_stats['ICMP']['types'][icmp_type] += 1

            # 统计字节数并计算滑动窗口
            packet_size = len(packet)
            self.stats['bytes_transferred'] += packet_size
            
            current_time = time.time()
            with self.sliding_window_lock:
                self.sliding_window.append((current_time, packet_size))
                cutoff_time = current_time - self.window_size
                while self.sliding_window and self.sliding_window[0][0] < cutoff_time:
                    self.sliding_window.popleft()

            # 连接跟踪 (TCP/UDP)
            if 'src_ip' in features and 'dst_ip' in features and 'src_port' in features and 'dst_port' in features:
                conn_key = f"{features['src_ip']}:{features['src_port']}->{features['dst_ip']}:{features['dst_port']}"
                with self.lock:
                    conn_info = self.connections.get(conn_key)
                    if conn_info is None:
                        conn_info = {
                            'start_time': features['timestamp'],
                            'last_activity': features['timestamp'],
                            'packets': 0,
                            'bytes': 0,
                            'protocol': features['protocol'],
                            'src_ip': features['src_ip'],
                            'src_port': features['src_port'],
                            'dst_ip': features['dst_ip'],
                            'dst_port': features['dst_port']
                        }
                        self.connections.put(conn_key, conn_info)
                        if features['protocol'] == 'TCP':
                            self.protocol_stats['TCP']['connections'] += 1
                    
                    conn_info['last_activity'] = features['timestamp']
                    conn_info['packets'] += 1
                    conn_info['bytes'] += len(packet)
                    self.connections.put(conn_key, conn_info)
                    
                    conn_duration = features['timestamp'] - conn_info['start_time']
                    
                    # 【核心修复1】：将连接级别的统计信息赋予 features，确保 AI 提取到的特征是宏观会话特征，而非单包特征
                    features['connection_count'] = conn_info['packets']
                    features['bytes_transferred'] = conn_info['bytes']
                    
                    if conn_duration > 0:
                        features['connection_duration'] = conn_duration
                        features['packet_rate'] = conn_info['packets'] / conn_duration
                        features['byte_rate'] = conn_info['bytes'] / conn_duration
                    else:
                        features['connection_duration'] = 0.0
                        features['packet_rate'] = 0.0
                        features['byte_rate'] = 0.0

            self._put_to_queue(self.analysis_queue, features, 'analysis_queue')
            
            if self.ai_detector:
                self._put_to_queue(self.ai_detection_queue, features, 'ai_detection_queue')
            else:
                self._put_to_queue(self.db_write_queue, features, 'db_write_queue')
            
        except Exception as e:
            logger.error(f"处理数据包时出错: {e}")
    
    def _put_to_queue(self, q, item, queue_name):
        try:
            q.put(item, block=False)
        except queue.Full:
            self.stats['dropped_packets'] += 1
            if self.stats['dropped_packets'] % 100 == 0:
                logger.warning(f"{queue_name} 队列已满，已丢弃 {self.stats['dropped_packets']} 个数据包")

    def _cleanup_connections(self):
        while self.running:
            time.sleep(60)
            current_time = time.time()
            with self.lock:
                all_connections = self.connections.items()
                to_remove = []
                for conn_key, conn_info in all_connections:
                    if current_time - conn_info['last_activity'] > self.connection_timeout:
                        to_remove.append(conn_key)
                for conn_key in to_remove:
                    self.connections.remove(conn_key)
    
    def _cleanup_fast_drop(self):
        while self.running:
            time.sleep(300)
            current_time = time.time()
            with self.fast_drop_lock:
                to_remove = []
                for ip, add_time in self.local_fast_drop_set.items():
                    if current_time - add_time > self.fast_drop_expiry:
                        to_remove.append(ip)
                for ip in to_remove:
                    self.local_fast_drop_set.remove(ip)

    def _analyze_traffic(self):
        while self.running:
            try:
                features = self.analysis_queue.get(block=True, timeout=1)
                src_ip = features.get('src_ip', 'Unknown')
                ip_analysis = self.analysis_results.get(src_ip)
            
                if ip_analysis is None:
                    ip_analysis = {
                        'total_packets': 0,
                        'total_bytes': 0,
                        'protocols': {},
                        'ports': {},
                        'syn_count': 0,
                        'rst_count': 0,
                        'syn_ack_count': 0,
                        'failed_connection_count': 0,
                        'last_activity': features['timestamp']
                    }
            
                ip_analysis['total_packets'] += 1
                ip_analysis['total_bytes'] += features['packet_length']
                ip_analysis['last_activity'] = features['timestamp']
            
                protocol = features.get('protocol', 'Other')
                if protocol not in ip_analysis['protocols']:
                    ip_analysis['protocols'][protocol] = 0
                ip_analysis['protocols'][protocol] += 1
            
                dst_port = features.get('dst_port', 0)
                if dst_port > 0:
                    if dst_port not in ip_analysis['ports']:
                        ip_analysis['ports'][dst_port] = 0
                    ip_analysis['ports'][dst_port] += 1
            
                if features.get('protocol') == 'TCP' and 'flags' in features:
                    flags = features['flags']
                    if flags & 0x02:
                        ip_analysis['syn_count'] += 1
                    if flags & 0x04:
                        ip_analysis['rst_count'] += 1
                    if flags & 0x12 == 0x12:
                        ip_analysis['syn_ack_count'] += 1
                    if flags & 0x02 and not (flags & 0x10):
                        ip_analysis['failed_connection_count'] += 1
            
                self.analysis_results.put(src_ip, ip_analysis)
                    
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"分析流量时出错: {e}")

    def _ai_detection_worker(self):
        batch_size = 50
        batch = []
        last_flush_time = time.time()
        
        while self.running:
            try:
                features = self.ai_detection_queue.get(block=True, timeout=0.1)
                batch.append(features)
                
                current_time = time.time()
                if len(batch) >= batch_size or (current_time - last_flush_time) > 0.5:
                    self._process_ai_batch(batch)
                    batch = []
                    last_flush_time = current_time
                    
            except queue.Empty:
                if batch:
                    self._process_ai_batch(batch)
                    batch = []
                    last_flush_time = time.time()
                continue
            except Exception as e:
                pass
                
        if batch:
            self._process_ai_batch(batch)
    
    def _process_ai_batch(self, batch):
        if not batch:
            return
            
        valid_items = []
        for features in batch:
            valid_items.append(features)
            
        try:
            if self.ai_detector and hasattr(self.ai_detector, 'detect_anomaly_batch'):
                results = self.ai_detector.detect_anomaly_batch(valid_items)
            elif self.ai_detector:
                results = [self.ai_detector.detect_anomaly(f) for f in valid_items]
            else:
                results = [{'is_anomaly': False} for _ in valid_items]
            
            self.stats['ai_detections'] += len(results)
            
            for i, result in enumerate(results):
                original_features = valid_items[i]
                is_anomaly = result.get('is_anomaly', False)
                original_features['is_anomaly'] = 1 if is_anomaly else 0
                
                if is_anomaly and self.db_manager:
                    try:
                        vulnerability_type = self._analyze_vulnerability_type(original_features)
                        
                        alert = Alert(
                            timestamp=original_features.get('timestamp', time.time()),
                            level='中危',
                            type='AI检测异常',
                            src_ip=original_features.get('src_ip', 'Unknown'),
                            description=f'AI检测到异常流量: {original_features.get("src_ip", "Unknown")} -> {original_features.get("dst_ip", "Unknown")}',
                            dst_ip=original_features.get('dst_ip', 'Unknown'),
                            vulnerability_type=vulnerability_type
                        )
                        self.db_manager.insert_alert(alert)
                    except Exception as e:
                        logger.error(f"生成告警时出错: {e}")
                
                self._put_to_queue(self.db_write_queue, original_features, 'db_write_queue')
                
        except Exception as e:
            logger.error(f"批量AI检测时出错，执行降级处理: {e}")
            for original_features in valid_items:
                original_features['is_anomaly'] = 0
                self._put_to_queue(self.db_write_queue, original_features, 'db_write_queue')

    def _db_writer_worker(self):
        batch_size = 100
        batch = []
        last_flush_time = time.time()
        
        while self.running:
            try:
                features = self.db_write_queue.get(block=True, timeout=0.1)
                batch.append(features)
                
                current_time = time.time()
                if len(batch) >= batch_size or (current_time - last_flush_time) > 1.0:
                    self._flush_batch_to_db(batch)
                    batch = []
                    last_flush_time = current_time
                    
            except queue.Empty:
                if batch:
                    self._flush_batch_to_db(batch)
                    batch = []
                    last_flush_time = time.time()
                continue
                
        if batch:
            self._flush_batch_to_db(batch)
    
    def _flush_batch_to_db(self, batch):
        if not batch or not self.db_manager:
            return
        try:
            traffic_logs = []
            for features in batch:
                try:
                    from database.models import TrafficLog
                    log = TrafficLog(
                        timestamp=features.get('timestamp', time.time()),
                        src_ip=features.get('src_ip', '0.0.0.0'),
                        dst_ip=features.get('dst_ip', '0.0.0.0'),
                        protocol=features.get('protocol', 'Other'),
                        length=features.get('packet_length', 0),
                        src_port=features.get('src_port'),
                        dst_port=features.get('dst_port'),
                        ttl=features.get('ttl'),
                        flags=str(features.get('flags', '')) if 'flags' in features else None,
                        is_anomaly=features.get('is_anomaly', 0)
                    )
                    traffic_logs.append(log)
                except Exception:
                    pass
            
            if hasattr(self.db_manager, 'insert_traffic_batch'):
                inserted_count = self.db_manager.insert_traffic_batch(traffic_logs)
                self.stats['db_inserts'] += inserted_count
        except Exception as e:
            logger.error(f"批量写入数据库失败: {e}")

    def start_capture(self):
        self.running = True
        self.connections_cleanup_thread = threading.Thread(target=self._cleanup_connections)
        self.connections_cleanup_thread.daemon = True
        self.connections_cleanup_thread.start()
        
        self.fast_drop_cleanup_thread = threading.Thread(target=self._cleanup_fast_drop)
        self.fast_drop_cleanup_thread.daemon = True
        self.fast_drop_cleanup_thread.start()
        
        self.analysis_thread = threading.Thread(target=self._analyze_traffic)
        self.analysis_thread.daemon = True
        self.analysis_thread.start()
        
        if self.ai_detector:
            self.ai_detection_thread = threading.Thread(target=self._ai_detection_worker)
            self.ai_detection_thread.daemon = True
            self.ai_detection_thread.start()
        
        if self.db_manager:
            self.db_writer_thread = threading.Thread(target=self._db_writer_worker)
            self.db_writer_thread.daemon = True
            self.db_writer_thread.start()
        
        self.capture_thread = threading.Thread(target=self._capture_loop)
        self.capture_thread.daemon = True
        self.capture_thread.start()

    def _capture_loop(self):
        from scapy.all import AsyncSniffer
        sniffer = AsyncSniffer(
            iface=self.interface, 
            filter=self.filter, 
            prn=self.packet_handler, 
            store=False
        )
        sniffer.start()
        while self.running:
            time.sleep(1)
        try:
            sniffer.stop()
        except Exception:
            pass

    def stop_capture(self):
        self.running = False
        time.sleep(1)

    def get_stats(self):
        import copy
        with self.lock:
            elapsed_time = time.time() - self.stats['start_time']
            connection_count = len(self.connections)
            
            current_time = time.time()
            with self.sliding_window_lock:
                cutoff_time = current_time - self.window_size
                while self.sliding_window and self.sliding_window[0][0] < cutoff_time:
                    self.sliding_window.popleft()
                
                recent_data = list(self.sliding_window)
                
                if recent_data:
                    time_divisor = min(self.window_size, max(1.0, elapsed_time))
                    total_bytes = sum(s for _, s in recent_data)
                    total_packets = len(recent_data)
                    real_time_bandwidth = (total_bytes * 8) / (time_divisor * 1024 * 1024)
                    real_time_packets_per_second = total_packets / time_divisor
                else:
                    real_time_bandwidth = 0.0
                    real_time_packets_per_second = 0.0
            
            return copy.deepcopy({
                **self.stats,
                'bandwidth_mbps': round(real_time_bandwidth, 2),
                'connection_count': connection_count,
                'packets_per_second': round(real_time_packets_per_second, 2),
                'analysis_results_count': len(self.analysis_results)
            })

    def get_protocol_stats(self):
        import copy
        with self.lock:
            return copy.deepcopy(dict(self.protocol_stats))

    def get_recent_connections(self, max_count=50):
        import copy
        with self.lock:
            sorted_connections = sorted(
                self.connections.values(),
                key=lambda x: x['last_activity'],
                reverse=True
            )
            return copy.deepcopy(sorted_connections[:max_count])

    def get_top_ips(self, max_count=10):
        ip_data = list(self.analysis_results.items())
        sorted_ips = sorted(ip_data, key=lambda x: x[1]['total_packets'], reverse=True)
        return sorted_ips[:max_count]
    
    def _detect_web_vulnerabilities(self, features):
        """检测Web漏洞，基于HTTP payload中的关键字"""
        if not features.get('is_http', False) or 'payload' not in features:
            return None
        
        payload = features['payload']
        if not payload:
            return None
        
        try:
            if isinstance(payload, bytes):
                payload_str = payload.decode('utf-8', errors='ignore')
            else:
                payload_str = str(payload)
            
            # 【核心修复2】：对HTTP Payload进行 URL 解码，防止攻击者通过 %27%20OR%201%3D1 绕过规则
            payload_str = urllib.parse.unquote(payload_str)
            
            if self._is_legitimate_request(payload_str):
                return None
            
            sql_injection_patterns = [
                r"'\s*OR\s+1\s*=\s*1\s*--",
                r"'\s*UNION\s+SELECT",
                r"'\s*DROP\s+TABLE",
                r"'\s*INSERT\s+INTO",
                r"'\s*DELETE\s+FROM",
                r"'\s*UPDATE\s+.*SET",
                r"'\s*EXEC\s+sp_",
                r"'\s*xp_cmdshell",
                r"'\s*1\s*=\s*1",
                r"'\s*1'--",
                r"'\s*OR\s+1\s*=\s*1",
                r"'\s*AND\s+1\s*=\s*1",
                r"SLEEP\(\d+\)",
                r"BENCHMARK\(\d+",
                r"WAITFOR\s+DELAY",
                r"UNHEX\(",
                r"HEX\("
            ]
            
            xss_patterns = [
                r"<script[^>]*>[^<]*</script>",
                r"on\w+\s*=\s*['\"][^'\"]*",
                r"javascript:\s*alert\(",
                r"<iframe[^>]*src=['\"][^'\"]*['\"]",
                r"<object[^>]*data=['\"][^'\"]*['\"]",
                r"<embed[^>]*src=['\"][^'\"]*['\"]",
                r"<img[^>]*src=['\"][^'\"]*onerror=['\"][^'\"]*['\"]"
            ]
            
            command_injection_patterns = [
                r";\s*[a-zA-Z0-9]+\s*",
                r"\|\s*[a-zA-Z0-9]+\s*",
                r"`[a-zA-Z0-9]+`",
                r"\$\([a-zA-Z0-9]+\)",
                r"rm\s+-rf\s+",
                r"cat\s+/etc/passwd",
                r"ls\s+-la\s+"
            ]
            
            information_disclosure_patterns = [
                r"password\s*=\s*['\"][^'\"]*['\"]",
                r"token\s*=\s*['\"][^'\"]*['\"]",
                r"secret\s*=\s*['\"][^'\"]*['\"]",
                r"api_key\s*=\s*['\"][^'\"]*['\"]",
                r"private_key\s*=\s*['\"][^'\"]*['\"]",
                r"/etc/passwd",
                r"/etc/shadow",
                r"phpinfo\(\)",
                r"info\.php"
            ]
            
            for pattern in sql_injection_patterns:
                if re.search(pattern, payload_str, re.IGNORECASE):
                    return 'SQL注入攻击'
            
            for pattern in xss_patterns:
                if re.search(pattern, payload_str, re.IGNORECASE):
                    return 'XSS攻击'
            
            for pattern in command_injection_patterns:
                if re.search(pattern, payload_str, re.IGNORECASE):
                    return '命令注入攻击'
            
            for pattern in information_disclosure_patterns:
                if re.search(pattern, payload_str, re.IGNORECASE):
                    return '敏感信息泄露'
            
            return None
            
        except Exception as e:
            logger.error(f"检测Web漏洞时出错: {e}")
            return None
    
    def _is_legitimate_request(self, payload_str):
        legitimate_patterns = [
            r"/api/", r"/v1/", r"/v2/", r"\.js$", r"\.css$", r"\.html$", r"\.png$", 
            r"\.jpg$", r"\.jpeg$", r"\.gif$", r"\.ico$", r"/wp-", r"/admin/", 
            r"/login/", r"/logout/", r"q=", r"search=", r"query="
        ]
        
        for pattern in legitimate_patterns:
            if re.search(pattern, payload_str, re.IGNORECASE):
                return True
        
        if len(payload_str) < 10:
            return True
        
        http_methods = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"]
        for method in http_methods:
            if payload_str.startswith(method):
                return True
        
        return False

    def _analyze_vulnerability_type(self, features):
        """分析漏洞类型"""
        try:
            web_vulnerability = self._detect_web_vulnerabilities(features)
            if web_vulnerability:
                return web_vulnerability
            
            dst_port = features.get('dst_port', 0)
            src_port = features.get('src_port', 0)
            protocol = features.get('protocol', 'Other')
            packet_length = features.get('packet_length', 0)
            
            port_vulnerability_map = {
                21: 'FTP漏洞', 22: 'SSH漏洞', 23: 'Telnet漏洞', 25: 'SMTP漏洞',
                80: 'HTTP漏洞', 443: 'HTTPS漏洞', 3306: 'MySQL漏洞', 1433: 'MSSQL漏洞',
                3389: 'RDP漏洞', 27017: 'MongoDB漏洞', 6379: 'Redis漏洞', 
                11211: 'Memcached漏洞', 2375: 'Docker API漏洞', 5984: 'CouchDB漏洞'
            }
            
            if dst_port in port_vulnerability_map:
                return port_vulnerability_map[dst_port]
            if src_port in port_vulnerability_map:
                return port_vulnerability_map[src_port]
            
            if protocol == 'TCP':
                flags = features.get('flags', 0)
                if flags & 0x02 and not (flags & 0x10):
                    return '端口扫描'
                if features.get('is_http', False):
                    return 'Web应用漏洞'
            
            elif protocol == 'UDP':
                if packet_length > 1000:
                    return 'UDP Flood攻击'
            
            elif protocol == 'ICMP':
                if packet_length > 60:
                    return 'ICMP Flood攻击'
            
            if packet_length > 1500:
                return '异常数据包'
            elif packet_length < 20:
                return '碎片攻击'
            
            # 【核心修复3】：增加包数阈值限制，消除规则系统的大面积误报
            if 'connection_duration' in features:
                duration = features['connection_duration']
                packets = features.get('connection_count', 1)
                # 修复误报：任何正常TCP握手的第二、三个包到达时间间隔都在零点几毫秒，必须增加包数限制
                if duration < 0.1 and packets > 20:
                    return '快速连接攻击'
            
            if 'packet_rate' in features:
                packet_rate = features['packet_rate']
                packets = features.get('connection_count', 1)
                # 修复误报：网络波动会导致瞬间发包率极高，必须限制总发包规模才能定性为高频攻击
                if packet_rate > 200 and packets > 50:
                    return '高频率攻击'
            
            return '未知漏洞'
            
        except Exception as e:
            logger.error(f"分析漏洞类型时出错: {e}")
            return '未知漏洞'