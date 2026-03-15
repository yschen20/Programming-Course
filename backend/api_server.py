"""
==================================================
校园网异常检测平台 - API接口服务
==================================================
"""

from flask import Flask, jsonify, request
from flask_cors import CORS
import sys
from pathlib import Path
import time
import jwt
import os
import logging
import secrets
from functools import wraps
import threading

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# 添加模块路径
sys.path.append(str(Path(__file__).parent / "database"))
sys.path.append(str(Path(__file__).parent))

from db_manager import DatabaseManager
from models import Blacklist, BlockLog
from ai.ai_detector import AIDetector

# JWT配置
JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY')
if not JWT_SECRET_KEY:
    key_file = Path(__file__).parent / 'data' / '.jwt_secret'
    if key_file.exists():
        JWT_SECRET_KEY = key_file.read_text().strip()
    else:
        JWT_SECRET_KEY = secrets.token_hex(32)
        try:
            key_file.parent.mkdir(parents=True, exist_ok=True)
            key_file.write_text(JWT_SECRET_KEY)
        except Exception as e:
            logger.error(f"写入JWT密钥文件失败: {e}")

JWT_ALGORITHM = 'HS256'
JWT_EXPIRATION = 86400  # 延长到24小时

def jwt_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
        if not token:
            return jsonify({'error': '缺少认证token'}), 401
        try:
            payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
            request.user = payload
        except jwt.ExpiredSignatureError:
            return jsonify({'error': '登录已过期，请重新登录'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': '无效的token'}), 401
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
        if not token:
            return jsonify({'error': '缺少认证token'}), 401
        try:
            payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
            request.user = payload
            if payload.get('role') != 'admin':
                return jsonify({'error': '权限不足，需要管理员权限'}), 403
        except Exception:
            return jsonify({'error': '登录已失效'}), 401
        return f(*args, **kwargs)
    return decorated_function

app = Flask(__name__)

# 增加文件上传大小限制到500MB
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024

# 增加对 Vue3 + Vite 默认端口 5173 及 3000 的跨域支持
allowed_origins = os.environ.get(
    'ALLOWED_ORIGINS', 
    'http://localhost:3000,http://127.0.0.1:3000,http://localhost:5173,http://127.0.0.1:5173'
).split(',')
CORS(app, origins=allowed_origins, supports_credentials=True)

db = DatabaseManager()
ai_detector = AIDetector()

class CacheManager:
    def __init__(self):
        self.cache = {}
        self.lock = threading.RLock()
    def get(self, key):
        with self.lock:
            if key in self.cache:
                value, timestamp, ttl = self.cache[key]
                if time.time() - timestamp < ttl:
                    return value
                else:
                    del self.cache[key]
            return None
    def set(self, key, value, ttl=10):
        with self.lock:
            self.cache[key] = (value, time.time(), ttl)

cache_manager = CacheManager()

@app.route('/api/status', methods=['GET'])
@jwt_required
def get_status():
    try:
        db_stats = db.get_stats()
        return jsonify({
            'status': 'running',
            'database': db_stats,
            'ai_detector': {'is_trained': ai_detector.stats.get('is_trained', False)}
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/traffic', methods=['GET'])
@jwt_required
def get_traffic():
    """获取真实流量日志（动态读取数据库）"""
    try:
        limit = request.args.get('limit', 100, type=int)
        offset = request.args.get('offset', 0, type=int)
        
        # 防止前端传过来空字符串 "" 导致 SQL 查询失效
        src_ip = request.args.get('src_ip', '').strip() or None
        protocol = request.args.get('protocol', '').strip() or None
        status = request.args.get('status', '').strip() or None
        
        # 处理时间范围参数
        start_time = None
        end_time = None
        start_time_str = request.args.get('start_time', '').strip()
        end_time_str = request.args.get('end_time', '').strip()
        
        if start_time_str:
            try:
                import datetime
                # 解析前端传来的时间字符串
                dt = datetime.datetime.strptime(start_time_str, '%Y-%m-%d %H:%M:%S')
                start_time = dt.timestamp()
            except:
                pass
        
        if end_time_str:
            try:
                import datetime
                # 解析前端传来的时间字符串
                dt = datetime.datetime.strptime(end_time_str, '%Y-%m-%d %H:%M:%S')
                end_time = dt.timestamp()
            except:
                pass
        
        # 从数据库获取真实数据
        logs = db.get_recent_traffic(
            limit=limit, 
            offset=offset, 
            src_ip=src_ip, 
            protocol=protocol,
            start_time=start_time,
            end_time=end_time,
            status=status
        )
        total = db.get_traffic_count(
            src_ip=src_ip, 
            protocol=protocol,
            start_time=start_time,
            end_time=end_time,
            status=status
        )
        
        logs_dict = []
        for log in logs:
            logs_dict.append({
                'id': getattr(log, 'id', 0),
                'timestamp': getattr(log, 'timestamp', 0),
                'src_ip': getattr(log, 'src_ip', ''),
                'dst_ip': getattr(log, 'dst_ip', ''),
                'protocol': getattr(log, 'protocol', ''),
                'length': getattr(log, 'length', 0),
                'is_anomaly': getattr(log, 'is_anomaly', 0)
            })
            
        return jsonify({
            'logs': logs_dict,
            'total': total,
            'limit': limit,
            'offset': offset
        })
    except Exception as e:
        logger.error(f"获取流量日志失败: {e}")
        return jsonify({'error': '服务器内部错误'}), 500

@app.route('/api/traffic/analysis', methods=['GET'])
@jwt_required
def get_traffic_analysis():
    try:
        hours = request.args.get('hours', 24, type=int)
        # 增加 None 的兜底校验
        if hours is None:
            hours = 24
            
        time_stats = db.get_traffic_stats_by_time(hours=hours)
        top_talkers = db.get_top_talkers(limit=10, hours=hours)
        
        capture_status = db.get_system_status('capture')
        real_time_results = {}
        if capture_status and capture_status.get('metrics'):
            import json
            try:
                metrics = json.loads(capture_status['metrics'])
                real_time_results = {
                    'packets_per_second': metrics.get('packets_per_second', 0),
                    'bytes_per_second': metrics.get('bandwidth_mbps', 0),
                    'active_connections': metrics.get('connection_count', 0)
                }
            except: pass
            
        return jsonify({
            'time_stats': time_stats,
            'top_talkers': top_talkers,
            'real_time': real_time_results
        })
    except Exception as e:
        logger.error(f"获取流量分析失败: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/alerts', methods=['GET'])
@jwt_required
def get_alerts():
    """获取真实告警列表"""
    try:
        limit = request.args.get('limit', 100, type=int)
        offset = request.args.get('offset', 0, type=int)
        
        level = request.args.get('severity', '').strip() or None
        status = request.args.get('status', '').strip() or None
        
        alerts = db.get_alerts(level=level, status=status, limit=limit, offset=offset)
        total = db.get_alert_count(level=level, status=status)
        
        alerts_dict = []
        for alert in alerts:
            alerts_dict.append({
                'id': getattr(alert, 'id', 0),
                'timestamp': getattr(alert, 'timestamp', 0),
                'level': getattr(alert, 'level', ''),
                'type': getattr(alert, 'type', ''),
                'src_ip': getattr(alert, 'src_ip', ''),
                'dst_ip': getattr(alert, 'dst_ip', ''),
                'description': getattr(alert, 'description', ''),
                'status': getattr(alert, 'status', '未处理'),
                'vulnerability_type': getattr(alert, 'vulnerability_type', '')
            })
            
        return jsonify({
            'alerts': alerts_dict,
            'total': total,
            'limit': limit,
            'offset': offset
        })
    except Exception as e:
        logger.error(f"获取告警失败: {e}")
        return jsonify({'error': '服务器内部错误'}), 500

@app.route('/api/alerts/<int:alert_id>', methods=['PUT'])
@jwt_required
def update_alert(alert_id):
    try:
        status = request.get_json().get('status')
        if db.update_alert_status(alert_id, status):
            return jsonify({'message': '状态已更新'})
        return jsonify({'error': '告警不存在'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/monitor/alerts', methods=['DELETE'])
@admin_required
def clear_monitor_alerts():
    try:
        deleted = db.clear_all_alerts()
        return jsonify({'message': f'清空了 {deleted} 条记录'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/defense/blocked', methods=['GET'])
@jwt_required
def get_blocked_ips():
    try:
        blacklist = db.get_blacklist()
        blocked_ips = []
        now = time.time()
        for item in blacklist:
            if hasattr(item, 'status') and item.status == '封禁中':
                if not item.expire_time or item.expire_time > now:
                    blocked_ips.append({
                        'ip': item.ip,
                        'reason': item.reason,
                        'attack_type': item.reason.split(' ')[0] if item.reason else '手动拦截',
                        'blocked_at': item.create_time,
                        'expires_at': item.expire_time,
                        'manual': '手动' in item.reason
                    })
        return jsonify({'blocked_ips': blocked_ips, 'total': len(blocked_ips)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/defense/history', methods=['GET'])
@jwt_required
def get_defense_history():
    try:
        limit = request.args.get('limit', 100, type=int)
        offset = request.args.get('offset', 0, type=int)
        logs = db.get_block_logs(limit=limit, offset=offset)
        total = db.get_block_log_count()
        history = []
        for log in logs:
            history.append({
                'ip': getattr(log, 'ip', ''),
                'reason': getattr(log, 'rule', ''),
                'attack_type': getattr(log, 'rule', '未知').split()[0],
                'blocked_at': getattr(log, 'timestamp', 0)
            })
        return jsonify({'history': history, 'total': total})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/defense/block', methods=['POST'])
@admin_required
def manual_block_ip():
    try:
        data = request.get_json()
        ip = data.get('ip')
        
        # IP地址格式验证
        import re
        ip_regex = r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        if not ip or not re.match(ip_regex, ip):
            return jsonify({'error': '无效的IP地址格式'}), 400
        
        import json
        db.add_command('defense_block', json.dumps({
            'command': 'block',
            'ip': ip,
            'duration': int(data.get('duration', 3600)),
            'reason': data.get('reason', '手动拦截'),
            'timestamp': time.time()
        }))
        return jsonify({'message': '拦截指令已下发'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/defense/unblock', methods=['POST'])
@admin_required
def manual_unblock_ip():
    try:
        ip = request.get_json().get('ip')
        
        # IP地址格式验证
        import re
        ip_regex = r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        if not ip or not re.match(ip_regex, ip):
            return jsonify({'error': '无效的IP地址格式'}), 400
        
        import json
        db.add_command('defense_unblock', json.dumps({'ip': ip}))
        return jsonify({'message': '解封指令已下发'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/defense/whitelist', methods=['GET', 'POST', 'DELETE'])
@jwt_required
def handle_whitelist():
    try:
        if request.method == 'GET':
            whitelist = db.get_blacklist(active_only=False, limit=1000)
            return jsonify({'whitelist': [item.ip for item in whitelist if item.status == 'whitelist']})
        
        if request.user.get('role') != 'admin':
            return jsonify({'error': '权限不足'}), 403
            
        ip = request.get_json().get('ip')
        
        # IP地址格式验证
        import re
        ip_regex = r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        if not ip or not re.match(ip_regex, ip):
            return jsonify({'error': '无效的IP地址格式'}), 400
        
        import json
        if request.method == 'POST':
            db.add_command('whitelist_add', json.dumps({'ip': ip}))
            return jsonify({'message': '添加白名单指令已下发'})
        elif request.method == 'DELETE':
            db.add_command('whitelist_remove', json.dumps({'ip': ip}))
            return jsonify({'message': '移除白名单指令已下发'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/ai/detect', methods=['POST'])
@jwt_required
def ai_detect():
    try:
        data = request.get_json()
        if hasattr(ai_detector, '_load_latest_model'):
            ai_detector._load_latest_model()
        result = ai_detector.detect_anomaly(data)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/ai/stats', methods=['GET'])
@jwt_required
def ai_stats():
    try:
        if hasattr(ai_detector, '_load_latest_model'):
            ai_detector._load_latest_model()
        return jsonify(ai_detector.stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/ai/train', methods=['POST'])
@admin_required
def ai_train():
    try:
        data = request.get_json()
        training_data = data.get('training_data', [])
        if not isinstance(training_data, list) or len(training_data) < 5:
            return jsonify({'error': '至少需要 5 条样本特征'}), 400
            
        model_name = data.get('model_name', f'model_{int(time.time())}')
        import tempfile, json
        data_dir = os.path.join(os.path.dirname(__file__), 'data')
        os.makedirs(data_dir, exist_ok=True)
        temp_file_path = os.path.join(data_dir, f"train_{int(time.time())}_{secrets.token_hex(4)}.json")
        
        with open(temp_file_path, 'w', encoding='utf-8') as f:
            json.dump(training_data, f)
            
        db.add_command('train_command', json.dumps({
            'training_data_path': temp_file_path,
            'model_name': model_name,
            'algorithm': 'isolation_forest'
        }))
        return jsonify({'message': '训练任务已下发至引擎'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/ai/upload-dataset', methods=['POST'])
@admin_required
def upload_dataset():
    try:
        if 'file' not in request.files:
            return jsonify({'error': '请选择要上传的数据集文件'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': '文件名不能为空'}), 400
        
        # 检查文件格式
        if not (file.filename.endswith('.csv') or file.filename.endswith('.json')):
            return jsonify({'error': '只支持CSV和JSON格式的数据集'}), 400
        
        # 保存文件
        data_dir = os.path.join(os.path.dirname(__file__), 'data', 'datasets')
        os.makedirs(data_dir, exist_ok=True)
        
        import secrets
        filename = f"{int(time.time())}_{secrets.token_hex(4)}_{file.filename}"
        file_path = os.path.join(data_dir, filename)
        file.save(file_path)
        
        # 获取模型名称
        model_name = request.form.get('model_name', f'model_{int(time.time())}')
        
        # 调用训练脚本
        import subprocess
        import sys
        script_path = os.path.join(os.path.dirname(__file__), 'ai', 'train_from_dataset.py')
        
        # 启动训练进程
        subprocess.Popen([
            sys.executable, script_path,
            file_path,
            model_name
        ])
        
        return jsonify({'message': '数据集上传成功，训练任务已启动', 'filename': filename})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/stats/summary', methods=['GET'])
@jwt_required
def get_stats_summary():
    try:
        cached = cache_manager.get('summary')
        if cached: return jsonify(cached)
        
        res = {
            'traffic_count': db.get_traffic_count(),
            'alert_count': db.get_alert_count(),
            'blacklist_count': db.get_blacklist_count(),
            'block_count': db.get_block_count()
        }
        
        cap = db.get_system_status('capture')
        if cap and cap.get('metrics'):
            import json
            try: res['capture_stats'] = json.loads(cap['metrics'])
            except: pass
            
        cache_manager.set('summary', res, 1)
        return jsonify(res)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/monitor/summary', methods=['GET'])
@jwt_required
def get_monitor_summary():
    try:
        metrics = db.get_system_metrics(limit=1)
        if metrics:
            m = metrics[0]
            return jsonify({
                'cpu': {'percent': m.get('cpu_percent') or 0},
                'memory': {
                    'percent': m.get('memory_percent') or 0,
                    # 使用 (x or 0) 确保当值为 None 时，强制转换为 0 再做乘法
                    'used': (m.get('memory_used_mb') or 0) * 1024 * 1024,
                    'available': (m.get('memory_available_mb') or 0) * 1024 * 1024
                },
                'disk': {'percent': m.get('disk_percent') or 0},
                'network': {
                    'bytes_sent': (m.get('network_sent_mb') or 0) * 1024 * 1024,
                    'bytes_recv': (m.get('network_recv_mb') or 0) * 1024 * 1024
                },
                'active_connections': m.get('active_connections') or 0
            })
        return jsonify({})
    except Exception as e:
        logger.error(f"获取监控摘要失败: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/monitor/services', methods=['GET'])
@jwt_required
def get_services_status():
    try:
        daemon = db.get_system_status('daemon')
        cap = db.get_system_status('capture')
        defense = db.get_system_status('defense')
        
        return jsonify({'services': {
            '守护核心进程': {'status': 'running' if daemon and daemon.get('status') == 'running' else 'stopped'},
            '网络抓包嗅探': {'status': 'running' if cap and cap.get('status') == 'running' else 'stopped'},
            '智能拦截防御': {'status': 'enabled' if defense and defense.get('status') == 'enabled' else 'disabled'},
            'REST API接口': {'status': 'running'}
        }})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/defense/config', methods=['GET', 'PUT'])
@jwt_required
def defense_config():
    from config import ConfigManager
    cm = ConfigManager(str(Path(__file__).parent / 'data' / 'config.json'))
    if request.method == 'GET':
        return jsonify(cm.get_section('defense'))
    elif request.user.get('role') == 'admin':
        cm.update_section('defense', request.get_json())
        import json
        db.add_command('config_reload', json.dumps({'section': 'defense'}))
        return jsonify({'message': '配置已保存并重载'})
    return jsonify({'error': '权限不足'}), 403

@app.route('/api/cleanup/config', methods=['GET', 'PUT'])
@jwt_required
def cleanup_config():
    from config import ConfigManager
    cm = ConfigManager(str(Path(__file__).parent / 'data' / 'config.json'))
    if request.method == 'GET':
        return jsonify({'retention_days': cm.get_section('database').get('retention_days', 30)})
    elif request.user.get('role') == 'admin':
        cm.update_section('database', {'retention_days': request.get_json().get('retention_days', 30)})
        import json
        db.add_command('config_reload', json.dumps({'section': 'cleanup'}))
        return jsonify({'message': '清理策略已保存'})
    return jsonify({'error': '权限不足'}), 403

@app.route('/api/cleanup', methods=['POST'])
@admin_required
def manual_cleanup():
    try:
        from config import ConfigManager
        cm = ConfigManager(str(Path(__file__).parent / 'data' / 'config.json'))
        days = cm.get_section('database').get('retention_days', 30)
        res = db.cleanup_old_data(days)
        return jsonify({'message': f"磁盘清理完成，释放了大量日志数据", 'details': res})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        user = db.check_user(data.get('username'), data.get('password'))
        if user:
            token = jwt.encode({
                'user_id': user.id, 'username': user.username, 'role': user.role,
                'exp': time.time() + JWT_EXPIRATION
            }, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
            return jsonify({'token': token, 'user': {'id': user.id, 'username': user.username, 'role': user.role}})
        return jsonify({'error': '管理员账号或密码错误'}), 401
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/auth/change-password', methods=['POST'])
@jwt_required
def change_password():
    try:
        data = request.get_json()
        if not db.check_user(request.user.get('username'), data.get('old_password')):
            return jsonify({'error': '原密码不正确'}), 401
        db.update_password(request.user.get('username'), data.get('new_password'))
        return jsonify({'message': '密码修改成功'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.teardown_request
def close_db_connection(exception):
    try:
        if 'db' in globals() and db is not None:
            db.close()
    except Exception: pass

def create_app():
    """创建Flask应用实例"""
    return app

if __name__ == '__main__':
    logger.info("API服务启动中...")
    app.run(debug=False, host='0.0.0.0', port=5000, threaded=True)