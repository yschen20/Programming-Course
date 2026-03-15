import os
import time
import logging
import json
import numpy as np
from pathlib import Path
import joblib

logger = logging.getLogger(__name__)

class FeatureExtractor:
    """统一的特征提取器，供 capture.py 和 ai_detector.py 共同使用"""
    def __init__(self):
        self.features_keys = ['bytes_transferred', 'packet_length', 'connection_count', 'connection_duration', 'packet_rate']

    def extract_features(self, data, return_dict=False):
        features = {
            'bytes_transferred': float(data.get('bytes_transferred', data.get('bytes_sent', 0.0))),
            'packet_length': float(data.get('packet_length', data.get('bytes_recv', 0.0))),
            'connection_count': float(data.get('connection_count', data.get('packets', 0.0))),
            'connection_duration': float(data.get('connection_duration', 0.0)),
            'packet_rate': float(data.get('packet_rate', 0.0))
        }
        
        if return_dict:
            return features
            
        return [
            features['bytes_transferred'],
            features['packet_length'],
            features['connection_count'],
            features['connection_duration'],
            features['packet_rate']
        ]


class AIDetector:
    def __init__(self):
        self.model_dir = Path(__file__).parent.parent / "data" / "models"
        self.model_dir.mkdir(parents=True, exist_ok=True)
        
        self.active_model_name = None
        self.model = None
        self.stats_file = self.model_dir / "stats.json"
        
        self._last_stats_mtime = 0
        self.feature_extractor = FeatureExtractor()
        self.features_keys = self.feature_extractor.features_keys
        
        self.stats = {
            'is_trained': False,
            'active_model': None,
            'total_detections': 0,
            'anomalies_found': 0,
            'last_trained_at': None
        }
        
        self._load_latest_model()

    def _load_latest_model(self):
        try:
            if not self.stats_file.exists():
                return
                
            current_mtime = os.path.getmtime(self.stats_file)
            if current_mtime == self._last_stats_mtime and self.model is not None:
                return
                
            self._last_stats_mtime = current_mtime
            
            with open(self.stats_file, 'r', encoding='utf-8') as f:
                new_stats = json.load(f)
                
            # 先更新统计信息
            self.stats.update(new_stats)
            
            # 尝试加载模型
            if new_stats.get('active_model') != self.active_model_name or self.model is None:
                if new_stats.get('active_model'):
                    model_path = self.model_dir / f"{new_stats['active_model']}.joblib"
                    if model_path.exists():
                        self.model = joblib.load(model_path)
                        self.active_model_name = new_stats['active_model']
                        logger.info(f"AI 模型已成功热加载至内存: {self.active_model_name}")
                    else:
                        # 模型文件不存在，重置状态
                        logger.warning(f"模型文件不存在: {model_path}")
                        self.model = None
                        self.active_model_name = None
                        self.stats['is_trained'] = False
                        self.stats['active_model'] = None
                        # 保存更新后的状态
                        self._save_stats()
            
            # 确保is_trained状态与模型是否存在一致
            self.stats['is_trained'] = (self.model is not None)
            
        except Exception as e:
            logger.error(f"热加载 AI 模型失败: {e}")

    def _save_stats(self):
        try:
            with open(self.stats_file, 'w', encoding='utf-8') as f:
                json.dump(self.stats, f)
            self._last_stats_mtime = os.path.getmtime(self.stats_file)
        except Exception as e:
            logger.error(f"保存 AI 统计状态失败: {e}")

    def _extract_features(self, data):
        if 'bytes_sent' not in data and 'bytes_transferred' not in data:
            data['bytes_transferred'] = data.get('packet_length', 0.0)
        if 'packets' not in data and 'connection_count' not in data:
            data['connection_count'] = 1.0
        if 'connection_duration' not in data:
            data['connection_duration'] = 1.0
        if 'packet_rate' not in data:
            data['packet_rate'] = 1.0
        return self.feature_extractor.extract_features(data, return_dict=False)

    def train_model(self, training_data, model_name, algorithm='isolation_forest'):
        try:
            from sklearn.ensemble import IsolationForest
            if not training_data or len(training_data) < 5:
                return False, f"训练样本太少 (仅 {len(training_data)} 条)，至少需要 5 条样本以构建模型"

            X_train = []
            for item in training_data:
                features = self._extract_features(item)
                X_train.append(features)
                
            X_matrix = np.array(X_train)
            
            logger.info(f"使用 {len(X_matrix)} 条样本进行 {algorithm} 模型训练...")
            model = IsolationForest(
                n_estimators=100,
                contamination=0.05,
                random_state=42
            )
            model.fit(X_matrix)
            
            model_path = self.model_dir / f"{model_name}.joblib"
            joblib.dump(model, model_path)
            
            self.model = model
            self.active_model_name = model_name
            
            self.stats['is_trained'] = True
            self.stats['active_model'] = model_name
            self.stats['last_trained_at'] = time.time()
            self._save_stats()
            
            return True, f"模型 {model_name} 训练完毕，特征维度: {len(self.features_keys)}"
            
        except Exception as e:
            import traceback
            error_msg = traceback.format_exc()
            logger.error(f"模型训练核心逻辑崩溃: {error_msg}")
            return False, str(e)

    def detect_anomaly(self, data):
        self.stats['total_detections'] += 1
        result = {
            'is_anomaly': False, 'score': 0.0, 'model_used': self.active_model_name or 'None',
            'attack_type': '正常流量', 'confidence': 0.0
        }
        try:
            if not self.model:
                self._save_stats()
                return result
                
            features = self._extract_features(data)
            X = np.array([features])
            pred = self.model.predict(X)[0]
            score = self.model.decision_function(X)[0]
            
            is_anomaly = (pred == -1) and (score < -0.1)
            if is_anomaly:
                self.stats['anomalies_found'] += 1
                result['attack_type'] = 'AI判定异常'
                result['confidence'] = round(min(1.0, 0.5 + abs(score) * 2), 2)
                
            result['is_anomaly'] = bool(is_anomaly)
            result['score'] = round(float(score), 4)
        except Exception as e:
            logger.error(f"AI 检测执行期间出错: {e}")
        
        if self.stats['total_detections'] % 10 == 0:
            self._save_stats()
        return result

    # 核心修复点：补全批量检测方法，支持 Capture.py 中的防抖优化调用
    def detect_anomaly_batch(self, data_list):
        self.stats['total_detections'] += len(data_list)
        results = [{'is_anomaly': False, 'score': 0.0, 'model_used': self.active_model_name or 'None', 'attack_type': '正常流量', 'confidence': 0.0} for _ in data_list]
        try:
            if not self.model:
                if self.stats['total_detections'] % 50 == 0:
                    self._save_stats()
                return results
                
            features_list = [self._extract_features(data) for data in data_list]
            X = np.array(features_list)
            
            preds = self.model.predict(X)
            scores = self.model.decision_function(X)
            
            for i in range(len(data_list)):
                pred = preds[i]
                score = scores[i]
                is_anomaly = (pred == -1) and (score < -0.1)
                
                results[i]['score'] = round(float(score), 4)
                if is_anomaly:
                    self.stats['anomalies_found'] += 1
                    results[i]['attack_type'] = 'AI判定异常'
                    results[i]['confidence'] = round(min(1.0, 0.5 + abs(score) * 2), 2)
                results[i]['is_anomaly'] = bool(is_anomaly)
        except Exception as e:
            logger.error(f"批量AI检测期间出错: {e}")
            
        if self.stats['total_detections'] % 50 == 0:
            self._save_stats()
        return results

    def get_model_stats(self):
        return self.stats

def create_ai_detector():
    return AIDetector()