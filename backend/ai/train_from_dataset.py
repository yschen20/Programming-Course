#!/usr/bin/env python3
"""
从多种格式的数据集训练AI模型
支持CSV、JSON等格式的数据集导入
"""

import os
import sys
import json
import csv
import argparse
import logging
from pathlib import Path

# 添加项目路径
sys.path.insert(0, str(Path(__file__).parent.parent))

from ai.ai_detector import create_ai_detector

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def load_csv_dataset(file_path):
    """加载CSV格式的数据集"""
    data = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                # 转换数据类型
                processed_row = {}
                for key, value in row.items():
                    # 尝试转换为数值类型
                    try:
                        processed_row[key] = float(value)
                    except ValueError:
                        processed_row[key] = value
                data.append(processed_row)
        logger.info(f"成功加载CSV数据集: {file_path}, 共 {len(data)} 条记录")
    except Exception as e:
        logger.error(f"加载CSV数据集失败: {e}")
        raise
    return data


def load_json_dataset(file_path):
    """加载JSON格式的数据集"""
    data = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        # 确保数据是列表格式
        if not isinstance(data, list):
            data = [data]
        logger.info(f"成功加载JSON数据集: {file_path}, 共 {len(data)} 条记录")
    except Exception as e:
        logger.error(f"加载JSON数据集失败: {e}")
        raise
    return data


def load_dataset(file_path):
    """根据文件扩展名加载不同格式的数据集"""
    file_ext = Path(file_path).suffix.lower()
    if file_ext == '.csv':
        return load_csv_dataset(file_path)
    elif file_ext == '.json':
        return load_json_dataset(file_path)
    else:
        raise ValueError(f"不支持的文件格式: {file_ext}，仅支持CSV和JSON格式")


def preprocess_data(data):
    """预处理数据，确保数据格式正确"""
    processed_data = []
    for item in data:
        # 确保数据包含必要的字段
        processed_item = {}
        
        # 处理字节传输量
        if 'bytes_transferred' in item:
            processed_item['bytes_transferred'] = item['bytes_transferred']
        elif 'bytes_sent' in item:
            processed_item['bytes_transferred'] = item['bytes_sent']
        elif 'total_bytes' in item:
            processed_item['bytes_transferred'] = item['total_bytes']
        # 处理CICIDS2017格式
        elif 'Total Length of Fwd Packets' in item and 'Total Length of Bwd Packets' in item:
            try:
                fwd_bytes = float(item['Total Length of Fwd Packets'])
                bwd_bytes = float(item['Total Length of Bwd Packets'])
                processed_item['bytes_transferred'] = fwd_bytes + bwd_bytes
            except (ValueError, TypeError):
                processed_item['bytes_transferred'] = 0.0
        else:
            processed_item['bytes_transferred'] = 0.0
        
        # 处理包大小
        if 'packet_length' in item:
            processed_item['packet_length'] = item['packet_length']
        elif 'bytes_recv' in item:
            processed_item['packet_length'] = item['bytes_recv']
        elif 'length' in item:
            processed_item['packet_length'] = item['length']
        # 处理CICIDS2017格式
        elif 'Packet Length Mean' in item:
            try:
                processed_item['packet_length'] = float(item['Packet Length Mean'])
            except (ValueError, TypeError):
                processed_item['packet_length'] = 0.0
        elif 'Average Packet Size' in item:
            try:
                processed_item['packet_length'] = float(item['Average Packet Size'])
            except (ValueError, TypeError):
                processed_item['packet_length'] = 0.0
        else:
            processed_item['packet_length'] = 0.0
        
        # 处理连接包数
        if 'connection_count' in item:
            processed_item['connection_count'] = item['connection_count']
        elif 'packets' in item:
            processed_item['connection_count'] = item['packets']
        elif 'count' in item:
            processed_item['connection_count'] = item['count']
        # 处理CICIDS2017格式
        elif 'Total Fwd Packets' in item and 'Total Backward Packets' in item:
            try:
                fwd_packets = float(item['Total Fwd Packets'])
                bwd_packets = float(item['Total Backward Packets'])
                processed_item['connection_count'] = fwd_packets + bwd_packets
            except (ValueError, TypeError):
                processed_item['connection_count'] = 1.0
        else:
            processed_item['connection_count'] = 1.0
        
        # 处理连接持续时间
        if 'connection_duration' in item:
            processed_item['connection_duration'] = item['connection_duration']
        elif 'duration' in item:
            processed_item['connection_duration'] = item['duration']
        # 处理CICIDS2017格式
        elif 'Flow Duration' in item:
            try:
                # CICIDS2017的Flow Duration是以微秒为单位，转换为秒
                duration_us = float(item['Flow Duration'])
                processed_item['connection_duration'] = duration_us / 1000000.0
            except (ValueError, TypeError):
                processed_item['connection_duration'] = 1.0
        else:
            processed_item['connection_duration'] = 1.0
        
        # 处理发包速率
        if 'packet_rate' in item:
            processed_item['packet_rate'] = item['packet_rate']
        elif 'rate' in item:
            processed_item['packet_rate'] = item['rate']
        # 处理CICIDS2017格式
        elif 'Flow Packets/s' in item:
            try:
                processed_item['packet_rate'] = float(item['Flow Packets/s'])
            except (ValueError, TypeError):
                # 根据包数和持续时间计算速率
                packets = processed_item['connection_count']
                duration = processed_item['connection_duration']
                if duration > 0:
                    processed_item['packet_rate'] = packets / duration
                else:
                    processed_item['packet_rate'] = 1.0
        else:
            # 根据包数和持续时间计算速率
            packets = processed_item['connection_count']
            duration = processed_item['connection_duration']
            if duration > 0:
                processed_item['packet_rate'] = packets / duration
            else:
                processed_item['packet_rate'] = 1.0
        
        processed_data.append(processed_item)
    
    logger.info(f"数据预处理完成，共 {len(processed_data)} 条记录")
    return processed_data


def train_from_dataset(dataset_path, model_name):
    """从数据集训练模型"""
    try:
        # 加载数据集
        raw_data = load_dataset(dataset_path)
        
        # 预处理数据
        processed_data = preprocess_data(raw_data)
        
        # 创建AI检测器实例
        ai_detector = create_ai_detector()
        
        # 训练模型
        success, message = ai_detector.train_model(processed_data, model_name)
        
        if success:
            logger.info(f"模型训练成功: {message}")
            print(f"\n✅ 模型训练成功!")
            print(f"📋 训练信息: {message}")
            print(f"🎯 模型名称: {model_name}")
            print(f"📊 训练样本数: {len(processed_data)}")
        else:
            logger.error(f"模型训练失败: {message}")
            print(f"\n❌ 模型训练失败: {message}")
            return False
        
        return True
        
    except Exception as e:
        logger.error(f"训练过程中发生错误: {e}")
        print(f"\n❌ 训练过程中发生错误: {e}")
        return False


def main():
    """主函数"""
    parser = argparse.ArgumentParser(description='从数据集训练AI异常检测模型')
    parser.add_argument('dataset', help='数据集文件路径 (支持CSV和JSON格式)')
    parser.add_argument('model_name', help='训练后的模型名称')
    parser.add_argument('--algorithm', default='isolation_forest', help='训练算法 (默认: isolation_forest)')
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("🎯 从数据集训练AI模型")
    print("=" * 60)
    print(f"📁 数据集路径: {args.dataset}")
    print(f"🤖 模型名称: {args.model_name}")
    print(f"🔍 算法: {args.algorithm}")
    print("=" * 60)
    
    # 检查数据集文件是否存在
    if not Path(args.dataset).exists():
        print(f"❌ 数据集文件不存在: {args.dataset}")
        return
    
    # 开始训练
    train_from_dataset(args.dataset, args.model_name)


if __name__ == "__main__":
    main()
