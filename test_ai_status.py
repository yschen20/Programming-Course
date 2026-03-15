import sys
from pathlib import Path

# 添加项目路径
sys.path.insert(0, str(Path(__file__).parent / "backend"))

from ai.ai_detector import create_ai_detector

def test_ai_status():
    print("测试 AI 检测器状态...")
    ai_detector = create_ai_detector()
    print("AI 检测器创建成功")
    print("当前状态:")
    print(f"  训练状态: {ai_detector.stats.get('is_trained', False)}")
    print(f"  活跃模型: {ai_detector.stats.get('active_model', 'None')}")
    print(f"  总检测次数: {ai_detector.stats.get('total_detections', 0)}")
    print(f"  发现异常数: {ai_detector.stats.get('anomalies_found', 0)}")
    print(f"  最后训练时间: {ai_detector.stats.get('last_trained_at', 'None')}")

if __name__ == "__main__":
    test_ai_status()
