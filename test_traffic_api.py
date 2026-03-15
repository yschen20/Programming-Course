import requests

# 测试 API 端点
url = 'http://localhost:5000/api/traffic'

# 测试请求头（使用有效的 token）
headers = {
    'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxLCJ1c2VybmFtZSI6ImFkbWluIiwicm9sZSI6ImFkbWluIiwiZXhwIjoxNzczMTI2Nzg3fQ.Hk7X3JfQ3e7j4c4Y4X4X4X4X4X4X4X4X4X4X4X4X4'
}

# 测试参数
params = {
    'limit': 10,
    'offset': 0
}

try:
    print('测试 /api/traffic 接口...')
    response = requests.get(url, headers=headers, params=params)
    print(f'状态码: {response.status_code}')
    print(f'响应内容: {response.json()}')
except Exception as e:
    print(f'测试失败: {str(e)}')
