import requests
import json

# 测试登录获取token
def test_login():
    url = 'http://localhost:5000/api/auth/login'
    data = {
        'username': 'admin',
        'password': 'admin123'
    }
    response = requests.post(url, json=data)
    print('Login response:', response.status_code, response.json())
    if response.status_code == 200:
        return response.json().get('token')
    return None

# 测试上传数据集API
def test_upload_dataset(token):
    url = 'http://localhost:5000/api/ai/upload-dataset'
    headers = {
        'Authorization': f'Bearer {token}'
    }
    # 创建一个简单的测试文件
    with open('test.txt', 'w') as f:
        f.write('test data')
    
    # 准备表单数据
    files = {
        'file': open('test.csv', 'rb')
    }
    data = {
        'model_name': 'test_model'
    }
    
    response = requests.post(url, headers=headers, files=files, data=data)
    print('Upload dataset response:', response.status_code, response.json())

if __name__ == '__main__':
    token = test_login()
    if token:
        test_upload_dataset(token)