# webssh

#### 项目介绍
使用WebSocket通过浏览器连接linux，提供灵活的接口，可直接作为一个服务连接通过cmdb获取信息登陆服务器。基于https://github.com/huashengdun/webssh 二次开发

![](http://carey-akhack-com.oss-cn-hangzhou.aliyuncs.com/webssh/webssh.gif)

#### python版本

python >=2.7

#### 安装

```
git clone https://gitee.com/careyjike_173/webssh.git && cd webssh

pip install -r requirements.txt

python main.py
```

### 配置
配置文件`webssh/conf.py`

```
# 监听地址
listen = '127.0.0.1' 

# 监听端口
port = 8888 

# debug模式
debug = False  

# 日志文件
log_file_prefix = './logs/web_ssh.log'  

# 用户信息，用于其它系统请求认证，格式{"username": "password", "username1": "password1"}
auth = {
    'admin': 'admin'
}

# jwt secret值
secret = 'zzz'

# cmdb接口地址
cmdb_api = 'http://127.0.0.1:8000/cmdb/get/host/info/api/'

# ws进程延迟等待时间
delay = 3
```

#### 使用说明
 
- 直接访问  
  - 通过浏览器`http://127.0.0.1:8888`(按实际配置)，填写服务器信息即可登陆

- API方式
  
  - 页面需要引用`/`页面的`css`和`js`文件(也可自己实现)

  - `/auth` 认证接口, 发送`post`请求类型为`application/json`获取`token`, 返回值格式`{"status": "success", "data": "token值", "code": 0}`

  - `/` 获取资产认证并开启ws进程, 发送`post`请求类型为`application/json`并将`token`值携带到`header`中的`Token`上请求`/`获取`id`。 `post data`需携带加密信息(服务端会拿着加密信息去`CMDB`获取服务器认证信息，需自己和`CMDB`系统协调该值), `post data`格式`{"data": "加密信息"}`

  - 发送`ws`请求`/ws?id=xx`,需携带`ID`

##### js例子

- 获取认证信息

```
$.ajax({
  url: 'http://127.0.0.1:8888/auth',
  dataType: 'json',
  contentType: 'application/json',
  type: 'post',
  data: JSON.stringify({"username": "admin", "password": "admin"}),
  success: function (result) {
    if (result.code === 0){
      token = result.data;
      Cookies.set('token', token);
    } else {
      console.log(result);
      layer.msg("获取认证信息错误: "+ result.status)
    }
  },
  error: function () {
    layer.msg('请求错误!', {icon: 5})
  }
});
```

- 获取资产认证信息并生成ws进程

```
$.ajax({
  url: 'http://127.0.0.1:8888/',
  type: 'post',
  data: JSON.stringify(data),
  contentType: "application/json",
  processData: false,
  headers: {
    "Token": token
  },
  success: callback,
  error: function () {
    layer.closeAll('loading');
    layer.msg('请求错误!', {icon: 5})
  }
});
```
