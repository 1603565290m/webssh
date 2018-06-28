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
配置文件`webssh/settings.py`

```
get_host_info_url  // CMDB接口地址
allow_origin  // 来源地址
```

#### 使用说明
 
- 直接访问  
  - 通过浏览器`http://127.0.0.1:8888`(按实际配置)，填写服务器信息即可登陆

- API方式
  - 需要配置`allow_orgin`否则请求将被拒绝
  - 配置`get_host_info_url`获取服务器认证信息
  - 页面需要引用`/`页面的`css`和`js`文件(也可自己实现)
  - 发生`options`请求`/auth`获取`_xsrf`值, 返回值格式`{"status": "success", "data": "_xsrf值"}`
  - 发送`post`请求类型为`application/json`并将`_xsrf`值携带到`header`中的`X-XSRFToken`上请求`/`获取`id`, `post data`需携带加密信息(服务端会拿着加密信息去`CMDB`获取服务器认证信息，需自己和`CMDB`系统协调该值), `post data`格式`{"data": "加密信息"}`
  - 发送`ws`请求`/ws?id=xx`,需携带`ID`
