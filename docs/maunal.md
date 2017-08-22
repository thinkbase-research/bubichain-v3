## __编译__
### Linux
支持 Ubuntu、Centos 等大多数操作系统编译，下面编译步骤以 Ubuntu 14.04 示例
- 安装依赖

```bash
sudo apt-get install automake
sudo apt-get install autoconf
sudo apt-get install libtool
sudo apt-get install g++
sudo apt-get install libssl-dev
sudo apt-get install cmake
sudo apt-get install libbz2-dev
```
- 编译

```bash
cd bubichain
chmod + x ./autogen.sh
./autogen.sh
./configure
```
生成的可执行文件目录：src/main/bubi

### Windows
- 安装 Visual Studio Ulimate 2013
- 打开 bubichain\build\win32\Bubi.vs12.sln, 使用 VS 自带编译器编译即可。生成的可执行文件在bubichain\build\win32\dbin 目录下。

## __部署__
Windows 部署与 Linux 下部署基本类似，本示例以 Linux 为准。

### __目录结构__

目录 | 描述 
|:--- | --- 
| bin | 存放可执行文件（编译后的bubi可执行程序）
| config | 配置文件目录包含：bubi.json、ca.crt、entity.crt、entity_privkey.pem、dh2048.pem
| data | 数据库目录，存放账本数据
| script | 启停脚本目录
| log | 运行日志存储目录


### __节点部署__

### __运行__

### __配置__

#### config.json 

#### 加密数据配置
配置文件中所有隐私数据都是加密存储的，解密密钥都是被硬编码在程序中。所以拿到密码明文后需要经过如下转换才可配置：

- 命令./bin/bubi --aes-crypto [参数]

```bash
[root@localhost bubichain]# ./bin/bubi --aes-crypto root e2ba44bf0b27f0acbe7b5857e3bc6348
```
- 需加密配置项 

名称 | 描述 
|:--- | --- 
| config.p2p.private_password |证书解密密码
| config.validation.node_private_key | 共识节点私钥

#### __证书配置__
最新版本布比区块链默认启用节点证书接入，采用双向认证方式。

##### 相关文件

名称 | 描述 
|:--- | --- 
| ca.crt | 本区块链所有节点的根证书
| entity.crt | 本节点的证书，由根证书签发
| entity_privkey.pem | 节点证书密钥，使用时需解密。密码被加密配置在 config.p2p.private_password

##### 生产根证书
- 将bubi_ca文件放在bubichain/bin/下
- 配置config/ca.json

```json
{ "root" : { "file_name" : "ca", //根证书的名称"common_name" : "bubi", //证书签发机构名称"email" : "hr@bubi.cn", //证书签发机构邮箱"domain" : "www.bubi.cn", //证书签发机构网站"days" : 3650, //根证书有效期"private_password" : //根证书私钥密码 "42001df2a1f54974baa38073eae2ee53" }, "entity" : { "root_private_file" : "ca.pem", //根证书私钥名称"root_ca_file" : "ca.crt", //根证书名称"root_private_password" : //根证书私钥密码 "42001df2a1f54974baa38073eae2ee53","request_file" : "node_bubi.csr", //待签名文件"days" : 3650, //节点证书有效期"ca_enable" : true//是否开启ca验证 }, "logger" : { "path" : "log/bubi.log", "dest" : "FILESTDOUTSTDERR", "level" : "INFOWARNINGERRORFATAL", "time_capacity" : 1, "size_capacity" : 10, "expire_days" : 5 } }
```

- 执行./bin/bubi_ca--root

```bash
[root@localhost bubichain]# ./bin/bubi_ca --root root certificate file: /usr/local/bubichain/config/ca.crt private file: /usr/local/bubichain/config/ca.pem
```

- 在config下会生成ca.crt,ca.pem两个文件

##### 获取节点硬件地址

```bash
[root@localhost bubichain]# ./bin/bubi --hardware-addresslocal hardware address (0bc9143ba7ccc951cf257948af2d02ff)
```

##### 生成节点证书

- 请求证书的的命令./bin/bubi --request-cert 后加参数（全部英文）
- 参数解释
 
| 名称 | 描述
|:--- | --- 
|common_name |节点名称 
|organization |  组织机构名称 
| email | 联系邮箱 
|private_password | 证书私钥（明文）
| hardware_address |硬件地址（由上一步获取）
| node_id | 节点id，可不填
 
- 生成文件在bubichain/config目录下 node_bubi.csr：请求证书，node_bubi.pem：证书私钥

```bash
[root@localhost bubichain]# ./bin/bubi --request-cert //生成节点证书命令，参数含义 missing parameter, need 6 parameters (common_name, organization, email, private_password, hardware_address, node_id(when ignore, it's *) [root@localhost bubichain]# ./bin/bubi --request-cert node bubi bubi@bubi.cn bubitest 0bc9143ba7ccc951cf257948af2d02ff  request file : /usr/local/bubichain/config/node_bubi.csr private file : /usr/local/bubichain/config/node_bubi.pem 0bc9143ba7ccc951cf257948af2d02ff the request certificate information: { "ca" : { "extensions" : { "hardware_address" : "0bc9143ba7ccc951cf257948af2d02ff", "node_id" : "*" }, "subject" : { "common_name" : "node", "email" : "bubi@bubi.cn", "organization" : "bubi" } } }
```

##### 将证书发送给管理员

通过邮件或其他方式将node_bubi.csr文件发送给系统管理员，等待管理员签发证书

##### 管理员签发证书
- 修改config/ca.json配置文件中待签名文件名称
- 执行./bin/bubi_ca --entity
- 生成节点证书
- 将ca.crt及node_bubi.crt发送给用户

##### 接收管理员签发的证书
- 管理员对node_bubi.csr进行证书签发，生成node_bubi.crt
- 将生成node_bubi.crt文件及ca.crt文件发送给用户
- 将上面两个文件放到bubichain/config下
