# __布比区块链开发文档__

## __查询账号信息__

```http
GET /getAccount?address=a002423c235a7ba9649347ff85b6be1c51980d1eff0398&key=hello&code=xxx&issuer=xxx
```

|参数|描述
|:--- | --- 
| address | 账号地址， 必填
| key | 账号的 metadata 中指定的key的值，如果不填写，那么返回结果中含有所有的metadata
| code |资产代码
| issuer | 资产发行商

资产代码和资产发行商这两个变量要么同时填写，要么同时不填写。若不填写，返回的结果中包含所有的资产。

```json
{
  "error_code" : 0,
  "result" : {
    "address" : "a002423c235a7ba9649347ff85b6be1c51980d1eff0398",
    "assets" : [{
        "amount" : 1400,
        "property" : {
          "code" : "CNY",
          "issuer" : "a002423c235a7ba9649347ff85b6be1c51980d1eff0398"
        }
      }, {
        "amount" : 1000,
        "property" : {
          "code" : "USD",
          "issuer" : "a002423c235a7ba9649347ff85b6be1c51980d1eff0398"
        }
      }, {
        "amount" : 3000,
        "property" : {
          "code" : "zichanpingzheng",
          "issuer" : "a002943cede1be5fb0ca0da9f9b49b0ce20b613357524a"
        }
      }, {
        "amount" : 3000,
        "property" : {
          "code" : "CNY",
          "issuer" : "a002abcecded14a3068d2c535324980f41c7aeb8bf144c"
        }
      }
    ],
    "assets_hash" : "9696b03e4c3169380882e0217a986717adfc5877b495068152e6aa25370ecf4a",
    "contract" : null,
    "metadatas" : [{
        "key" : "123",
        "value" : "123_value",
        "version" : 1
      }, {
        "key" : "456",
        "value" : "456_value",
        "version" : 1
      }, {
        "key" : "abcd",
        "value" : "abcd_value",
        "version" : 1
      }
    ],
    "nonce" : 1,
    "priv" : {
      "master_weight" : "1",
      "thresholds" : {
        "tx_threshold" : "1"
      }
    },
    "storage_hash" : "82c8407cc7cd77897be3100c47ed9d43ec4097ee1c00e2c13447187e5b1ac66c"
  }
}


```
- 如果该账户不存在,则返回内容

```json
{
   "error_code" : 4,
   "result" : null
}
```


## __查询ledger__
```http
GET /getLedger?seq=xxxx&with_validator=true&with_consvalue=true
```
|参数|描述
|:--- | --- 
|seq  | ledger的序号， 如果不填写，返回当前ledger
|with_validator | true or false,附带验证节点列表
|with_consvalue | true or fasse,附带共识value

- 如果查询到ledger则返回内容:

```json
{
   "error_code" : 0,
   "result" : {
      "header" : {
         "account_tree_hash" : "945c729a8dace879bfca6d88077a6c7c6f1ffec55bb7b9398dde2e31c223905e",
         "close_time" : 1499682806032615,
         "consensus_value_hash" : "f418eefca74cbe95b1cda2cc3c20504dc90e9bcd1d995c8642c831c6bce91211",
         "hash" : "bfd1ca75335790b0f0e2dbbf822c09ddb73520abc314e56345466d17b8323d6a",
         "previous_hash" : "f1a586ba5d92b4aab10e40f424621a9ff284c07ae1e683d7036102d63a2e297c",
         "seq" : 6,
         "validators_hash" : "f8fa66d831ab39ea149525211e1a939b8d9fafbb19f7c4d6a4de18f998884f4c",
         "version" : 3000
      },
      "validators" : {
         "validators" : [
            "a0024740b934765287b16113adc6bb285d72c124d9e3c1",
            "a0022df150ad08ab8c238a44844bfe6f4f6576c1ab35c4"
         ]
      }
      ,
      "consensus_value" :{...}
   }
}
```

- 如果没有查询到ledger返回的内容:

``` json
{
   "error_code" : 4,
   "result" : null
}
```

## __查询交易__

```http
GET /getTransactionHistory?hash=ad545bfc26c440e324076fbbe1d8affbd8a2277858dc35927d425d0fe644e698
```

|参数|描述
|:--- | --- 
|hash | 交易的hash，是交易的唯一标识
|ledger_seq | ledger的序号

返回示例
```json
{
   "error_code" : 0,
   "result" : {
      "total_count" : 1,
      "transactions" : [
         {
            "close_time" : 1496652785322300,
            "error_code" : 0,
            "ledger_seq" : 8,
            "signatures" : [
               {
                  "public_key" : "b0020413806c5dd6fd473ab3ea7c484453ba2c07b41ff4d13832a49488bc3eec27c25f5c9f477eeb0e9953de10a8f3df956a979f4750b51efc59db6e7c2a998fdbda0acd",
                  "sign_data" : "4b5c4efb4f51a46fc1aa3989debf9fb02e4a9913f67f0fa796b704988ff97f037436669ba7d17a60c96a0c53d4a3bb7913c0c5dcfd29b2abac0ad9d8f58c0c78"
               },
               {
                  "public_key" : "b002043891953ca02a9decd4d5050385332b6599b11f2a2d34ee8edec541611b6e29e7ca992cf1998fb1fc41f51af30525d6e1119dfec74bf3405341b0eb79ee564ab7ce",
                  "sign_data" : "0bf9f4557150f894ddbc6b7bdce71b3b5fab7b761896a6a0c92d2a01956cdf44d423994e50b22704d0b43f62f0cd6caef6fdc223d4d9ef1e88b8644a250a66df"
               },
               {
                  "public_key" : "b002046ea5264d68f4407c7d449612b94f7603a50bd2e75ee9458c7b720b185e0be54986e7f9d9f6571434f7cb335e00be34addd16ce998a01a073db880a8262743f8a42",
                  "sign_data" : "7f82bffe5f9603728e341f3cdfa85d03523b6f9345ef0c5cb23076db091ddb124f96e5b23c5bf32fca7a77319333b789c22b370d556ae7543e12a96814294872"
               }
            ],
            "transaction" : {
               "nonce" : 1,
               "operations" : [
                  {
                     "create_account" : {
                        "dest_address" : "a002abcecded14a3068d2c535324980f41c7aeb8bf144c"
                     },
                     "type" : 1
                  },
                  {
                     "create_account" : {
                        "dest_address" : "a002943cede1be5fb0ca0da9f9b49b0ce20b613357524a"
                     },
                     "type" : 1
                  },
                  {
                     "create_account" : {
                        "dest_address" : "a002385d3017771162b353e9af4c11edb66c665abcfcb6"
                     },
                     "type" : 1
                  },
                  {
                     "create_account" : {
                        "dest_address" : "a002423c235a7ba9649347ff85b6be1c51980d1eff0398"
                     },
                     "type" : 1
                  },
                  {
                     "issue_asset" : {
                        "amount" : 10000000,
                        "code" : "CNY"
                     },
                     "source_address" : "a002abcecded14a3068d2c535324980f41c7aeb8bf144c",
                     "type" : 2
                  }
               ],
               "source_address" : "a0025e6de5a793da4b5b00715b7774916c06e9a72b7c18"
            }
         }
      ]
   }
}
```

如果该交易不存在则返回

```json
{
   "error_code" : 4,
   "result" : {
      "total_count" : 0,
      "transactions" : []
   }
}
```

## __配置验证节点__

```http
POST /confValidator?add=a00252641e461a28e0f2d19e01fa9ce4ba89af24d5f0c6&&del=a0027fb6fd8e8ffbf64cf10efebd9278735d5e39a6325e
```

|参数|描述
|:--- | --- 
|add |逗号分隔的需要添加的验证节点列表
|del |逗号分隔的需要删除的验证节点列表

注：需要大部分的验证节点都执行添加、删除操作，且共识成功后才能添加、删除成功


## __获取交易序列化数据__

|参数|描述
|:--- | --- 
|source_address |交易发起者的地址
|nonce |序号，相当于seq，通过getAccount获取，如果没有则为0
|operations | 操作列表

```http
POST /getTransactionBlob
```

```json
{
  "source_address" : "a0025e6de5a793da4b5b00715b7774916c06e9a72b7c18",
  "nonce" : 130,
  "operations" : [{
      "ps" : "根据不同的操作类型填写"
    }, {
      "ps" : "根据不同的操作类型填写"
    }
  ]
}
```


## __提交交易__

|参数|描述
|:--- | --- 
|transaction_blob| 交易序列化之后的16进制格式
|sign_data| 签名16进制格式
|public_key| 公钥

```http
POST /submitTransaction
```

```json
{
  "items" : [{
      "transaction_blob" : "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
      "signatures" : [{
          "sign_data" : "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
          "public_key" : "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
        }, {
          "sign_data" : "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
          "public_key" : "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
        }
      ]
    }
  ]
}
```

### __交易字段公共字段__

|参数|描述
|:--- | --- 
|source_address | 交易发起人地址， required
|nonce| 交易序号,required
|expr_condition|表达式字段, optional
|metadata|交易的元数据, optional

### expr_condtion 表达式规则
该表达式字段，用于自定义交易有效规则，比如设置交易在某个账户的master_weight 大于 100 有效，则填：
jsonpath(account(\"bubiV8i6mtcDN5a1X7PbRPuaZuo63QRrHxHGr98s\"), \".priv.master_weight\") > 100

#### expr_condtion内部函数


|参数|描述
|:--- | --- 
|account(address)| 获取账户信息, 返回 json 序列化字符串
|ledger(nonce) | 获取区块信息, 返回 json 序列化字符串
|jsonpath(json_string, path)| 获取json对象的属性值 
|LEDGER_SEQ| 内置变量，代表最新的区块高度
|LEDGER_TIME|内置变量，代表最新的区块生成时间

### 操作

操作有4个共同属性

|参数|描述
|:--- | --- 
|source_address| 指哪个账号做此操作,若为空或不填写，默认与交易发起者相同， optional
|type|表示该操作的类型， required
|metadata|操作的 metadata 值，16进制表示， optional
|expr_condition|操作的表达式限制， optional


#### 操作类型
操作类型代码 | 操作类型名称 | 说明
|:--- | --- | --- |
1 | 创建帐号 | 用来新建帐号
2 | 发行资产 | 
3 | 转移资产 | 调用此接口可以将自定义资产转给另一个帐号
4 | 设置metadata     |  设置账号属性 key / value 值
5 | 设置Signer Weight | 设置账号权重，包括master 和 signer
6 | 设置Threshold | 设置门限值，包括默认门限或具体操作门限
7 | 调用合约


#### 1. 创建账号

|参数|描述
|:--- | --- 
|dest_address |  账号的地址
|contract|  如果不填写，那么这是一个普通的账号。如果填写，那么这是一个合约账号
| priv|  该账号的权限信息

```json

 {
   "type" : 1,
   "create_account" :
   {
     "dest_address" : "a0026f43f60f511c8260b9ded0c830de6109b3bbeb06c7", //required
     "contract" : //optional
     {
       "contract_id" : "something identify this contract",
       "payload" : "function Main(input) {  var a = callBackGetAccountInfo('a0025e6de5a793da4b5b00715b7774916c06e9a72b7c18');  if (a) callBackLog(a);  var b = callBackGetAccountMetaData('a0025e6de5a793da4b5b00715b7774916c06e9a72b7c18', input['key']);  if (b) callBackLog(b);  var tx = { 'operations' : [{ 'type' : 'ISSUE_ASSET', 'source_address' : 'a0025e6de5a793da4b5b00715b7774916c06e9a72b7c18', 'issue_asset' : {  'code' : 'cny',  'amount' : input.amount }  } ]  };  callBackDoOperation(tx); } "
     },
     "metadatas" : [
        {
          "key" : "111",
          "value" : "hello 111!",
          "version" : 0
        },
        {
          "key" : "222",
          "value" : "hello 222!",
          "version" : 0
        }
     ],
     "priv" :  //required
     {
       "master_weight" : 10, //optional, default 0, [0, MAX(UINT32)]
       "signers" : [      //optional
         {
           "address" : "a002d225e3e52fa8b341105d2109c0be0a90749ee42b21",
           "weight" : 6
         }
       ],
       "thresholds" : //required
       {
         "tx_threshold" : 7, //optional,  default 0, [0, MAX(INT64)]
         "type_thresholds" : [  //optional
           {
             "type" : 1,
             "threshold" : 8
           },
           {
             "type" : 2,
             "threshold" : 5
           }
         ]
       }
     }
   }
 }
```

#### 2. 发行资产

```json

{
  "type" : 2,
  "issue_asset" :
  {
    "amount" : 1000,
    "code" : "CNY"
  }
}
```


#### 3. 转移资产/调用合约
该操作先把指定的资产转给目标账号，然后调用目标账号的合约代码并以input作为入参。
若目标账号没有合约代码，则只进行转移资产操作。

```json

{
  "type" : 3,
  "payment" :
  {
    "dest_address" : "a002f22d29d38b3a4f0afb3689f24c580529c05454a20c",
    "asset" :
    {
      "property" :
      {
        "issuer" : "a002d5905562ba1a32d7879c73131d68c5814526ff62b4",
        "code" : "CNY"
      },
      "amount" : 100
    },
    "input":"{\"bar\":\"foo\"}"
  }
}
```


#### 4. 设置metadata
设置账号的metadata属性，metadata 是一个key-value 结构，可存储多个键值对。

|参数|描述
|:--- | --- 
| key  |required，length:(0, 256]
| value  |optional，length:(0, 1048576]
| version |optional，default 0, 0：不限制版本，>0 : 当前 value 的版本必须为该值， <0 : 非法

每次可设置多个。

```json
{
  "type" : 4,
  "set_metadata" :
      {
        "key" : "abc",
        "value" : "hello abc!",
        "version" : 0
      }
}
```
---

#### 5. 设置Signer Weight
设置账号的签名属性
- master_weight optional，default 0， -1 ： 不设置该值，0：设置master权重值为0， >0 && <= MAX(UINT32)：设置权重值为该值，其他：非法
- address 需要操作的 signer 地址，符合地址校验规则。
- weight  optional，default 0, 0 ：删除该signer，>0 && <= MAX(UINT32)：设置权重值为该值，其他：非法

```json
{
    "type" : 5,
    "set_signer_weight" : { 
         "master_weight" : 2, 
         "signers" : [ 
            { 
               "address" : "a002ebe7a1c703f90f1c7ecdd7bc6bc4b3ab01f3563f80", 
               "weight" : 2 
            } 
         ] 
      }
}
```

#### 6. 设置Threshold
设置账号操作的权限

|参数|描述
|:--- | --- 
|tx_threshold |optional，default 0, 表示该账号的最低权限，-1: 表示不设置该值，>0 && <= MAX(INT64)：设置权重值为该值，其他：非法
|type |表示某种类型的操作  (0, 100]
|threshold | optional，default 0, 0 ：删除该类型操作，>0 && <= MAX(INT64)：设置权重值为该值，其他：非法

```json
{
    "type" : 6,
    "set_threshold": {
        "tx_threshold": 7,
        "type_thresholds":[
            {
                "type":1,
                "threshold":8
            },
            {
                "type":2,
                "threshold":5
            }
        ]  
    }
}
```

# __如何写合约__
合约是一段JavaScript代码，系统要求实现main函数，该函数也是合约执行过程中的入口函数。
该函数的入参是字符串input，是调用该合约的时候指定的。

下面是一个简单的例子

```javascript
function foo(bar)
{
  /*do whatever you want*/

}

function main(input)
{
  var para = JSON.parse(input);
  if (para.do_foo)
  {
    var x = {
      'hello' : 'world'
    };
    foo(x);
  }
}
```

系统提供了几个全局函数, 这些函数可以获取区块链的一些信息，也可驱动账号发起交易

### 1. 获取账号信息(不包含metada和资产)

callBackGetAccountInfo(address);
- address: 账号地址

例如
``` javascript
var account = callBackGetAccountInfo('a0025e6de5a793da4b5b00715b7774916c06e9a72b7c18');
/*
account具有如下格式
 {
    "address": "a002943cede1be5fb0ca0da9f9b49b0ce20b613357524a",
    "assets_hash": "5aef61a8988ce2be1da67cf4b37717748c352b8e4a0bdad2ad0964f80aca0101",
    "contract": null,
    "priv": null,
    "storage_hash": "e4775fb7fc2a5a06a4bbe0e63f362f8e24ff7752f0259ccd2fe1fc2e6e68781a"
  }
*/
```

### 2. 获取某个账号的metadata信息
callBackGetAccountMetaData(account_address, metadata_key);
- account_address: 账号地址
- metadata_key： metadata的key

例如
```javascript
var bar = callBackGetAccountMetaData('a0025e6de5a793da4b5b00715b7774916c06e9a72b7c18','abc');
/*
 bar的值是如下的格式
 {
     'key':'abc',
     'value':'hello world',
     'version':12
 }
*/

```
即可得到账号a0025e6de5a793da4b5b00715b7774916c06e9a72b7c18的metadata中abc的值

### 3.  获取某个账号的资产信息
callBackGetAccountAsset(account_address, asset_property);

- account_address: 账号地址
- asset_property： 资产属性

例如
```javascript
var asset_property =
{
  'issuer' : 'a002bbe0b6f547d6bec2c83fb9bb93e75d37c1755f2de6',
  'code' : 'CNY'
};
var bar = callBackGetAccountAsset('a0025e6de5a793da4b5b00715b7774916c06e9a72b7c18', asset_property);

/*
{
  "amount": 1,
  "property": {
    "code": "CNY",
    "issuer": "a002bbe0b6f547d6bec2c83fb9bb93e75d37c1755f2de6"
  }
}
*/
```

### 4.  获取交易
callBackGetTransactionInfo(hash);
- hash: 交易hash

例如
```javascript
var tx = callBackGetTransactionInfo('ea565a904d568368f4ab556bb20c3f3933411f72ef487e8f73eddbc6d7b84565');
```

### 5. 获取区块信息
callBackGetLedgerInfo(ledger_seq);
- ledger_seq: 区块号

例如
```javascript
var ledger = callBackGetLedgerInfo(40);
/*
ledger具有如下格式
{
    "account_tree_hash": "af05a60772cfd39f3b7838f4032f50450c100dedddf88e0132066688f6ae5c14",
    "consensus_value": {
      "close_time": 1495855656157405,
      "payload": "240398d89a5efba398fefb0dc194b45abe7b9dbc35326ee8238fff6633371004"
    },
    "hash": "9f82d8ad1c381e1ce2ce00c559fb2cf3a386d79e9414e92ce3ed809258913384",
    "ledger_sequence": 40,
    "ledger_version": 1000,
    "previous_hash": "3ff9b79479d62e7c52f2c0ab08598d219ffd4403bd5c1337764d3591e9b0ba24",
    "transaction_tree_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "tx_count": 34359738368
  }
*/

```

### 6.  该合约账号的地址
全局变量  ThisAddress

全局变量ThisAddress的值等于该合约账号的地址。

例如账号x发起了一笔交易调用合约Y，本次执行过程中，ThisAddress的值就是Y合约账号的地址。

```javascript
var bar = ThisAddress;
/*
bar的值是Y合约的账号地址。
*/
```

### 7.  调用者的地址
全局变量  Sender

全局变量Sender的值等于本次调用该合约的账号。

例如某账号发起了一笔交易，该交易中有个操作是调用合约Y（该操作的source_address是x），那么合约Y执行过程中，Sender的值就是x账号的地址。

```javascript
var bar = Sender;
/*
那么bar的值是x的账号地址。
*/
```


### 8.  做交易
令合约账号做一笔交易，即里面的任意一个操作的source_address都会自动变成合约账号。
所以source_address是不需要填写的，即使填写也无用。

callBackDoOperation(transaction);
- transaction: 交易内容
返回: true/false



例如
```javascript
var transaction =
{
  'operations' :
  [
    {
      "type" : "ISSUE_ASSET",
      "issue_asset" :
      {
        "amount" : 1000,
        "code" : "CNY"
      }
    }
  ]
};

var result = callBackDoOperation(transaction);
```

### 9.  设置本合约账号的metadata
callBackSetAccountMetaData(KeyPair);
- KeyPair: 要设置的内容
返回:true/false
例如

```javascript
var KeyPair =
{
  'key' : 'abc',
  'value' : 'hello',
  'version' : 2
};

var result = callBackSetAccountMetaData(KeyPair);
```

**注意: 此函数相当于合约账号发起一笔交易，该交易的操作是设置自身的metadata。** 

即和如下用法等价：

```javascript
var transaction =
{
  'operations' :
  [
    {
      "type" : "SET_METADATA",
      "set_metadata" :
      {
        'key' : 'abc',
        'value' : 'hello',
        'version' : 2
      }
    }
  ]
};

var result = callBackDoOperation(transaction);
```
其中```version```可以不填写。
- 如果version有值且不为0，其值需要和当前的version匹配才能设置成功。
- 如果不填写或version为0，那么系统不需要匹配当前version即可设置成功。

## __错误码__
错误由两部分构成:
- error_code : 错误码，大概的错误分类
- error_desc : 错误描述，一般能从错误描述准确发现错误具体信息

错误列表如下：

error_code | enum | error_desc
|:--- | --- | --- |
0  | ERRCODE_SUCCESS | 操作成功
1  | ERRCODE_INTERNAL_ERROR | 服务内部错误
2  | ERRCODE_INVALID_PARAMETER | 参数错误
3  | ERRCODE_ALREADY_EXIST | 对象已存在， 如重复提交交易
4  | ERRCODE_NOT_EXIST | 对象不存在，如查询不到账号、TX、区块等
5  | ERRCODE_TX_TIMEOUT | TX 超时，指该 TX 已经被当前节点从 TX 缓存队列去掉，==但并不代表这个一定不能被执行==
20  | ERRCODE_EXPR_CONDITION_RESULT_FALSE | 指表达式执行结果为 false，意味着该 TX 当前没有执行成功，==但这并不代表在以后的区块不能成功==
21  | ERRCODE_EXPR_CONDITION_SYNTAX_ERROR | 指表达式语法分析错误，代表该 TX 一定会失败
90  | ERRCODE_INVALID_PUBKEY | 公钥非法 
91  | ERRCODE_INVALID_PRIKEY | 私钥非法
92  | ERRCODE_ASSET_INVALID | 资产issue 地址非法，或者 code 长度不在有效范围内
93  | ERRCODE_INVALID_SIGNATURE | 签名权重不够，达不到操作的门限值
94  | ERRCODE_INVALID_ADDRESS | 地址非法
95  | ERRCODE_TIME_NOT_IN_RANGE | 不在有效时间范围内
96  | ERRCODE_NO_NETWORK_CONSENSUS | 
97  | ERRCODE_MISSING_OPERATIONS | TX 确实操作
98  | ERRCODE_LAGER_OPERATIONS | 
99  | ERRCODE_BAD_SEQUENCE | 序列号错误
100 | ERRCODE_ACCOUNT_LOW_RESERVE | 
101 | ERRCODE_ACCOUNT_SOURCEDEST_EQUAL | 源目的账号相等
102 | ERRCODE_ACCOUNT_DEST_EXIST | 创建账号操作，目标账号已存在
103 | ERRCODE_ACCOUNT_NOT_EXIST | 账户不存在
104 | ERRCODE_ACCOUNT_ASSET_LOW_RESERVE | 支付操作，资产余额不足
105 | ERRCODE_ACCOUNT_ASSET_AMOUNT_TOO_LARGE |
110 | ERRCODE_SEQNUMBER_NOT_MATCH | 
114 | ERRCODE_OUT_OF_TXCACHE |  TX 缓存队列已满
120 | ERRCODE_WEIGHT_NOT_VALID | 权重值不在有效范围内
121 | ERRCODE_THRESHOLD_NOT_VALID | 门限值不在有效范围内
131 | ERRCODE_INPUT_NOT_EXIST |
144 | ERRCODE_INVALID_DATAVERSION | version 版本号不与账号匹配
150 | ERRCODE_CONTRACT_EXISTS |
151 | ERRCODE_CONTRACT_EXECUTE_FAIL | 合约执行失败
152 | ERRCODE_CONTRACT_SYNTAX_ERROR | 合约语法分析失败

## __交易码__

type | enum | 交易说明
|:--- | --- | --- |
1  | CREATE_ACCOUNT | 创建账号
2  | ISSUE_ASSET | 发行资产
3  | PAYMENT | 转移资产
4  | SET_METADATA | 设置metadata
5  | SET_SIGNER_WEIGHT | 设置signerweight
6  | SET_THRESHOLD | 设置threshold
7  | INVOKE_CONTRACT | 调用合约