Yingmi OpenAPI公共参数和api校验
=================================

Yingmi OpenAPI通过校验的形式确定Yingmi OpenAPI调用者（以下简称“调用者”）的合法性、身份、权限，以及保证请求本身没有被中间篡改。当调用者希望使用Yingmi OpenAPI时，应首先向Yingmi申请api key和api secret。其中，

* api key是一个唯一的代码用于识别调用者身份；
* api key是一段密文，用于产生请求签名。调用者应当非常小心地保管api key，不能够泄露。也不要在发送请求时传输它。

# 请求公共参数

每个调用OpenAPI请求都必须包含以下公共参数. 当请求的HTTP Method为GET时，公共参数以URL中的“query string的格式输入”；当请求的HTTP Method为POST时，公共参数以在请求体中的“x-www-form-urlencoded”格式或者URL中的“query string”格式输入。


| 参数名 | 示例   | 含义 |
|-------|-------|------|
| key |2762aee5-4fa8-437e-85af-1dbfbe466298| api key |
| sig | heBO3tbI1FHfhvt5x5cpswMlsCE= | 请求签名，产生方式详见下一节|
| sigVer | 1 | 签名算法版本，目前只支持“1” |
| ts |  2015-08-29T12:31:24.556 | 请求时间戳，格式为ISO8601格式。如果不带时区，默认为＋0800，即北京时间|
| nonce | zXwagyl3ksf | 请求随机字符串，用于保证即便同样的请求，每次产生的签名都不同。调用方应保证每次产生一个随机字符串. 最短8字符，最长32字符。 |

# 请求签名产生方法

签名的使用方式是

* 调用者在请求被发送前根据请求数据和api secret产生一个密钥，并作为请求参数`sig`的值。
* 盈米在服务器端根据请求数据和内部保存的api secret重新计算一个签名，并将其与请求中`sig`参数值比较。如果相同则视为校验通过，否则返回401 Unauthorized错误

为此，调用者和盈米OpenAPI必须采用相同的规则产生签名。


## 步骤1 获取HTTP方法名和URL Path

如果请求HTTP Method为Get，则方法名为“GET” （全大写）；如果为Post, 则方法名为“POST”(全大写)。

URL Path是指请求URL第一个base URL后，至Query String开始的部分。如“创建一个账户”的api URL为"https://api.yingmi.cn/v1/account/createAccount?accountName='浩宁'", 盈米openapi生产系统规定https://api.yingmi.cn/v1"
为Base Url。则Path为"/account/createAccount".

## 步骤2 将所有参数排序和拼接

将请求中query string和body中所有参数放到一起，按照参数名字典升序排序，以"参数名=参数值"格式拼接每一个参数，最后将所有参数用"&"拼接到一起。 这些拼接到一起的参数包括除sig之外的所有公共参数。


**注意**: 如果参数的值为空（例如"foo=&bar=4"中的foo），则该参数不参与拼接和计算。对于sig计算来说，可以认为他们不存在。

**注意**: 参数拼接过程在调用者应当发生在参数被URL Encoded之前；在盈米服务器端应该发生在参数被URL Encoded以后。拼接的参数不需要经过URL Encode，例如符号“&”，“：”或者中文等都应该保持原样。拼接过程与请求被传输过程中的编码过程是两件互不干扰的过程。

例如“创建账户”api请求的参数为:

| 参数名 | 参数值 |
|-------|-------|
| key |2762aee5-4fa8-437e-85af-1dbfbe466298|
| sigVer |1 |
| nonce |123456789 |
| ts | 2015-08-29T12:31:24.556|
| accountName | 浩宁 |
| identityType | 0 |
| identityNo |110101197310065272 |
| brokerUserId |lXzyp |
| paymentType | pay:Y |
| paymentNo | 123456|


拼接后得到的结果是

```
accountName=浩宁&brokerUserId=lXzyp&identityNo=110101197310065272&identityType=0&key=2762aee5-4fa8-437e-85af-1dbfbe466298&nonce=123456789&paymentNo=123456&paymentType=pay:Y&sigVer=1&ts=2015-08-29T12:31:24.556
```

## 步骤3 产生规范化字符串

将步骤1的HTTP方法名、URL Path和步骤2产生的结果用":"拼接。

```
unifiedString = {HTTP Method}:{HTTP Path}:{Params}
```

例如创建一个账户的请求拼接后的结果是：

```
POST:/account/createAccount:accountName=浩宁&brokerUserId=lXzyp&identityNo=110101197310065272&identityType=0&key=2762aee5-4fa8-437e-85af-1dbfbe466298&nonce=123456789&paymentNo=123456&paymentType=pay:Y&sigVer=1&ts=2015-08-29T12:31:24.556
```

## 步骤4 产生签名

将步骤3的结果根据api secret产生一个HMAC Sha1摘要，并且以Base64编码产生签名. 将步骤3的结果传入HMAC Sha1
进行计算时，要对字符串进行UTF8编码。大部分语言默认会采用UTF8编码。如果不是，需要明确的指定。

```
sig = base64HmacSha1(apiSecret, encode(unifiedString, 'utf-8'))
```

假如api secret是"MY3c6h402vU4dZNeHrRVnkP3rVWM4l8Az396Pu3KouAkyWKs", 则步骤3产生的摘要为

```
heBO3tbI1FHfhvt5x5cpswMlsCE=
```


# 参考实现

## Python

```python
import hmac
import hashlib
import base64

def get_sig(method, path, params, secret):
    if 'dig' in params: # sig doesn't participate in sig calculation
        del params['sig']
    unified_string = method + ':' + path + ':'
    param_names = params.keys()
    param_names.sort()
    params_kv = []
    for param_name in param_names:
        param_value = params_kv[param_name]
        if param_value != '' and param_value != None:
            continue # ignore all the params with empty value
        params_kv.append(param_name + "=" + param_value)
    unified_string += '&'.join(params_kv)
    digest = hmac.new(secret, unified_string, hashlib.sha1).digest()
    sig = base64.standard_b64encode(digest)
    return sig
```

## Java

```java
    String getSig(String method, String path, String apiSecret, Map<String, String> params) {
        StringBuilder sb = new StringBuilder();
        Set<String> keySet = new TreeSet<String>(params.keySet());
        for (String key: keySet) {
            String value = params.get(key);
            if (value == null || value.length == 0) {
                continue; // ignore all the params with empty value
            }
            sb.append(key);
            sb.append("=");
            sb.append(params.get(key));
            sb.append("&");
        }
        sb.setLength(sb.length() - 1); // trim the last "&"
        String unifiedString = method.toUpperCase() + ":" + path + ":" + sb.toString();

        // calc hmac sha1
        try {
            SecretKeySpec secret = new SecretKeySpec(apiSecret.getBytes(), "HmacSHA1");
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(secret);
            byte[] hmac = mac.doFinal(unifiedString.getBytes()); // UTF8 is the default encoding in java

            // base64 encode the hmac
            String sig = Base64.getEncoder().encodeToString(hmac);
            return sig;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }

        return null;
    }
```

## Nodejs

```javascript
var _ = require('lodash');

function getSig(method, path, params, secret) {
  delete params.sig; // sig doesn't participate in sig calculation
  var paramNames = _.keys(params).sort();
  var unifiedString = method + ':' + path + ':';
  var paramsKV = [];
  for (var paramName of paramNames) {
    var paramValue = params[paramName];
    if (paramValue === '' || paramValue === null || paramValue === undefined) {
        continue; // ignore all the params with empty value
    }
    paramsKV.push(paramName + '=' + paramValue);
  }
  unifiedString += paramsKV.join('&');

  var hash = crypto.createHmac('sha1', new Buffer(secret, 'utf-8')).update(new Buffer(unifiedString, 'utf-8')).digest('hex');
  var sig = new Buffer(hash).toString('base64');
  return sig;
}
```
