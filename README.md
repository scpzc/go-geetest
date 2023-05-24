# go-geetest

go-geetest is Go library for GeeTest CAPTCHA.

## 引入

```go
import "github.com/scpzc/go-geetest/geetest"
```
### 生成

```go
g, _ := NewGeetest(id, key)
process, err := g.PreProcess("userID", true, "web", ip)
```

### 校验

```go
b, err = g.SuccessValidate(challenge, validate, seccode, "userID", "", "")    #服务器正常
b := g.FailValidate(challenge, validate)   #服务器宕机
```

