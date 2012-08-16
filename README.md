Stun Client php
=====================
学习网上的stun python脚本做了一个同功能的php版本
* * *

功能描述
-----------

> 检测本机网络环境

使用方法
----------

*	运行程序获取结果
php test.php
<pre><code>
NAT TYPE:Port Restricted NAT 3
MAPPED ADDRESS:218.17.55.162:15499
</code></pre>

*	找一个公共标准的Stun服务器，替换下面的服务器地址
<pre><code>
<?php
include_once("STUNClient.php");

//屏蔽socket通信警告
error_reporting(E_ERROR);

$sc = new STUNClient();

//$sc->setServerAddr("stun.ekiga.net"); 
//$sc->setServerAddr("stun.iptel.org");
$sc->setServerAddr("stunserver.org");
$sc->createSocket();

print("NAT TYPE:" . $sc->natType2String($sc->getNatType()) ."\n");
print("MAPPED ADDRESS:" . $sc->getMappedAddr() . "\n");
?>
</code></pre>

Weibo Account
-------------

Have a question? [@littley](http://weibo.com/littley)

