<?php


/**
 * RET_VALUE
 * 
 * @package 
 * @author ciaos
 * @copyright 2012
 * @access public
 */
class RET_VALUE
{
    static $_RET_TEST_I1_UDP_BLOCKED = 0;
    static $_RET_TEST_I1_IP_SAME = 1;
    static $_RET_TEST_I1_IP_DIFF = 2;
    static $_RET_TEST_II_NO_RESP = 3;
    static $_RET_TEST_II_GOT_RESP = 4;
    static $_RET_TEST_I2_IP_SAME = 5;
    static $_RET_TEST_I2_IP_DIFF = 6;
    static $_RET_TEST_III_NO_RESP = 7;
    static $_RET_TEST_III_GOT_RESP = 8;
    static $_RET_TEST_IV_LOCAL = 9;
    static $_RET_TEST_IV_DIFF = 10;
};

/**
 * NAT_TYPE
 * 
 * @package   
 * @author ciaos
 * @copyright 2012
 * @access public
 */
class NAT_TYPE
{
    static $_NAT_TYPE_OPENED = 0;       //拥有公网IP
    static $_NAT_TYPE_FULLCONE_NAT = 1; //
    static $_NAT_TYPE_REST_NAT = 2;     //限制地址
    static $_NAT_TYPE_PORTREST_NAT = 3; //限制端口
    static $_NAT_TYPE_SYM_UDP_FIREWALL = 4; //防火墙
    static $_NAT_TYPE_SYM_NAT_LOCAL = 5;
    static $_NAT_TYPE_SYM_NAT = 6;      //对称型
    static $_NAT_TYPE_UDP_BLOCKED = 7;  //防火墙限制UDP通信
}

/**
 * STUNClient
 * 
 * @package   
 * @author ciaos
 * @copyright 2012
 * @access public
 */
class STUNClient{
    
    private $socket;
    
    private $serverIP;
    private $serverPort;
    private $localIP;
    private $localPort;
    
    private $mappedIP;
    private $mappedPort;
    private $changedIP;
    private $changedPort;
    
    //Message Type
    private $_BindingRequest = 0x0001;
    private $_BindingResponse = 0x0101;
    private $_BindingErrorReponse = 0x0111;
    
    //Message Attribute Types
    private $_MAPPED_ADDRESS = 0x0001;
    private $_CHANGE_REQUEST = 0x0003;
    private $_CHANGED_ADDRESS = 0x0005;
    private $_ERROR_CODE = 0x0009;
    
    protected $_TID1 = 0x00005555;
    protected $_TID2 = 0x01234567;
    protected $_TID3 = 0x00abcdef;
    protected $_TID4 = 0x00000000;
    
    protected $_BUFLEN = 4096;
    protected $_TIMEOUT = 3;
    
    /**
     * STUNClient::setServerAddr()
     * 
     * @param mixed $host
     * @param integer $port
     * @return
     */
    public function setServerAddr($host,$port = 3478){
        
        if(preg_match("/^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/",$host,$res) == false){
            $this->serverIP = gethostbyname($host);
        }
        else{
            $this->serverIP = $host;
        }
        $this->serverPort = $port;
    }
    
    /**
     * STUNClient::createSocket()
     * 
     * @return
     */
    public function createSocket(){
        $this->socket = socket_create(AF_INET,SOCK_DGRAM,getprotobyname("udp"));
        socket_set_nonblock($this->socket);
    }
    
    /**
     * STUNClient::getLocalIPPort()
     * 
     * @return
     */
    private function getLocalIPPort()
    {
        $s = socket_create(AF_INET,SOCK_STREAM,getprotobyname("tcp"));
        socket_connect($s,"www.google.com",80);
        socket_getsockname($s,$this->localIP,$this->localPort);
    }
    
    /**
     * STUNClient::testI1()
     * 
     * 发送给Stun服务器的UDP包，检测能否接受，并比较外网映射IP
     * 
     * @return 
     */
    private function testI1(){
        
        $msg = pack("nnNNNN",$this->_BindingRequest, 0,
            $this->_TID1,$this->_TID2,$this->_TID3,$this->_TID4);

        socket_sendto($this->socket,$msg,strlen($msg),0,$this->serverIP,$this->serverPort);
     
        $st = time();
        $block = true;
        while(time() - $st < $this->_TIMEOUT){
          
            socket_recvfrom($this->socket,$data,$this->_BUFLEN,0,$remoteIP,$remotePort);
            if($remoteIP != $this->serverIP or $remotePort != $this->serverPort){
                continue;
            }
            if(strlen($data) < 20){
                continue;
            }
            
            $retInfo = unpack("nmsg/nlen/N4tid",substr($data,0,20));
            
            if($retInfo["msg"] != $this->_BindingResponse){
                continue;
            }
            if(!$again && $retInfo["len"] != strlen($data) - 20){
                continue;
            }
            if(!$again && ($retInfo["tid1"]!=$this->_TID1 or $retInfo["tid2"]!=$this->_TID2 or
                $retInfo["tid3"]!=$this->_TID3 or $retInfo["tid4"]!=$this->_TID4)){
                continue;
            }
            $block = false;
            break;
        }
        $this->_TID4 += 1;
        if($block == true){
            return RET_VALUE::$_RET_TEST_I1_UDP_BLOCKED;
        }
        
        $restLen = strlen($data) - 20;
        $restIdx = 20;
        while(true){
            if($restLen < 4){
                break;
            }
            $mah = substr($data,$restIdx,4);
            $restLen -= 4;
            $restIdx += 4;
            $info = unpack("ntag/nlen",$mah);
            if($info["len"] > $restLen){
                return null;
            }
            
            $v = substr($data,$restIdx,$info["len"]);
            $restLen -= $info["len"];
            $restIdx += $info["len"];
            if($info["tag"] == $this->_MAPPED_ADDRESS){
                if($info["len"] != 8){
                    return null;
                }
                $info = unpack("Cfirst/Cflag/nport/C4s",$v);
                if($info["flag"] != 1){
                    return null;
                }
                $this->mappedIP = sprintf("%u.%u.%u.%u",$info["s1"],$info["s2"],$info["s3"],$info["s4"]);
                $this->mappedPort = $info["port"];
            }
            elseif($info["tag"] == $this->_CHANGED_ADDRESS){
                if($info["len"] != 8){
                    return null;
                }
                $info = unpack("Cfirst/Cflag/nport/C4s",$v);
                if($info["flag"] != 1){
                    return null;
                }
                $this->changedIP = sprintf("%u.%u.%u.%u",$info["s1"],$info["s2"],$info["s3"],$info["s4"]);
                $this->changedPort = $info["port"];
            }
        }
        $this->getLocalIPPort();
        if($this->localIP == $this->mappedIP and $this->localPort == $this->mappedPort){
            return RET_VALUE::$_RET_TEST_I1_IP_SAME;
        }
        return RET_VALUE::$_RET_TEST_I1_IP_DIFF;
    }
    
    /**
     * STUNClient::testII()
     * 
     * 通知服务器换一个端口与IP返回信息
     * 
     * @return
     */
    private function testII(){
        
        $msg = pack("nnNNNNnnCCCC",$this->_BindingRequest, 8,
            $this->_TID1,$this->_TID2,$this->_TID3,$this->_TID4,
            $this->_CHANGE_REQUEST, 4, 0, 0, 0, 6);

        socket_sendto($this->socket,$msg,strlen($msg),0,$this->serverIP,$this->serverPort);
        
        $st = time();
        while(time() - $st < $this->_TIMEOUT){
            
            $again = false;
          
            socket_recvfrom($this->socket,$data,$this->_BUFLEN,0,$remoteIP,$remotePort);
            if($remoteIP != $this->changedIP or $remotePort != $this->changedPort){
                continue;
            }
            if(strlen($data) < 20){
                continue;
            }
            
            $retInfo = unpack("nmsg/nlen/N4tid",substr($data,0,20));
            
            if($retInfo["msg"] != $this->_BindingResponse){
                $again = true;
            }
            if(!$again && $retInfo["len"] != strlen($data) - 20){
                $again = true;
            }
            if(!$again && ($retInfo["tid1"]!=$this->_TID1 or $retInfo["tid2"]!=$this->_TID2 or
                $retInfo["tid3"]!=$this->_TID3 or $retInfo["tid4"]!=$this->_TID4)){
                $again = true;
            }
            if(!$again){
                return RET_VALUE::$_RET_TEST_II_GOT_RESP;
            }
        }
        $this->_TID4 += 1;
        return RET_VALUE::$_RET_TEST_II_NO_RESP;
    }
    /**
     * STUNClient::testI2()
     * 
     * 向更换后的服务器IP与Port通信并检测能否接收数据
     * 
     * @return
     */
    private function testI2(){
        $mappedIP = "";
        
        $msg = pack("nnNNNN",$this->_BindingRequest, 0,
            $this->_TID1,$this->_TID2,$this->_TID3,$this->_TID4);

        socket_sendto($this->socket,$msg,strlen($msg),0,$this->changedIP,$this->changedPort);
        
        $st = time();
        while(time() - $st < $this->_TIMEOUT){
            
            socket_recvfrom($this->socket,$data,$this->_BUFLEN,0,$remoteIP,$remotePort);
            if($remoteIP != $this->changedIP or $remotePort != $this->changedPort){
                continue;
            }
            
            if(strlen($data) < 20){
                continue;
            }
            $retInfo = unpack("nmsg/nlen/N4tid",substr($data,0,20));
            
            if($retInfo["msg"] != $this->_BindingResponse){
                continue;
            }
            if(!$again && $retInfo["len"] != strlen($data) - 20){
                continue;
            }
            if(!$again && ($retInfo["tid1"]!=$this->_TID1 or $retInfo["tid2"]!=$this->_TID2 or
                $retInfo["tid3"]!=$this->_TID3 or $retInfo["tid4"]!=$this->_TID4)){
                continue;
            }
            break;
        }
        $this->_TID4 += 1;
        
        $restLen = strlen($data) - 20;
        $restIdx = 20;
        while(true){
            if($restLen < 4){
                break;
            }
            $mah = substr($data,$restIdx,4);
            $restLen -= 4;
            $restIdx += 4;
            $info = unpack("ntag/nlen",$mah);
            if($info["len"] > $restLen){
                return null;
            }
            
            $v = substr($data,$restIdx,$info["len"]);
            $restLen -= $info["len"];
            $restIdx += $info["len"];
            if($info["tag"] == $this->_MAPPED_ADDRESS){
                if($info["len"] != 8){
                    return null;
                }
                $info = unpack("Cfirst/Cflag/nport/C4s",$v);
                if($info["flag"] != 1){
                    return null;
                }
                $mappedIP = sprintf("%u.%u.%u.%u",$info["s1"],$info["s2"],$info["s3"],$info["s4"]);
                $mappedPort = $info["port"];
            }
        }
        if($mappedIP == ""){
            return null;
        }
        if($mappedIP == $this->mappedIP and $mappedPort == $this->mappedPort){
            return RET_VALUE::$_RET_TEST_I2_IP_SAME;
        }
        else{
            return RET_VALUE::$_RET_TEST_I2_IP_DIFF;
        }
    }
    /**
     * STUNClient::testIII()
     * 
     * 通知服务器用同IP但是是另外一个端口返回信息
     * 
     * @return
     */
    private function testIII(){
        
        $msg = pack("nnNNNNnnCCCC",$this->_BindingRequest, 8,
            $this->_TID1,$this->_TID2,$this->_TID3,$this->_TID4,
            $this->_CHANGE_REQUEST, 4, 0, 0, 0, 2);

        socket_sendto($this->socket,$msg,strlen($msg),0,$this->serverIP,$this->serverPort);

        $st = time();
        while(time() - $st < $this->_TIMEOUT){
            
            socket_recvfrom($this->socket,$data,$this->_BUFLEN,0,$remoteIP,$remotePort);
            if($remoteIP != $this->serverIP or $remotePort != $this->changedPort){
                continue;
            }
            if(strlen($data) < 20){
                continue;
            }
            
            $retInfo = unpack("nmsg/nlen/N4tid",substr($data,0,20));
            
            if($retInfo["msg"] != $this->_BindingResponse){
                continue;
            }
            if(!$again && $retInfo["len"] != strlen($data) - 20){
                continue;
            }
            if(!$again && ($retInfo["tid1"]!=$this->_TID1 or $retInfo["tid2"]!=$this->_TID2 or
                $retInfo["tid3"]!=$this->_TID3 or $retInfo["tid4"]!=$this->_TID4)){
                continue;
            }
            return RET_VALUE::$_RET_TEST_III_GOT_RESP;
        }
        $this->_TID4 += 1;
        return RET_VALUE::$_RET_TEST_III_NO_RESP;
    }
    
    /**
     * STUNClient::testIV()
     * 
     * @return
     */
    private function testIV(){
        $sock = socket_create(AF_INET, SOCK_DGRAM , getprotobyname("udp"));
        socket_set_nonblock($sock);
        
        $msg = pack("nnNNNN",$this->_BindingRequest, 0,
            $this->_TID1,$this->_TID2,$this->_TID3,$this->_TID4);
        
        $resp1 = "";
        $resp2 = "";
        
        socket_sendto($sock,$msg,strlen($msg),0,$this->serverIP,$this->serverPort);
        socket_sendto($sock,$msg,strlen($msg),0,$this->changedIP,$this->changedPort);
        
        $st = time();
        while(time() - $st < $this->_TIMEOUT){
            
            socket_recvfrom($sock,$data,$this->_BUFLEN,0,$remoteIP,$remotePort);
            if(strlen($data) < 20){
                continue;
            }
            
            $retInfo = unpack("nmsg/nlen/N4tid",substr($data,0,20));
            
            if($retInfo["msg"] != $this->_BindingResponse){
                continue;
            }
            if($retInfo["len"] != strlen($data) - 20){
                continue;
            }
            if($retInfo["tid1"]!=$this->_TID1 or $retInfo["tid2"]!=$this->_TID2 or
                $retInfo["tid3"]!=$this->_TID3 or $retInfo["tid4"]!=$this->_TID4){
                continue;
            }

            if($resp1 == "" && ($remoteIP == $this->serverIP and $remotePort == $this->serverPort)){
                $resp1 = $data;
            }
            if($resp2 == "" && ($remoteIP == $this->changedIP and $remotePort == $this->changedPort)){
                $resp2 = $data;
            }
            if($resp1 != "" and $resp2 != ""){
                break;
            }
        }
        $this->_TID4 += 1;
        socket_close($sock);

        $mappedIP1 = "";
        $mappedIP2 = "";
        
        $restLen = strlen($resp1) - 20;
        $restIdx = 20;
        while(true){
            if($restLen < 4){
                break;
            }
            $mah = substr($resp1,$restIdx,4);
            $restLen -= 4;
            $restIdx += 4;
            $info = unpack("ntag/nlen",$mah);
            if($info["len"] > $restLen){
                return null;
            }
            
            $v = substr($resp1,$restIdx,$info["len"]);
            $restLen -= $info["len"];
            $restIdx += $info["len"];
            if($info["tag"] == $this->_MAPPED_ADDRESS){
                if($info["len"] != 8){
                    return null;
                }
                $info = unpack("Cfirst/Cflag/nport/C4s",$v);
                if($info["flag"] != 1){
                    return null;
                }
                $mappedIP1 = sprintf("%u.%u.%u.%u",$info["s1"],$info["s2"],$info["s3"],$info["s4"]);
                $mappedPort1 = $info["port"];
            }
        }
        if($mappedIP1 == ""){
            return null;
        }
        
        $restLen = strlen($resp2) - 20;
        $restIdx = 20;
        while(true){
            if($restLen < 4){
                break;
            }
            $mah = substr($resp2,$restIdx,4);
            $restLen -= 4;
            $restIdx += 4;
            $info = unpack("ntag/nlen",$mah);
            if($info["len"] > $restLen){
                return null;
            }
            
            $v = substr($resp2,$restIdx,$info["len"]);
            $restLen -= $info["len"];
            $restIdx += $info["len"];
            if($info["tag"] == $this->_MAPPED_ADDRESS){
                if($info["len"] != 8){
                    return null;
                }
                $info = unpack("Cfirst/Cflag/nport/C4s",$v);
                if($info["flag"] != 1){
                    return null;
                }
                $mappedIP2 = sprintf("%u.%u.%u.%u",$info["s1"],$info["s2"],$info["s3"],$info["s4"]);
                $mappedPort2 = $info["port"];
            }
        }
        if($mappedIP2 == ""){
            return null;
        }
        
        if($mappedIP1 == $mappedIP2 and ($mappedPort1 >= $mappedPort2 - 10 && $mappedPort1 <= $mappedPort2 + 10)){
            return RET_VALUE::$_RET_TEST_IV_LOCAL;
        }
        else{
            return RET_VALUE::$_RET_TEST_IV_DIFF;
        }       
    }
    
    /**
     * STUNClient::getNatType()
     * 
     * @return 获取网络类型
     */
    public function getNatType(){
        
        if($this->socket == null){
            return null;
        }
        
        $res = $this->testI1();
        if($res == RET_VALUE::$_RET_TEST_I1_UDP_BLOCKED){
            return NAT_TYPE::$_NAT_TYPE_UDP_BLOCKED;
        }
        elseif($res == RET_VALUE::$_RET_TEST_I1_IP_SAME){
            $res = $this->testII();
            if($res == RET_VALUE::$_RET_TEST_II_GOT_RESP){
                return NAT_TYPE::$_NAT_TYPE_OPENED;
            }
            return NAT_TYPE::$_NAT_TYPE_SYM_UDP_FIREWALL;
        }
        else{
            $res = $this->testII();
            if($res == RET_VALUE::$_RET_TEST_II_GOT_RESP){
                return NAT_TYPE::$_NAT_TYPE_FULLCONE_NAT;
            }
            $res = $this->testI2();
            if($res == RET_VALUE::$_RET_TEST_I2_IP_DIFF){
                $res = $this->testIV();
                if($res == RET_VALUE::$_RET_TEST_IV_LOCAL){
                    return NAT_TYPE::$_NAT_TYPE_SYM_NAT_LOCAL;
                }
                return NAT_TYPE::$_NAT_TYPE_SYM_NAT;
            }
            $res = $this->testIII();
            if($res == RET_VALUE::$_RET_TEST_III_GOT_RESP){
                return NAT_TYPE::$_NAT_TYPE_REST_NAT;
            }
            if($res != null){
                return NAT_TYPE::$_NAT_TYPE_PORTREST_NAT;
            }
        }
    }
    
    /**
     * STUNClient::getMappedAddr()
     * 
     * @return 本机外网映射IP与端口
     */
    public function getMappedAddr(){
        
        $mappedIP = "";
        
        $msg = pack("nnNNNN",$this->_BindingRequest, 0,
            $this->_TID1,$this->_TID2,$this->_TID3,$this->_TID4);

        socket_sendto($this->socket,$msg,strlen($msg),0,$this->serverIP,$this->serverPort);
     
        $st = time();
        while(time() - $st < $this->_TIMEOUT){
          
            socket_recvfrom($this->socket,$data,$this->_BUFLEN,0,$remoteIP,$remotePort);
            if($remoteIP != $this->serverIP or $remotePort != $this->serverPort){
                continue;
            }
            if(strlen($data) < 20){
                continue;
            }
            
            $retInfo = unpack("nmsg/nlen/N4tid",substr($data,0,20));
            
            if($retInfo["msg"] != $this->_BindingResponse){
                continue;
            }
            if(!$again && $retInfo["len"] != strlen($data) - 20){
                continue;
            }
            if(!$again && ($retInfo["tid1"]!=$this->_TID1 or $retInfo["tid2"]!=$this->_TID2 or
                $retInfo["tid3"]!=$this->_TID3 or $retInfo["tid4"]!=$this->_TID4)){
                continue;
            }
            break;
        }
        $this->_TID4 += 1;
        
        $restLen = strlen($data) - 20;
        $restIdx = 20;
        while(true){
            if($restLen < 4){
                break;
            }
            $mah = substr($data,$restIdx,4);
            $restLen -= 4;
            $restIdx += 4;
            $info = unpack("ntag/nlen",$mah);
            if($info["len"] > $restLen){
                return null;
            }
            
            $v = substr($data,$restIdx,$info["len"]);
            $restLen -= $info["len"];
            $restIdx += $info["len"];
            if($info["tag"] == $this->_MAPPED_ADDRESS){
                if($info["len"] != 8){
                    return null;
                }
                $info = unpack("Cfirst/Cflag/nport/C4s",$v);
                if($info["flag"] != 1){
                    return null;
                }
                $mappedIP = sprintf("%u.%u.%u.%u",$info["s1"],$info["s2"],$info["s3"],$info["s4"]);
                $mappedPort = $info["port"];
            }
        }
        return $mappedIP . ":" . $mappedPort;
    }
    
    /**
     * STUNClient::natType2String()
     * 
     * @param mixed $t
     * @return 本机网络类型
     */
    public function natType2String($t){
        if($t == NAT_TYPE::$_NAT_TYPE_OPENED){
            return "Opened " . $t;
        }
        elseif($t == NAT_TYPE::$_NAT_TYPE_FULLCONE_NAT){
            return "Full Cone NAT " . $t;
        }
        elseif($t == NAT_TYPE::$_NAT_TYPE_REST_NAT){
            return "Restricted NAT " . $t;
        }
        elseif($t == NAT_TYPE::$_NAT_TYPE_PORTREST_NAT){
            return "Port Restricted NAT " . $t;
        }
        elseif($t == NAT_TYPE::$_NAT_TYPE_SYM_UDP_FIREWALL){
            return "Symmetric UDP Firewall " .$t;
        }
        elseif($t == NAT_TYPE::$_NAT_TYPE_SYM_NAT_LOCAL){
            return "Symmetric NAT with localization " .$t;
        }
        elseif($t == NAT_TYPE::$_NAT_TYPE_SYM_NAT){
            return "Symmetric NAT " . $t;
        }
        elseif($t == NAT_TYPE::$_NAT_TYPE_UDP_BLOCKED){
            return "Block " . $t;
        }
    }
}

?>