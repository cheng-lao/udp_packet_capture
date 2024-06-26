import hashlib
import random
import socket
import time
from datetime import datetime as dt
import sys
import threading
import argparse

def argsparse():
    
    parser = argparse.ArgumentParser(description='Reverse TCP Client')
    parser.add_argument('-ip',"--serverip", default="172.19.73.224", help="Target Server IP Address", required=True)
    parser.add_argument('-p',"--port", type = int, default=12345, help="Target Server Port", required=True)
    parser.add_argument('-num',"--TotalNum",type = int ,default= 12 ,help="File to send", required = False)
    parser.add_argument('-maxs',"--MaxSizeBlock", type = int , default= 1400 ,help="Maximum size of blocks to send and the Maximum can't bigger than the 1400", required=False)
    parser.add_argument('-size',"--Size", type = int , default= 1024 ,help="Size of message to receive and the Minimum can't smaller than the 1024", required=False)
    parser.add_argument('-t',"--time", type = int , default= 0.2 ,help="Time to wait for a response (second)", required=False)
    args = parser.parse_args()
    if args.Size < 1024:
        parser.error("Size can't smaller than 1024, because the size is too small to receive the response message")
    if args.MaxSizeBlock > 1400:
        parser.error("MaxSizeBlock can't bigger than 1400, because the size is too big to send the message")
    return args

class Client:
    
    def __init__(self, args) -> None:
        self.ip = args.serverip
        self.port = args.port
        self.num = args.TotalNum
        self.time = args.time        
        self.client = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        self.seq = 0
        self.ack = 0
        self.receivedseq = 0
        self.receivedack = 0
        self.addr = (self.ip,self.port)
        self.RTTlist = []
        self.firstdatetime = ""
        self.lastdatetime = ""
        self.isreceive = False
        self.successcount = 0
    
    @staticmethod
    def hash_string(s):
        sha_signature = hashlib.sha256(s.encode()).hexdigest()
        return sha_signature
    
    def domessage(self ,seq :int,ack: int,content: str,SYN,FIN,ver= 2,otherflag = [0,0,0,0,0,0])-> str:
        """
        Args:
            cnt (int): seq number
            ack (int): ack number
            content (str): content str
            ver (int, optional): UDP version. Defaults to 2
            SYN (int, optional): SYN flag Defaults to 0.
            FIN (int, optional): FIN flag Defaults to 0.
            agrs (tuple): other flags
        Raises:
            ValueError: content too long

        Returns:
            str: _description_
        
        报文格式
        报文基础格式 单位byte
        
        -------------------------------------------------------------------
        |        seq(7)           |         ack(7)            |   ver(2)  |
        -------------------------------------------------------------------
        | SYN(1) | FIN(1) | args(other_flags 6) |  content_lenth(8)       |
        -------------------------------------------------------------------
        |                      checkcode(64)                              |
        -------------------------------------------------------------------
        |                       time-date(19)                              |
        -------------------------------------------------------------------
        |                      content(Unknown)                           |
        -------------------------------------------------------------------
        checkcode = hash(content) 将整个报文的所有内容进行hash转换成64个字符的字符串
        放在报文的头部部分作为校验和
        报文最大长度为512 content最大长度为397 
        """
        datetime = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))
        if len(content.encode()) > 397:
            raise ValueError("content too long")
        contentlen = len(content.encode())
        message = str(self.seq).zfill(7) + str(self.ack).zfill(7) + str(ver).zfill(2) + \
                    str(SYN) + str(FIN) + "000000" + str(contentlen).zfill(8)   \
                        + datetime  + content   
        checkcode = self.hash_string(message)
        message = message[0:32] + checkcode + message[32:]
        
        return message
    
    def TackleMessage(self,message:str):
        """ 解析报文
        Args:
            message (str): 报文
        Returns: None
        """
        checkcode = message[32:96]
        checkmessage = message[0:32] + message[96:]
        if Client.hash_string(checkmessage) == checkcode:
            # return True
            if self.firstdatetime == "":
                self.firstdatetime = message[96:115]
            self.lastdatetime = message[96:115]
            return True
        else:
            raise ValueError("CheckCode Error")
        

    def countdowntimer(self,WaitTime,callback,request):
        """倒计时定时器
        Args:
            WaitTime (int): 等待时间
            resend (function): 重传函数
            content (str): 重传内容
        """
        time.sleep(WaitTime)
        if self.isreceive == False:
            if callback != None:
                callback(request)
            else: # 重发但是仍是被丢弃所以此时放弃发送该报文 
                return

    def resend(self,request):
        print("resend message: ",request[115:]) # 重发报文
        self.client.sendto(request.encode(), self.addr)
        if self.isreceive == False:
            self.countdowntimer(self.time,None,request)

    def closeConnect(self):
        print("进入了关闭连接!")
        while True:
            try:
                # 1. 发送FIN
                self.seq = self.receivedack
                self.ack = self.receivedseq + 1
                message = self.domessage(self.seq,self.ack,content="closeconnect #1",SYN=0,FIN=1)
                self.client.sendto(message.encode(), self.addr)
                
                # 2.接收ACK
                response = self.client.recv(1024)
                response = response.decode()

                if self.TackleMessage(response):
                    fin = int(response[17:18])
                    if fin == 1:
                        return True
            except socket.timeout as e:
                print("time out, send fin again")
                continue
            except Exception as e:
                print(e)
                print("send fin again")
                continue
        
    def statistics(self):
        self.RTTlist = [i for i in self.RTTlist if i > 0]
        print("success count: ", self.successcount)
        print("丢包率: {:0.3f}%".format(100*(self.num-self.successcount)/self.num))
        print("mean RTT: ",sum(self.RTTlist)/self.successcount)
        print("max RTT: ",max(self.RTTlist))

        minRTT = min(i for i in self.RTTlist if i > 0)
        print("min RTT: ",minRTT)
        datetime1 = dt.strptime(self.firstdatetime, "%Y-%m-%d %H:%M:%S")
        datetime2 = dt.strptime(self.lastdatetime, "%Y-%m-%d %H:%M:%S")
        difference = (datetime2 - datetime1).total_seconds()
        total_microseconds = difference * 1000
        print("Server的整体响应时间: ", total_microseconds, "ms")  #TODO: 处理一下时间的格式

    def buildConect(self):
        """建立连接
        
        不断循环直到连接建立成功
        
        Returns: True 表示连接建立成功
        """
        # 初始建立连接的时候不需要线程 超时了就不断重发直到可以建立连接为止
        self.client.settimeout(1)   # 设置超时时间 初始为1s 后面正常发送文件使用设置的超时时间
        while True:
            try:
                # 1. 发送SYN
                self.seq = random.randint(1,1000)
                self.ack = 0
                message = self.domessage(self.seq,ack=self.ack,content="buildconnect #1",SYN=1,FIN=0)
                
                self.client.sendto(message.encode(), self.addr)
                # 2. 接收SYN+ACK
                response = self.client.recv(1024)
                response = response.decode()
                # print("response: ",response)
                syn = response[16:17]
                fin = response[17:18]
                if syn == "1" and fin != "1":
                    self.receivedseq = int(response[0:7])    
                    self.receivedack = int(response[7:14])
                    self.seq = self.receivedack
                    self.ack = self.receivedseq + 1
                    return True
            except socket.timeout as e:
                continue
            except Exception as e:
                print("raise error",e)
                continue

    def run(self):
        #1.建立连接
        status = self.buildConect()
        if status: print("connect success")
        #2.发送报文
        self.successcount = 0
        thread1 = None
        self.client.settimeout(self.time*2 + 1e-3) # 设置超时时间
        for i in range(1,self.num+1): 
            # time.sleep(0.5)
            try:
                self.seq = self.receivedack
                self.ack = self.receivedseq + 1
                content = "message from client " + str(i) +  "th request"
                request = self.domessage(seq= self.seq, ack= self.ack , content=content , SYN=0 , FIN=0)
                # 开启定时器 超时重传
                starttime = time.perf_counter()
                thread1 = threading.Thread(target=self.countdowntimer,args=(self.time,self.resend,request))
                thread1.start()
                
                #发送报文
                self.client.sendto(request.encode(), self.addr)

                response = self.client.recv(1024)   # 接收响应报文
                # 处理报文
                response = response.decode()
                if self.TackleMessage(response):
                    self.isreceive = True
                    self.receivedseq = int(response[0:7])
                    self.receivedack = int(response[7:14])
                    
                    endtime = time.perf_counter()
                    print("RTT:{:0.6f} ms".format((endtime-starttime)*1000))
            
            except socket.timeout as e:
                # print("index number: {},request time out".format(i))
                self.RTTlist.append((-1)*1000)
                self.isreceive = False
                continue    # 放弃发送下一个 报文
            except Exception as e:
                self.isreceive = False
                print("raise error: ",e)
                self.RTTlist.append((-1)*1000)
                continue
            else:
                # 接收响应报文成功 
                self.isreceive = True

                self.RTTlist.append((endtime-starttime)*1000)
                self.successcount += 1
            finally:
                if thread1 is not None:
                    thread1.join()
                self.isreceive = False

        #3.关闭连接
        self.closeConnect()
        #4.统计数据
        self.statistics()
        pass

def main(args):
    client = Client(args)
    client.run()

if __name__ == "__main__":
    args = argsparse()
    main(args)
    
