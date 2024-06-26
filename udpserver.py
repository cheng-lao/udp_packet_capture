import socket
import random
import hashlib
import argparse
from threading import Thread
import threading
import time
import queue

def argsparse():
    paramaters = argparse.ArgumentParser()
    paramaters.add_argument("-p","--port",type=int,help="The port of the server" ,default=12345, required=True)
    paramaters.add_argument("-l","--listen",type=int,help="The number of the server listen",default = 50)
    paramaters.add_argument("-ip","--ip",type=str,help="The ip of the server",default="0.0.0.0", required=True)
    paramaters.add_argument("-RecvSize","--RecvSize",type=int,help="The Each RecvSize of the server",default=102400, required=False)
    args = paramaters.parse_args()
    return args

class Server:
    
    def __init__(self,ip:str,port:int,listen:int):
        self.ip = ip
        self.port = port
        self.listen = listen
        self.server = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        self.server.bind((self.ip,self.port))
        self.RecvSize = args.RecvSize
        self.recvivedack = {}
        self.recvivedseq = {}
        self.ack = {}
        self.seq = {}
        self.addrpool = {} 
        self.lock = threading.RLock()
     
    @staticmethod
    def hash_string(s):
        sha_signature = hashlib.sha256(s.encode()).hexdigest()
        return sha_signature
        
    def domessage(self,seq :int,ack: int,content: str,SYN,FIN,ver= 2,otherflag = [0,0,0,0,0,0])-> str:
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
        报文基础格式 单位bit
        
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
        checkcode = hash(content) 将整个报文的所有内容进行hash转换成64位的字符串
        放在报文的头部部分作为校验和
        报文最大长度为512 content最大长度为397 
        """
        
        datetime = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))
        if len(content.encode()) > 397:
            raise ValueError("content too long")
        contentlen = len(content.encode())
        message = str(seq).zfill(7) + str(ack).zfill(7) + str(ver).zfill(2) + \
                    str(SYN) + str(FIN) + "000000" + str(contentlen).zfill(8)   \
                        + datetime  + content    
        checkcode = Server.hash_string(message)
        message = message[0:32] + checkcode + message[32:]
        
        return message
    
    def TackleMessage(self,message: str):
        checkcode = message[32:96]
        checkmessage = message[0:32] + message[96:]
        if checkcode == Server.hash_string(checkmessage):
            return True
        else: 
            raise ValueError("CheckCode Error")
    
    def closeClient(self,addr):
        # 1.发送ACK回应
        with self.lock:
            self.ack[addr] = self.recvivedseq[addr] + 1
            self.seq[addr] = self.recvivedack[addr]
            message = self.domessage(self.seq[addr],self.ack[addr],content="closeconnect #1 from server in close mode",SYN=0,FIN=1)
            self.server.sendto(message.encode(),addr)
    
    def buildConnection(self,addr):
        lock = threading.Lock()
        with lock:
            self.seq[addr] = random.randint(1,1000)
            self.ack[addr] = self.recvivedseq[addr] + 1
            message = self.domessage(self.seq[addr],self.ack[addr],content = "buildconnect reply ack:{} from server in build mode".format(self.ack[addr]),SYN=1,FIN=0)
            self.server.sendto(message.encode(),addr)
    
    def handle_client(self,addr):
        # lock = threading.Lock()
        while True:
            if not self.addrpool[addr].empty():
                with self.lock:
                    data = self.addrpool[addr].get()
                if self.TackleMessage(data):
                    syn = int(data[16])
                    fin = int(data[17])
                    with self.lock:
                        self.recvivedseq[addr] = int(data[0:7])
                        self.recvivedack[addr] = int(data[7:14])
                    
                    if syn == 1 and fin == 0:
                        # 建立连接报文 客户端发送的第一个建立连接的报文
                        self.buildConnection(addr)
                    elif syn == 0 and fin == 1:
                        with self.lock:
                            self.closeClient(addr)
                            del self.addrpool[addr]
                            del self.recvivedack[addr]
                            del self.recvivedseq[addr]
                            del self.ack[addr]
                            del self.seq[addr]
                            break
                    else: 
                        with self.lock:
                            self.seq[addr] = self.recvivedack[addr]
                            self.ack[addr] = self.recvivedseq[addr] + 1
                            message = self.domessage(self.seq[addr],self.ack[addr],
                                                content="reply #{} from server in normal mode".format(self.seq[addr]),SYN=0,FIN=0)
                            self.server.sendto(message.encode(),addr)
    
    def run(self):
        while True:
            data , addr = self.server.recvfrom(self.RecvSize) # 整个服务端唯一接收数据的地方
            data = data.decode()
            # print("recv message is ",data)
            
            
            with self.lock:
                # print("addrpool is ",self.addrpool)
                if addr in self.addrpool:
                    randomdigit = random.random()
                    if randomdigit<0.5: # 丢包率
                        # print("drop the package")
                        continue
                    self.addrpool[addr].put(data)
                else:
                    # 如果没有的话就创建一个 新的线程
                    self.addrpool[addr] = queue.Queue()
                    self.addrpool[addr].put(data)
                    self.recvivedack[addr] = 0
                    self.recvivedseq[addr] = 0
                    self.ack[addr] = self.recvivedseq[addr] + 1
                    self.seq[addr] = self.ack[addr]

                    thread = Thread(target=self.handle_client,args=(addr,))
                    thread.start()
    
def main(args):
    server = Server(args.ip,args.port,args.listen)
    print("Server is running")    
    server.run()

if __name__ == "__main__":
    args = argsparse()
    main(args)
    

