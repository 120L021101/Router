from scapy.all import sniff, sendp, Ether, IP, TCP, Raw
import time
from threading import Thread

# veth1 和 veth2 的 IP 地址
veth1_ip = "192.168.2.1"  # veth1 的 IP 地址
veth2_ip = "192.168.2.2"  # veth2 的 IP 地址

# 物理地址（MAC地址）初始化
veth1_mac = "4a:dc:6b:b7:fc:6a"  # 确保设置正确的 MAC 地址
veth2_mac = "ca:95:c0:0b:e6:78"  # 初始为 None，后续会通过 ARP 获取

# 用于存储序列号和确认号
seq = 1000  # 初始序列号
ack = None   # 确认号

# 发送 TCP SYN 报文
def send_tcp_syn():
    global veth2_mac, seq
    # 创建 TCP SYN 报文
    packet = Ether(src=veth1_mac, dst=veth2_mac) / IP(src=veth1_ip, dst=veth2_ip) / TCP(sport=4189, dport=4189, flags="S", seq=seq)
    sendp(packet, iface="veth1")  # 通过 veth1 接口发送
    print(f"Sent TCP SYN to {veth2_ip} with seq={seq}")

def create_pcep_open_message():
    # PCEP 协议版本 1，Open 消息类型 1，固定长度 4
    pcep_version = 0x10  # 第 1 版本
    message_type = 1     # Open 消息类型
    message_length = 12  # 假设 Open 消息长度为 12 字节（可根据需求调整）

    # 设置 Open 消息的基本内容
    open_message = bytes([0x10, message_type]) + message_length.to_bytes(2, 'big')
    
    # 包含一个 Open 对象（带 Session ID 和 Keepalive 值）
    session_id = 1         # 简单的 Session ID
    keepalive = 30         # Keepalive 时间间隔，单位秒
    dead_timer = 90        # 死亡时间间隔，单位秒
    
    open_object = session_id.to_bytes(4, 'big') + keepalive.to_bytes(2, 'big') + dead_timer.to_bytes(2, 'big')
    
    return open_message + open_object

def send_pcep_open():
    global veth2_mac, seq
    open_message_payload = create_pcep_open_message()
    
    # 创建 TCP 包并将 PCEP OPEN 消息作为载荷
    packet = (
        Ether(src=veth1_mac, dst=veth2_mac)
        / IP(src=veth1_ip, dst=veth2_ip)
        / TCP(sport=4189, dport=4189, flags="PA", seq=seq)
        / Raw(load=open_message_payload)
    )
    sendp(packet, iface="veth1")  # 通过 veth1 接口发送
    print(f"Sent PCEP OPEN message to {veth2_ip} with seq={seq}")

# 处理接收到的 TCP SYN-ACK 报文
def packet_callback(packet):
    global ack, seq
    if TCP in packet and packet[TCP].flags == 0x12:  # 0x12 表示 SYN-ACK
        ack = packet[TCP].seq + 1  # 设置确认号
        print(f"Received TCP SYN-ACK from {packet[IP].src}: seq={packet[TCP].seq}, ack={ack}")
        
        # 更新序列号以反映我们接下来发送的数据包
        seq += 1

        send_pcep_open()

    elif TCP in packet and packet[TCP].flags == 0x11:  # 0x11 表示 FIN-ACK
        ack = packet[TCP].seq + 1  # 确认服务器的 FIN
        # 回复最后的 ACK 确认关闭连接
        fin_ack_packet = Ether(src=veth1_mac, dst=veth2_mac) / IP(src=veth1_ip, dst=veth2_ip) / TCP(sport=12345, dport=4189, flags="A", seq=seq, ack=ack)
        sendp(fin_ack_packet, iface="veth1")
        print(f"Received TCP final ACK to {veth2_ip} with seq={seq} and ack={ack}")
        print("Connection closed.")

def main():
    global veth1_mac

    # 启动发送线程
    send_thread = Thread(target=send_tcp_syn)
    send_thread.start()

    # 开始监听 veth1 接口
    print("Listening for TCP SYN-ACK responses...")
    sniff(iface="veth1", prn=packet_callback, filter="tcp", store=0)

if __name__ == "__main__":
    main()
