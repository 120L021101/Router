from scapy.all import sniff, Ether

# 设置物理地址（MAC地址），请替换为你实际的 veth1 的物理地址
veth1_mac = "02:16:61:44:f4:17"

def packet_callback(packet):
    # 检查是否是从veth1发送的报文，避免自身发送的报文
    if Ether in packet and packet[Ether].src != veth1_mac:
        print(f"收到报文: {packet.summary()}")

def main():
    # 开始监听veth1接口，过滤条件为只捕获传入的报文
    sniff(iface="veth1", prn=packet_callback, filter="not ether src " + veth1_mac, store=0)

if __name__ == "__main__":
    main()
