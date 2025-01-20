# 0000 3cb7 0011 0001 ad66 2267
# 0000 0000 a322 0500 0000 0000 1011 1213
# 1415 1617 1819 1a1b 1c1d 1e1f 2021 2223
# 2425 2627 2829 2a2b 2c2d 2e2f 3031 3233
# 3435 3637   

# 0800 c12a 0011 0001 ad66 2267 
# 0000 0000 a322 0500 0000 0000 1011 1213
# 1415 1617 1819 1a1b 1c1d 1e1f 2021 2223
# 2425 2627 2829 2a2b 2c2d 2e2f 3031 3233
# 3435 3637   

# 0000 3d06 0016 0001 5069 2267
# 0000 0000 bf08 0900 0000 0000 1011 1213
# 1415 1617 1819 1a1b 1c1d 1e1f 2021 2223
# 2425 2627 2829 2a2b 2c2d 2e2f 3031 3233
# 3435 3637   

# 0000 d50b 0018 0001 1b6a 2267
# 0000 0000 2b37 0300 0000 0000 1011 1213
# 1415 1617 1819 1a1b 1c1d 1e1f 2021 2223
# 2425 2627 2829 2a2b 2c2d 2e2f 3031 3233
# 3435 3637       

def calculate_ip_checksum(data):  
    """  
    计算IP校验和  
    :param data: 字节串（bytes）  
    :return: 校验和（整数）  
    """  
    print(len(data))
    if len(data) % 2 != 0:  
        # 如果数据长度是奇数，补一个字节的0  
        data += b'\x00'  
      
    checksum = 0  
    # 以两个字节为单位累加  
    for i in range(0, len(data), 2):  
        word = data[i] << 8 | data[i + 1]  
        checksum += word  
        # 如果高16位有进位，则加回到低16位  
        while checksum > 0xffff:  
            checksum = (checksum & 0xffff) + (checksum >> 16)  
      
    # 取反得到校验和  
    checksum = ~checksum & 0xffff  
    return checksum  
  
# 示例使用  
def calculate_checksum(data):  
    """  
    计算简单的16位累加和校验和  
    :param data: 字节串（bytes）  
    :return: 校验和（整数）  
    """  
    checksum = 0  
    for i in range(0, len(data), 2):  
        # 这里我们假设数据长度是偶数，因为校验和通常是这样计算的  
        word = data[i] << 8 | data[i + 1]  
        checksum += word  
        # 处理进位  
        while checksum > 0xffff:  
            checksum = (checksum & 0xffff) + (checksum >> 16)  
      
    # 通常校验和会取反，但这取决于具体协议  
    checksum = ~checksum & 0xffff  
    return checksum  
  
# 将十六进制字符串转换为字节串  
hex_data = "0000 0000 0011 0001 ad66 2267 0000 0000 a322 0500 0000 0000 1011 1213 1415 1617 1819 1a1b 1c1d 1e1f 2021 2223 2425 2627 2829 2a2b 2c2d 2e2f 3031 3233 3435 3637"
# hex_data = "0800 0000 0011 0001 ad66 2267 0000 0000 a322 0500 0000 0000 1011 1213 1415 1617 1819 1a1b 1c1d 1e1f 2021 2223 2425 2627 2829 2a2b 2c2d 2e2f 3031 3233 3435 3637"
hex_data = "0000 0000 0016 0001 5069 2267 0000 0000 bf08 0900 0000 0000 1011 1213 1415 1617 1819 1a1b 1c1d 1e1f 2021 2223 2425 2627 2829 2a2b 2c2d 2e2f 3031 3233 3435 3637"
hex_data = "0000 0000 0018 0001 1b6a 2267 0000 0000 2b37 0300 0000 0000 1011 1213 1415 1617 1819 1a1b 1c1d 1e1f 2021 2223 2425 2627 2829 2a2b 2c2d 2e2f 3031 3233 3435 3637"
hex_data = hex_data.replace(" ", "")  
byte_data = bytes.fromhex(hex_data)  
  
# 计算校验和  
checksum = calculate_ip_checksum(byte_data)  
print(f"Checksum: {checksum:04x}") 