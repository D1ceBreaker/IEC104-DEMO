#!/usr/bin/env python3
"""
Генератор pcap файла с трафиком IEC 104 протокола
IEC 60870-5-104 работает поверх TCP на порту 2404
"""

from scapy.all import *
import random

# Настройки
SERVER_IP = "192.168.1.100"
CLIENT_IP = "192.168.1.10"
SERVER_PORT = 2404
CLIENT_PORT = random.randint(50000, 60000)

packets = []

def create_iec104_apci(start_byte=0x68, length=4, control_field=b'\x00\x00\x00\x00'):
    """Создает APCI заголовок IEC 104"""
    return bytes([start_byte, length]) + control_field

def create_i_format(send_seq, recv_seq, asdu_data):
    """Создает I-формат сообщение (информационное)"""
    length = 4 + len(asdu_data)  # 4 байта control + ASDU
    control = struct.pack('>HH', send_seq << 1, recv_seq << 1)
    apci = create_iec104_apci(0x68, length, control)
    return apci + asdu_data

def create_s_format(recv_seq):
    """Создает S-формат сообщение (supervisory)"""
    control = struct.pack('>I', (recv_seq << 1) | 0x01)
    return create_iec104_apci(0x68, 4, control)

def create_u_format(type_code):
    """Создает U-формат сообщение (unnumbered)"""
    # STARTDT act: 0x07, STARTDT con: 0x0B, STOPDT act: 0x13, STOPDT con: 0x23
    control = struct.pack('>I', type_code)
    return create_iec104_apci(0x68, 4, control)

def create_asdu(type_id, vsq, cot, common_address, ioas):
    """Создает ASDU (Application Service Data Unit)"""
    asdu = struct.pack('B', type_id)  # Type Identification
    asdu += struct.pack('B', vsq)      # Variable Structure Qualifier
    asdu += struct.pack('B', cot)      # Cause of Transmission
    asdu += struct.pack('>H', common_address)  # Common Address of ASDU
    asdu += ioas  # Information Object Addresses
    return asdu

def create_ioa_value(ioa, value, quality=0):
    """Создает Information Object Address с значением"""
    # IOA: 3 байта (little-endian)
    ioa_bytes = struct.pack('<I', ioa)[:3]
    # Value: зависит от типа, здесь используем 4 байта для float
    value_bytes = struct.pack('>f', value)
    # Quality: 1 байт
    quality_byte = struct.pack('B', quality)
    return ioa_bytes + value_bytes + quality_byte

# Генерация пакетов

# 1. TCP Handshake
syn = IP(src=CLIENT_IP, dst=SERVER_IP) / TCP(sport=CLIENT_PORT, dport=SERVER_PORT, flags="S", seq=1000)
packets.append(syn)

syn_ack = IP(src=SERVER_IP, dst=CLIENT_IP) / TCP(sport=SERVER_PORT, dport=CLIENT_PORT, flags="SA", seq=2000, ack=syn.seq + 1)
packets.append(syn_ack)

ack = IP(src=CLIENT_IP, dst=SERVER_IP) / TCP(sport=CLIENT_PORT, dport=SERVER_PORT, flags="A", seq=syn.seq + 1, ack=syn_ack.seq + 1)
packets.append(ack)

# 2. STARTDT (U-формат) - начало передачи данных
startdt_act = create_u_format(0x07)  # STARTDT act
startdt_pkt = IP(src=CLIENT_IP, dst=SERVER_IP) / TCP(sport=CLIENT_PORT, dport=SERVER_PORT, flags="PA", seq=ack.seq, ack=syn_ack.seq + 1) / Raw(load=startdt_act)
packets.append(startdt_pkt)

startdt_con = create_u_format(0x0B)  # STARTDT con
startdt_con_pkt = IP(src=SERVER_IP, dst=CLIENT_IP) / TCP(sport=SERVER_PORT, dport=CLIENT_PORT, flags="PA", seq=syn_ack.seq + 1, ack=startdt_pkt.seq + len(startdt_act)) / Raw(load=startdt_con)
packets.append(startdt_con_pkt)

# 3. I-формат сообщения с данными (Single-point information)
send_seq = 0
recv_seq = 0

# Тип 1: Single-point information (M_SP_NA_1)
for i in range(5):
    ioas = create_ioa_value(ioa=1000 + i, value=1.0 if i % 2 == 0 else 0.0, quality=0)
    asdu = create_asdu(type_id=1, vsq=0x01, cot=3, common_address=1, ioas=ioas)
    iec104_data = create_i_format(send_seq, recv_seq, asdu)
    
    pkt = IP(src=SERVER_IP, dst=CLIENT_IP) / TCP(sport=SERVER_PORT, dport=CLIENT_PORT, flags="PA", 
                                                  seq=startdt_con_pkt.seq + len(startdt_con), 
                                                  ack=startdt_pkt.seq + len(startdt_act)) / Raw(load=iec104_data)
    packets.append(pkt)
    send_seq += 1
    recv_seq += 1

# 4. I-формат сообщения с измеренными значениями (Measured value, short floating point number)
# Тип 13: Measured value, short floating point number (M_ME_NC_1)
for i in range(3):
    value = random.uniform(0.0, 100.0)
    ioas = create_ioa_value(ioa=2000 + i, value=value, quality=0)
    asdu = create_asdu(type_id=13, vsq=0x01, cot=3, common_address=1, ioas=ioas)
    iec104_data = create_i_format(send_seq, recv_seq, asdu)
    
    last_pkt = packets[-1]
    pkt = IP(src=SERVER_IP, dst=CLIENT_IP) / TCP(sport=SERVER_PORT, dport=CLIENT_PORT, flags="PA",
                                                  seq=last_pkt.seq + len(last_pkt[Raw].load),
                                                  ack=startdt_pkt.seq + len(startdt_act)) / Raw(load=iec104_data)
    packets.append(pkt)
    send_seq += 1

# 5. S-формат сообщение (подтверждение получения)
last_pkt = packets[-1]
s_format = create_s_format(recv_seq)
s_pkt = IP(src=CLIENT_IP, dst=SERVER_IP) / TCP(sport=CLIENT_PORT, dport=SERVER_PORT, flags="PA",
                                               seq=startdt_pkt.seq + len(startdt_act),
                                               ack=last_pkt.seq + len(last_pkt[Raw].load)) / Raw(load=s_format)
packets.append(s_pkt)

# 6. Еще несколько I-формат сообщений
for i in range(3):
    ioas = create_ioa_value(ioa=3000 + i, value=random.uniform(0.0, 50.0), quality=0)
    asdu = create_asdu(type_id=13, vsq=0x01, cot=3, common_address=1, ioas=ioas)
    iec104_data = create_i_format(send_seq, recv_seq, asdu)
    
    last_pkt = packets[-1]
    pkt = IP(src=SERVER_IP, dst=CLIENT_IP) / TCP(sport=SERVER_PORT, dport=CLIENT_PORT, flags="PA",
                                                  seq=last_pkt.seq + len(last_pkt[Raw].load),
                                                  ack=s_pkt.seq + len(s_format)) / Raw(load=iec104_data)
    packets.append(pkt)
    send_seq += 1

# 7. STOPDT (U-формат) - остановка передачи данных
last_pkt = packets[-1]
stopdt_act = create_u_format(0x13)  # STOPDT act
stopdt_pkt = IP(src=CLIENT_IP, dst=SERVER_IP) / TCP(sport=CLIENT_PORT, dport=SERVER_PORT, flags="PA",
                                                      seq=s_pkt.seq + len(s_format),
                                                      ack=last_pkt.seq + len(last_pkt[Raw].load)) / Raw(load=stopdt_act)
packets.append(stopdt_pkt)

stopdt_con = create_u_format(0x23)  # STOPDT con
stopdt_con_pkt = IP(src=SERVER_IP, dst=CLIENT_IP) / TCP(sport=SERVER_PORT, dport=CLIENT_PORT, flags="PA",
                                                          seq=last_pkt.seq + len(last_pkt[Raw].load),
                                                          ack=stopdt_pkt.seq + len(stopdt_act)) / Raw(load=stopdt_con)
packets.append(stopdt_con_pkt)

# 8. TCP закрытие соединения
last_pkt = packets[-1]
fin = IP(src=CLIENT_IP, dst=SERVER_IP) / TCP(sport=CLIENT_PORT, dport=SERVER_PORT, flags="FA",
                                             seq=stopdt_pkt.seq + len(stopdt_act),
                                             ack=last_pkt.seq + len(stopdt_con)) / Raw(load=b'')
packets.append(fin)

fin_ack = IP(src=SERVER_IP, dst=CLIENT_IP) / TCP(sport=SERVER_PORT, dport=CLIENT_PORT, flags="FA",
                                                   seq=last_pkt.seq + len(stopdt_con),
                                                   ack=fin.seq + 1) / Raw(load=b'')
packets.append(fin_ack)

final_ack = IP(src=CLIENT_IP, dst=SERVER_IP) / TCP(sport=CLIENT_PORT, dport=SERVER_PORT, flags="A",
                                                    seq=fin.seq + 1,
                                                    ack=fin_ack.seq + 1) / Raw(load=b'')
packets.append(final_ack)

# Сохранение в pcap файл
output_file = "iec104_test.pcap"
wrpcap(output_file, packets)
print(f"✓ Создан pcap файл: {output_file}")
print(f"✓ Количество пакетов: {len(packets)}")
print(f"✓ Протокол: IEC 104 (TCP порт {SERVER_PORT})")
print(f"✓ Содержит: STARTDT, I-формат сообщения, S-формат, STOPDT")

