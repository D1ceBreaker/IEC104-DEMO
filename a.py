#!/usr/bin/env python3
"""
Генератор PCAP файла с IEC104 трафиком для тестирования правил Suricata
Создает валидный IEC104 трафик, который триггерит правила детекции
"""

from scapy.all import *
import struct
import time

# Параметры
SRC_IP = "192.168.1.100"
DST_IP = "192.168.1.10"
SRC_PORT = 52341
DST_PORT = 2404
OUTPUT_FILE = "iec104_test_generated.pcap"

packets = []
seq_num_client = 1000
seq_num_server = 2000
ack_num = 0

def create_tcp_packet(src_ip, dst_ip, src_port, dst_port, flags, seq, ack, payload=b""):
    """Создать TCP пакет"""
    ip = IP(src=src_ip, dst=dst_ip)
    tcp = TCP(sport=src_port, dport=dst_port, flags=flags, seq=seq, ack=ack)
    if payload:
        return ip/tcp/Raw(load=payload)
    return ip/tcp

def create_iec104_apci_u_format(utype):
    """
    Создать IEC104 U-format APCI
    utype: 'STARTDT_ACT' (0x07), 'STARTDT_CON' (0x0B), 'STOPDT_ACT' (0x13), 'TESTFR_ACT' (0x43)
    """
    start = 0x68
    length = 0x04  # U-format всегда 4 байта данных после length
    
    if utype == 'STARTDT_ACT':
        control = 0x07000000
    elif utype == 'STARTDT_CON':
        control = 0x0B000000
    elif utype == 'STOPDT_ACT':
        control = 0x13000000
    elif utype == 'TESTFR_ACT':
        control = 0x43000000
    elif utype == 'TESTFR_CON':
        control = 0x83000000
    else:
        control = 0x07000000
    
    return struct.pack('<BBL', start, length, control)

def create_iec104_i_format(send_seq, recv_seq, asdu_data):
    """
    Создать IEC104 I-format APCI с ASDU
    send_seq: номер отправляемого сообщения
    recv_seq: номер принятого сообщения (для подтверждения)
    asdu_data: ASDU payload
    """
    start = 0x68
    length = 4 + len(asdu_data)  # 4 bytes control + ASDU
    
    # I-format: оба младших бита = 0
    control1 = (send_seq * 2) & 0xFF
    control2 = ((send_seq * 2) >> 8) & 0xFF
    control3 = (recv_seq * 2) & 0xFF
    control4 = ((recv_seq * 2) >> 8) & 0xFF
    
    apci = struct.pack('<BBBBBB', start, length, control1, control2, control3, control4)
    return apci + asdu_data

def create_iec104_asdu(type_id, cot, common_addr, ioa, data):
    """
    Создать ASDU (Application Service Data Unit)
    type_id: Type Identification (например, 100 для C_IC_NA_1)
    cot: Cause of Transmission
    common_addr: Common Address of ASDU
    ioa: Information Object Address (3 bytes)
    data: Данные информационного объекта
    """
    vsq = 0x01  # 1 information object, without sequence
    
    # ASDU структура:
    # Type ID (1 byte)
    # VSQ (1 byte)
    # COT (1 or 2 bytes) - используем 2 bytes
    # Common Address (1 or 2 bytes) - используем 2 bytes
    # IOA (3 bytes)
    # Information Elements
    
    asdu = struct.pack('<BB', type_id, vsq)
    asdu += struct.pack('<H', cot)  # COT - 2 bytes
    asdu += struct.pack('<H', common_addr)  # Common Address - 2 bytes
    asdu += struct.pack('<I', ioa)[:3]  # IOA - 3 bytes
    asdu += data
    
    return asdu

print(f"Генерация IEC104 PCAP: {OUTPUT_FILE}")
print("=" * 60)

# === TCP Handshake ===
print("1. TCP Handshake...")
# SYN
pkt = create_tcp_packet(SRC_IP, DST_IP, SRC_PORT, DST_PORT, 'S', seq_num_client, 0)
packets.append(pkt)
seq_num_client += 1

# SYN-ACK
pkt = create_tcp_packet(DST_IP, SRC_IP, DST_PORT, SRC_PORT, 'SA', seq_num_server, seq_num_client)
packets.append(pkt)
seq_num_server += 1

# ACK
pkt = create_tcp_packet(SRC_IP, DST_IP, SRC_PORT, DST_PORT, 'A', seq_num_client, seq_num_server)
packets.append(pkt)

time.sleep(0.001)

# === IEC104 Communication ===
print("2. IEC104 STARTDT (активация передачи данных)...")

# Client -> Server: STARTDT ACT
payload = create_iec104_apci_u_format('STARTDT_ACT')
pkt = create_tcp_packet(SRC_IP, DST_IP, SRC_PORT, DST_PORT, 'PA', seq_num_client, seq_num_server, payload)
packets.append(pkt)
seq_num_client += len(payload)

# Server -> Client: STARTDT CON
payload = create_iec104_apci_u_format('STARTDT_CON')
pkt = create_tcp_packet(DST_IP, SRC_IP, DST_PORT, SRC_PORT, 'PA', seq_num_server, seq_num_client, payload)
packets.append(pkt)
seq_num_server += len(payload)

# ACK
pkt = create_tcp_packet(SRC_IP, DST_IP, SRC_PORT, DST_PORT, 'A', seq_num_client, seq_num_server)
packets.append(pkt)

i_send = 0
i_recv = 0

print("3. IEC104 Команды (триггерят правила Suricata)...")

# === Команда 1: Interrogation Command (C_IC_NA_1) - Type ID 100 ===
print("   - Interrogation command (C_IC_NA_1) - Type ID 100")
# COT = 6 (activation), Common Addr = 1, IOA = 0, QOI = 20 (station interrogation)
asdu_data = create_iec104_asdu(
    type_id=100,  # C_IC_NA_1
    cot=6,  # Activation
    common_addr=1,
    ioa=0,
    data=struct.pack('<B', 20)  # QOI = 20 (station interrogation)
)
payload = create_iec104_i_format(i_send, i_recv, asdu_data)
pkt = create_tcp_packet(SRC_IP, DST_IP, SRC_PORT, DST_PORT, 'PA', seq_num_client, seq_num_server, payload)
packets.append(pkt)
seq_num_client += len(payload)
i_send += 1

# ACK from server
pkt = create_tcp_packet(DST_IP, SRC_IP, DST_PORT, SRC_PORT, 'A', seq_num_server, seq_num_client)
packets.append(pkt)

time.sleep(0.01)

# === Команда 2: Single Command (C_SC_NA_1) - Type ID 45 ===
print("   - Single command (C_SC_NA_1) - Type ID 45")
# COT = 6 (activation), IOA = 1000, SCO = 0x01 (ON)
asdu_data = create_iec104_asdu(
    type_id=45,  # C_SC_NA_1
    cot=6,
    common_addr=1,
    ioa=1000,
    data=struct.pack('<B', 0x01)  # SCO: ON
)
payload = create_iec104_i_format(i_send, i_recv, asdu_data)
pkt = create_tcp_packet(SRC_IP, DST_IP, SRC_PORT, DST_PORT, 'PA', seq_num_client, seq_num_server, payload)
packets.append(pkt)
seq_num_client += len(payload)
i_send += 1

pkt = create_tcp_packet(DST_IP, SRC_IP, DST_PORT, SRC_PORT, 'A', seq_num_server, seq_num_client)
packets.append(pkt)

time.sleep(0.01)

# === Команда 3: Setpoint Command Float (C_SE_NC_1) - Type ID 50 ===
print("   - Setpoint command floating point (C_SE_NC_1) - Type ID 50")
# COT = 6, IOA = 2000, Value = 123.45
asdu_data = create_iec104_asdu(
    type_id=50,  # C_SE_NC_1
    cot=6,
    common_addr=1,
    ioa=2000,
    data=struct.pack('<fB', 123.45, 0x00)  # Float value + QOS
)
payload = create_iec104_i_format(i_send, i_recv, asdu_data)
pkt = create_tcp_packet(SRC_IP, DST_IP, SRC_PORT, DST_PORT, 'PA', seq_num_client, seq_num_server, payload)
packets.append(pkt)
seq_num_client += len(payload)
i_send += 1

pkt = create_tcp_packet(DST_IP, SRC_IP, DST_PORT, SRC_PORT, 'A', seq_num_server, seq_num_client)
packets.append(pkt)

time.sleep(0.01)

# === Команда 4: Clock Synchronization (C_CS_NA_1) - Type ID 103 ===
print("   - Clock synchronization command (C_CS_NA_1) - Type ID 103")
# CP56Time2a: 7 bytes timestamp
import datetime
now = datetime.datetime.now()
ms = now.microsecond // 1000
cp56time = struct.pack('<H', ms)  # milliseconds
cp56time += struct.pack('<B', now.minute)
cp56time += struct.pack('<B', now.hour)
cp56time += struct.pack('<B', now.day)
cp56time += struct.pack('<B', now.month)
cp56time += struct.pack('<B', now.year % 100)

asdu_data = create_iec104_asdu(
    type_id=103,  # C_CS_NA_1
    cot=6,
    common_addr=1,
    ioa=0,
    data=cp56time
)
payload = create_iec104_i_format(i_send, i_recv, asdu_data)
pkt = create_tcp_packet(SRC_IP, DST_IP, SRC_PORT, DST_PORT, 'PA', seq_num_client, seq_num_server, payload)
packets.append(pkt)
seq_num_client += len(payload)
i_send += 1

pkt = create_tcp_packet(DST_IP, SRC_IP, DST_PORT, SRC_PORT, 'A', seq_num_server, seq_num_client)
packets.append(pkt)

time.sleep(0.01)

# === Команда 5: Test Frame (C_TS_NA_1) - Type ID 104 ===
print("   - Test command (C_TS_NA_1) - Type ID 104")
asdu_data = create_iec104_asdu(
    type_id=104,  # C_TS_NA_1
    cot=6,
    common_addr=1,
    ioa=0,
    data=struct.pack('<H', 0xAAAA)  # Test pattern
)
payload = create_iec104_i_format(i_send, i_recv, asdu_data)
pkt = create_tcp_packet(SRC_IP, DST_IP, SRC_PORT, DST_PORT, 'PA', seq_num_client, seq_num_server, payload)
packets.append(pkt)
seq_num_client += len(payload)
i_send += 1

pkt = create_tcp_packet(DST_IP, SRC_IP, DST_PORT, SRC_PORT, 'A', seq_num_server, seq_num_client)
packets.append(pkt)

time.sleep(0.01)

# === Команда 6: Reset Process (C_RP_NA_1) - Type ID 105 ===
print("   - Reset process command (C_RP_NA_1) - Type ID 105")
asdu_data = create_iec104_asdu(
    type_id=105,  # C_RP_NA_1
    cot=6,
    common_addr=1,
    ioa=0,
    data=struct.pack('<B', 0x01)  # QRP = 1 (general reset)
)
payload = create_iec104_i_format(i_send, i_recv, asdu_data)
pkt = create_tcp_packet(SRC_IP, DST_IP, SRC_PORT, DST_PORT, 'PA', seq_num_client, seq_num_server, payload)
packets.append(pkt)
seq_num_client += len(payload)
i_send += 1

pkt = create_tcp_packet(DST_IP, SRC_IP, DST_PORT, SRC_PORT, 'A', seq_num_server, seq_num_client)
packets.append(pkt)

print("4. IEC104 STOPDT (деактивация передачи данных)...")

# Client -> Server: STOPDT ACT
payload = create_iec104_apci_u_format('STOPDT_ACT')
pkt = create_tcp_packet(SRC_IP, DST_IP, SRC_PORT, DST_PORT, 'PA', seq_num_client, seq_num_server, payload)
packets.append(pkt)
seq_num_client += len(payload)

# === TCP Close ===
print("5. TCP соединение закрывается...")

# Client -> Server: FIN
pkt = create_tcp_packet(SRC_IP, DST_IP, SRC_PORT, DST_PORT, 'FA', seq_num_client, seq_num_server)
packets.append(pkt)
seq_num_client += 1

# Server -> Client: FIN-ACK
pkt = create_tcp_packet(DST_IP, SRC_IP, DST_PORT, SRC_PORT, 'FA', seq_num_server, seq_num_client)
packets.append(pkt)
seq_num_server += 1

# Client -> Server: ACK
pkt = create_tcp_packet(SRC_IP, DST_IP, SRC_PORT, DST_PORT, 'A', seq_num_client, seq_num_server)
packets.append(pkt)

# === Сохранение PCAP ===
print(f"\n{'='*60}")
print(f"Сохранение PCAP файла: {OUTPUT_FILE}")
wrpcap(OUTPUT_FILE, packets)

print(f"✓ Создано {len(packets)} пакетов")
print(f"✓ Файл сохранен: {OUTPUT_FILE}")
print(f"\n{'='*60}")
print("Команды для тестирования:")
print(f"\n1. Анализ с Suricata:")
print(f"   cd /Users/papkovas/mephi/asu/suricata")
print(f"   ./src/suricata -r ../{OUTPUT_FILE} -c suricata.yaml -l logs")
print(f"\n2. Проверка результатов:")
print(f"   grep -c '\"app_proto\":\"iec104\"' logs/eve.json")
print(f"   jq 'select(.event_type == \"alert\")' logs/eve.json")
print(f"\n3. Просмотр в Wireshark:")
print(f"   wireshark {OUTPUT_FILE}")
print(f"\n{'='*60}")