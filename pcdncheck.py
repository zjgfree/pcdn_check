# ==============================================================
# 版权声明
# 此代码由[CU_HN_网上之星]创作，版权所有。未经授权，禁止任何形式的复制、传播和使用。
# 若需使用，请与作者取得联系并获得许可。
# 创作时间：[2025年3月19日]
# ==============================================================

from scapy.all import rdpcap
import pandas as pd
from xdbSearcher import XdbSearcher
import os
from datetime import datetime
import ipaddress
from tqdm import tqdm
import sys
import re

# 配置参数
PCDN_NODE_THRESHOLD = 0.3  # 单个节点流出占比阈值
IP2REGION_FILENAME = "ip2region.xdb"  # IP数据库文件名（与脚本同目录）
SUPERNODE_THRESHOLD = 0.01  # 上级节点流出流量占总流出流量的阈值


def get_ip_info(ip, searcher):
    """获取IP归属地（省份/城市/运营商）"""
    try:
        region = searcher.search(ip)
        if not region:
            return None, None, None
        data = region.split('|')
        return data[2], data[3], data[4]  # 省份, 城市, 运营商
    except:
        return None, None, None


def log_message(message, verbose):
    if verbose:
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{current_time}] {message}")


def analyze_pcap(file_path, verbose=False):
    log_message(f"开始分析 PCAP 文件: {file_path}", verbose)

    # 初始化IP数据库
    script_dir = os.path.dirname(os.path.abspath(__file__))
    db_path = os.path.join(script_dir, IP2REGION_FILENAME)
    cb = XdbSearcher.loadContentFromFile(dbfile=db_path)
    searcher = XdbSearcher(contentBuff=cb)
    log_message(f"成功加载 IP 数据库: {db_path}", verbose)

    # 流量统计结构
    ip_traffic = {}  # {ip: {'流出': 0, '流入': 0, '流出_TCP': 0, '流出_UDP': 0, '流入_TCP': 0, '流入_UDP': 0, '省份': '', '城市': '', '运营商': ''}}
    connections = {}  # {src_ip: set(dst_ips), dst_ip: set(src_ips)}
    total_tcp = 0
    total_udp = 0
    pcdn_http_detected = False
    http_get_requests = []

    # 解析数据包
    packets = rdpcap(file_path)
    log_message(f"成功读取 {len(packets)} 个数据包", verbose)
    for pkt in tqdm(packets, desc="解析数据包", unit="个"):
        if not pkt.haslayer('IP'):
            continue

        src_ip = pkt['IP'].src
        dst_ip = pkt['IP'].dst
        size = len(pkt)
        protocol = 'Unknown'
        if 'TCP' in pkt:
            protocol = 'TCP'
            total_tcp += size
        elif 'UDP' in pkt:
            protocol = 'UDP'
            total_udp += size

        # 统计流量
        for ip in [src_ip, dst_ip]:
            if ip not in ip_traffic:
                ip_traffic[ip] = {'流出': 0, '流入': 0, '流出_TCP': 0, '流出_UDP': 0, '流入_TCP': 0, '流入_UDP': 0,
                                  '省份': None, '城市': None, '运营商': None}

        ip_traffic[src_ip]['流出'] += size  # 流出：源IP发送的总流量
        ip_traffic[dst_ip]['流入'] += size  # 流入：目的IP接收的总流量
        if protocol == 'TCP':
            ip_traffic[src_ip]['流出_TCP'] += size
            ip_traffic[dst_ip]['流入_TCP'] += size
        elif protocol == 'UDP':
            ip_traffic[src_ip]['流出_UDP'] += size
            ip_traffic[dst_ip]['流入_UDP'] += size

        # 记录连接关系
        if src_ip not in connections:
            connections[src_ip] = set()
        connections[src_ip].add(dst_ip)
        if dst_ip not in connections:
            connections[dst_ip] = set()
        connections[dst_ip].add(src_ip)

        # 检测 HTTP 协议中是否包含 "pcdn"
        if 'TCP' in pkt and 'Raw' in pkt:
            raw_data = pkt['Raw'].load.decode('utf-8', errors='ignore')
            # 检查是否为 HTTP GET 请求
            if raw_data.startswith('GET '):
                # 提取请求路径
                parts = raw_data.split(' ')
                if len(parts) > 1:
                    path = parts[1]
                    if 'pcdn' in path.lower():
                        http_get_requests.append({
                            '源IP': src_ip,
                            '目的IP': dst_ip,
                            '请求的url': path
                        })
                        pcdn_http_detected = True

    # 获取IP归属地
    for ip in ip_traffic:
        province, city, operator = get_ip_info(ip, searcher)
        ip_traffic[ip].update({
            '省份': province,
            '城市': city,
            '运营商': operator
        })
    log_message("完成 IP 归属地查询", verbose)

    # 计算总流量
    total_out = sum(ip['流出'] for ip in ip_traffic.values())
    total_in = sum(ip['流入'] for ip in ip_traffic.values())
    total = total_out + total_in
    log_message(f"计算总流量完成：总流出 {total_out} 字节，总流入 {total_in} 字节，总计 {total} 字节", verbose)

    # 检测PCDN节点（流出TOP5且占比>30%）
    sorted_ips = sorted(ip_traffic.items(), key=lambda x: x[1]['流出'], reverse=True)
    pcdn_nodes = []
    for ip, info in sorted_ips[:5]:
        ratio = info['流出'] / total_out if total_out else 0
        if ratio > PCDN_NODE_THRESHOLD:
            pcdn_nodes.append({
                'IP': ip,
                '流出流量': info['流出'],
                '占比': f"{ratio * 100:.1f}%",
                '省份': info['省份'],
                '城市': info['城市'],
                '运营商': info['运营商']
            })
    log_message(f"检测到 {len(pcdn_nodes)} 个 PCDN 节点", verbose)

    # 关联IP分析
    associated_ips = {}
    for node in pcdn_nodes:
        node_ip = node['IP']
        peers = connections.get(node_ip, set())
        for peer in peers:
            if peer not in associated_ips:
                associated_ips[peer] = ip_traffic[peer]
    log_message(f"完成关联 IP 分析，共关联 {len(associated_ips)} 个 IP", verbose)

    # 生成报告
    report = {
        '文件信息': {
            '路径': file_path,
            '数据包数量': len(packets),
            '总流出流量': f"{total_out / 1024:.2f} KB",
            '总流入流量': f"{total_in / 1024:.2f} KB",
            '总流量': f"{total / 1024:.2f} KB",
            'TCP流量占比': f"{(total_tcp / total) * 100:.1f}%",
            'UDP流量占比': f"{(total_udp / total) * 100:.1f}%"
        },
        'PCDN节点': pcdn_nodes,
        '关联IP分析': list(associated_ips.values())
    }

    # 综合结论
    conclusion = ""
    if len(pcdn_nodes) > 0 or pcdn_http_detected:
        # 统计节点 IP 与之交互的 IP 地址的省份和运营商
        interacting_provinces = set()
        interacting_operators = set()
        for node in pcdn_nodes:
            node_ip = node['IP']
            peers = connections.get(node_ip, set())
            for peer in peers:
                interacting_provinces.add(ip_traffic[peer]['省份'])
                interacting_operators.add(ip_traffic[peer]['运营商'])

        unique_provinces = len(interacting_provinces)
        unique_operators = len(interacting_operators)

        high_udp = (total_udp / total) * 100 > 40
        multi_provinces = unique_provinces >= 5
        multi_operators = unique_operators >= 3

        signals = []
        if high_udp:
            signals.append("UDP流量占比高")
        if multi_provinces:
            signals.append("涉及多个省份")
        if multi_operators:
            signals.append("涉及多个运营商")
        if pcdn_http_detected:
            signals.append("HTTP请求中包含 'pcdn' 字样")

        signal_count = sum([high_udp, multi_provinces, multi_operators, pcdn_http_detected])
        if signal_count >= 3:
            conclusion = "完全符合PCDN特征，流量存在显著的分布式特征，多个节点参与数据分发，且网络分布广泛，各项关键指标均呈现明显的 PCDN 特性。"
        else:
            conclusion = "部分符合PCDN特征，但网络分布不够广泛或协议特征不明显。"
    else:
        conclusion = "不符合PCDN特征，未检测到符合条件的PCDN节点，且HTTP请求中未包含 'pcdn' 字样。"
        signals = []
    log_message(f"生成综合结论: {conclusion}", verbose)

    # 输出控制台报告
    print("\n" + "=" * 50 + "\n           PCDN 流量分析报告           \n" + "=" * 50)
    print(f"📅 分析时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"🔍 分析文件: {file_path}")
    print(f"📊 数据包数量: {report['文件信息']['数据包数量']}")
    print(f"⬆️ 总流出流量: {report['文件信息']['总流出流量']}")
    print(f"⬇️ 总流入流量: {report['文件信息']['总流入流量']}")
    print(f"📈 总流量: {report['文件信息']['总流量']}")
    print(f"📶 TCP流量占比: {report['文件信息']['TCP流量占比']}")
    print(f"📶 UDP流量占比: {report['文件信息']['UDP流量占比']}\n")

    # 输出PCDN节点
    print("🚩 PCDN节点检测（流出TOP5且占比>30%）:")
    if pcdn_nodes:
        for i, node in enumerate(pcdn_nodes, 1):
            print(f"节点 {i}:")
            print(f"  IP: {node['IP']}")
            print(f"  流出流量: {node['流出流量'] / 1024:.2f} KB | 占比: {node['占比']}")
            print(f"  归属地: {node['省份']} {node['城市']} | 运营商: {node['运营商']}\n")
    else:
        print("  未检测到符合条件的PCDN节点（TOP5节点流出占比均<30%）\n")

    # 处理关联IP的DataFrame
    if associated_ips:
        df = pd.DataFrame(associated_ips).T.reset_index()
        df.columns = ['IP', '流出流量', '流入流量', '流出_TCP', '流出_UDP', '流入_TCP', '流入_UDP', '省份', '城市',
                      '运营商']
        # 计算关联 IP 表格中的总流出流量
        associated_total_out = df['流出流量'].sum()
        df['上级节点IP'] = df.apply(
            lambda row: '是' if row['流出流量'] / associated_total_out > SUPERNODE_THRESHOLD else '否', axis=1)
        df = df.sort_values(by='流出流量', ascending=False)
    else:
        df = pd.DataFrame()

    # 全局流量
    df_all = pd.DataFrame(ip_traffic).T.reset_index()
    df_all.columns = ['IP', '流出流量', '流入流量', '流出_TCP', '流出_UDP', '流入_TCP', '流入_UDP', '省份', '城市',
                      '运营商']
    df_all = df_all.sort_values(by='流出流量', ascending=False)

    print(f"📢 综合结论: {conclusion}")
    print(f"📢 检测信号: {', '.join(signals) if signals else '无'}")

    # 保存结果到Excel
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    excel_path = f"pcdn_analysis_{timestamp}.xlsx"
    with pd.ExcelWriter(excel_path) as writer:
        # PCDN节点
        if pcdn_nodes:
            pd.DataFrame(pcdn_nodes).to_excel(writer, sheet_name="PCDN节点", index=False)
        # 关联IP
        if not df.empty:
            df[['IP', '省份', '城市', '运营商', '流出流量', '流入流量', '上级节点IP']].to_excel(writer,
                                                                                                   sheet_name="关联IP",
                                                                                                   index=False)
        # 全局流量
        df_all.to_excel(writer, sheet_name="全量IP统计", index=False)
        # HTTP GET 请求路径
        if http_get_requests:
            df_http_get = pd.DataFrame(http_get_requests)
            df_http_get = df_http_get.sort_values(by='目的IP', ascending=True)
            df_http_get.to_excel(writer, sheet_name="HTTP GET 请求", index=False)
    log_message(f"分析结果已保存到 {excel_path}", verbose)

    searcher.close()


if __name__ == "__main__":
    if len(sys.argv) not in [2, 3]:
        print("使用方法: python pcap_analyzer.py <pcap文件路径> [-v]")
        sys.exit(1)

    file_path = sys.argv[1]
    verbose = '-v' in sys.argv

    analyze_pcap(file_path, verbose)
    
