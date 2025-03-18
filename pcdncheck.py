# ==============================================================
# 版权声明
# 此代码由[CU_HN_网上之星]创作，版权所有。未经授权，禁止任何形式的复制、传播和使用。
# 若需使用，请与作者取得联系并获得许可。
# 创作时间：[2025年3月18日]
# ==============================================================

from scapy.all import rdpcap
import pandas as pd
from xdbSearcher import XdbSearcher
import os
from datetime import datetime
import ipaddress

# PCDN 特征检测参数
PCDN_UDP_THRESHOLD = 40  # UDP 流量占比阈值（%）
PCDN_UP_RATIO_THRESHOLD = 20  # 上行流量占比阈值（%）
MIN_UNIQUE_PROVINCES = 5  # 至少涉及的省份数
MIN_UNIQUE_ISPS = 3  # 至少涉及的运营商数

# 定义内网 IP 地址范围
private_networks = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16')
]


def is_private_ip(ip):
    """判断 IP 是否为内网 IP"""
    try:
        ip_obj = ipaddress.ip_address(ip)
        for network in private_networks:
            if ip_obj in network:
                return True
        return False
    except ValueError:
        return False


def get_ip_info(ip, searcher):
    try:
        region_str = searcher.search(ip)
        if region_str:
            data = region_str.split('|')
            province = data[2]
            city = data[3]  # 获取地市信息
            operator = data[4]
            return province, city, operator
        return None, None, None
    except Exception:
        return None, None, None


def analyze_pcap(file_path):
    try:
        # 动态获取脚本所在目录
        script_dir = os.path.dirname(os.path.abspath(__file__))
        # 构建 ip2region.xdb 文件路径
        db_path = os.path.join(script_dir, "ip2region.xdb")
        # 预先加载整个 xdb
        cb = XdbSearcher.loadContentFromFile(dbfile=db_path)
        searcher = XdbSearcher(contentBuff=cb)

        packets = rdpcap(file_path)
        ip_stats = {}

        for packet in packets:
            if 'IP' in packet:
                src_ip = packet['IP'].src
                dst_ip = packet['IP'].dst
                packet_size = len(packet)

                protocol = 'Unknown'
                if 'TCP' in packet:
                    protocol = 'TCP'
                elif 'UDP' in packet:
                    protocol = 'UDP'

                if not is_private_ip(src_ip):
                    if src_ip not in ip_stats:
                        ip_stats[src_ip] = {
                            'up_TCP': 0,
                            'up_UDP': 0,
                            'down_TCP': 0,
                            'down_UDP': 0,
                            'province': None,
                            'city': None,  # 增加地市字段
                            'operator': None
                        }
                    if protocol in ['TCP', 'UDP']:
                        ip_stats[src_ip][f'up_{protocol}'] += packet_size

                if not is_private_ip(dst_ip):
                    if dst_ip not in ip_stats:
                        ip_stats[dst_ip] = {
                            'up_TCP': 0,
                            'up_UDP': 0,
                            'down_TCP': 0,
                            'down_UDP': 0,
                            'province': None,
                            'city': None,  # 增加地市字段
                            'operator': None
                        }
                    if protocol in ['TCP', 'UDP']:
                        ip_stats[dst_ip][f'down_{protocol}'] += packet_size

        for ip in ip_stats:
            province, city, operator = get_ip_info(ip, searcher)
            ip_stats[ip]['province'] = province
            ip_stats[ip]['city'] = city  # 保存地市信息
            ip_stats[ip]['operator'] = operator

        # 关闭 searcher
        searcher.close()

        df = pd.DataFrame.from_dict(ip_stats, orient='index')
        df = df.reset_index().rename(columns={
            'index': 'IP',
            'operator': '运营商',
            'province': '省份',
            'city': '地市',  # 增加地市列
            'up_TCP': 'TCP上行',
            'down_TCP': 'TCP下行',
            'up_UDP': 'UDP上行',
            'down_UDP': 'UDP下行'
        })

        # 调整列顺序
        column_order = ['IP', '运营商', '省份', '地市', 'TCP上行', 'TCP下行', 'UDP上行', 'UDP下行']
        df = df[column_order]

        print(df)

        # 基础流量统计
        total_down = sum(row['up_TCP'] + row['up_UDP'] for row in ip_stats.values())
        total_up = sum(row['down_TCP'] + row['down_UDP'] for row in ip_stats.values())
        total_udp_down = sum(row['up_UDP'] for row in ip_stats.values())
        total_udp_up = sum(row['down_UDP'] for row in ip_stats.values())
        total_udp = total_udp_up + total_udp_down
        total_tcp_down = sum(row['up_TCP'] for row in ip_stats.values())
        total_tcp_up = sum(row['down_TCP'] for row in ip_stats.values())
        total_tcp = total_tcp_up + total_tcp_down

        # PCDN 特征计算
        features = {
            "total_packets": len(packets),
            "total_up_bytes": total_up,
            "total_down_bytes": total_down,
            "udp_percent": (total_udp / (total_udp + total_tcp)) * 100 if (total_udp + total_tcp) else 0,
            "up_ratio": (total_up / (total_up + total_down)) * 100 if (total_up + total_down) else 0,
            "unique_provinces": len({row['province'] for row in ip_stats.values() if row['province']}),
            "unique_cities": len({row['city'] for row in ip_stats.values() if row['city']}),  # 增加唯一地市数量
            "unique_isps": len({row['operator'] for row in ip_stats.values() if row['operator']}),
            "top_uploaders": sorted(ip_stats.items(), key=lambda x: x[1]['up_TCP'] + x[1]['up_UDP'], reverse=True)[:5]
        }

        # PCDN 特征分析与结论
        pcdn_signals = []

        # 信号 1：高上行流量（用户上传内容）
        if features["up_ratio"] > PCDN_UP_RATIO_THRESHOLD:
            pcdn_signals.append(f"✅ 上行流量占比高（{features['up_ratio']:.1f}% > {PCDN_UP_RATIO_THRESHOLD}%）")
        else:
            pcdn_signals.append(f"❌ 上行流量占比低（{features['up_ratio']:.1f}% < {PCDN_UP_RATIO_THRESHOLD}%）")

        # 信号 2：UDP 协议主导（实时流媒体）
        if features["udp_percent"] > PCDN_UDP_THRESHOLD:
            pcdn_signals.append(f"✅ UDP 流量占比高（{features['udp_percent']:.1f}% > {PCDN_UDP_THRESHOLD}%）")
        else:
            pcdn_signals.append(f"❌ UDP 流量占比低（{features['udp_percent']:.1f}% < {PCDN_UDP_THRESHOLD}%）")

        # 信号 3：广泛的地理分布
        if features["unique_provinces"] >= MIN_UNIQUE_PROVINCES:
            pcdn_signals.append(f"✅ 多省份节点（{features['unique_provinces']} ≥ {MIN_UNIQUE_PROVINCES}）")
        else:
            pcdn_signals.append(f"❌ 省份集中（{features['unique_provinces']} < {MIN_UNIQUE_PROVINCES}）")

        # 信号 4：多运营商混合（用户异构网络）
        if features["unique_isps"] >= MIN_UNIQUE_ISPS:
            pcdn_signals.append(f"✅ 多运营商节点（{features['unique_isps']} ≥ {MIN_UNIQUE_ISPS}）")
        else:
            pcdn_signals.append(f"❌ 运营商集中（{features['unique_isps']} < {MIN_UNIQUE_ISPS}）")

        # 信号 5：分布式节点特征（非中心化服务器）
        top_uploader_ratio = (features["top_uploaders"][0][1]['up_TCP'] + features["top_uploaders"][0][1]['up_UDP']) / total_up if total_up else 0
        if top_uploader_ratio < 0.5:  # 单个节点上传占比<50%（分布式特征）
            pcdn_signals.append(f"✅ 分布式上传（TOP1 节点占比{top_uploader_ratio * 100:.1f}% < 50%）")
        else:
            pcdn_signals.append(f"❌ 中心化上传（TOP1 节点占比{top_uploader_ratio * 100:.1f}% ≥ 50%）")

        # 新增信号 6：广泛的地市分布
        MIN_UNIQUE_CITIES = 10  # 至少涉及的地市数
        if features["unique_cities"] >= MIN_UNIQUE_CITIES:
            pcdn_signals.append(f"✅ 多地市节点（{features['unique_cities']} ≥ {MIN_UNIQUE_CITIES}）")
        else:
            pcdn_signals.append(f"❌ 地市集中（{features['unique_cities']} < {MIN_UNIQUE_CITIES}）")

        # 综合结论
        conclusion = "符合 PCDN 特征" if sum(1 for s in pcdn_signals if s.startswith("✅")) >= 3 else "不符合 PCDN 特征"

        # 输出报告
        print("\n" + "=" * 50 + "\n          PCDN 流量分析报告          \n" + "=" * 50)
        print(f"📅 分析时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"🔍 分析文件: {file_path}")
        print(f"📊 总数据包数: {features['total_packets']}")
        print(f"⬆️ 总上行流量: {total_up / 1024:.2f} KB")
        print(f"⬇️ 总下行流量: {total_down / 1024:.2f} KB")
        print(f"协议分布: UDP {features['udp_percent']:.1f}% | TCP {100 - features['udp_percent']:.1f}%")
        print(f"🌍 涉及省份: {features['unique_provinces']} 个 | 🌆 涉及地市: {features['unique_cities']} 个 | 📡 涉及运营商: {features['unique_isps']} 家")
        print("\n📌 PCDN 特征检测:")
        for sig in pcdn_signals:
            print(f"  {sig}")
        print(f"\n📢 综合结论: {conclusion}")

        # 保存 DataFrame 到 Excel 文件
        current_time = datetime.now().strftime("%Y%m%d%H%M%S")
        excel_file_path = f'pcdn_analysis_results_{current_time}.xlsx'
        try:
            df.to_excel(excel_file_path, index=False)
            print(f"结果已保存到 {excel_file_path}")
        except ImportError:
            print("无法保存为 Excel 文件，可能是缺少 openpyxl 库，请使用 'pip install openpyxl' 进行安装。")
        except Exception as e:
            print(f"保存 Excel 文件时出现错误: {e}")

    except Exception as e:
        print(f"分析文件时出现错误: {e}")


if __name__ == "__main__":
    file_path = "tcpdump2.pcap"
    analyze_pcap(file_path)
    
