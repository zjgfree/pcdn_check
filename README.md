# PCDN 流量分析工具（PCAP 文件分析）

## 🔍 项目简介
本工具用于分析 Wireshark 捕获的 `.pcap` 文件，识别网络流量是否符合 **PCDN（P2P 内容分发网络）** 特征，支持：
- 统计 IP 流量（TCP/UDP 上行/下行）
- 识别 IP 归属地（省份、地市、运营商）
- 检测 PCDN 特征（高上行、UDP 主导、分布式节点等）
- 输出结果到 Excel 文件（含时间戳后缀）


## 📦 依赖环境
```bash
# 安装依赖（通过 requirements.txt）
pip install -r requirements.txt
```

### `requirements.txt` 内容：
```plaintext
scapy>=2.4.5          # 网络数据包解析
pandas>=1.3.0        # 数据处理
openpyxl>=3.0.7      # Excel 文件写入
xdbSearcher>=1.0.0   # IP 归属地查询（需确认库来源）
```


## 🚀 快速开始

### 1. 准备文件
- **PCAP 文件**：待分析的网络数据包文件（如 `tcpdump.pcap`）。
- **IP 数据库**：下载 `ip2region.xdb` 数据库（[官网地址](https://github.com/lionsoul2014/ip2region)），并放置到指定路径（默认：`ip2region.xdb`）。

### 2. 配置参数
修改代码中的以下参数（可选）：
```python
# PCDN 特征检测阈值（位于代码开头）
PCDN_UDP_THRESHOLD = 40       # UDP 流量占比阈值（%）
PCDN_UP_RATIO_THRESHOLD = 20  # 上行流量占比阈值（%）
MIN_UNIQUE_PROVINCES = 5      # 至少涉及的省份数
MIN_UNIQUE_ISPS = 3           # 至少涉及的运营商数
```

### 3. 运行程序
```bash
python pcdncheck.py [PCAP文件路径]
# 示例：
python pcdncheck.py tcpdump.pcap
```


## 📊 功能说明

### 1. 输入与输出
- **输入**：Wireshark 捕获的 `.pcap` 文件。
- **输出**：
  - 控制台输出：流量统计、PCDN 特征分析报告。
  - Excel 文件：`pcap_analysis_results_时间戳.xlsx`（含 IP、归属地、流量详情）。

### 2. Excel 表格结构
| 列名         | 说明                     |
|--------------|--------------------------|
| IP           | 公网 IP 地址             |
| 运营商       | 网络运营商（如：中国电信）|
| 省份         | 归属省份（如：广东省）   |
| 地市         | 归属地市（如：深圳市）   |
| TCP上行       | TCP 协议上行流量（字节） |
| TCP下行       | TCP 协议下行流量（字节） |
| UDP上行       | UDP 协议上行流量（字节） |
| UDP下行       | UDP 协议下行流量（字节） |

### 3. PCDN 特征检测
检测以下特征（满足 ≥3 个则判定为 PCDN 流量）：
1. 上行流量占比 > 20%（用户上传内容）。
2. UDP 流量占比 > 40%（实时流媒体主导）。
3. 涉及 ≥5 个省份（分布式节点）。
4. 涉及 ≥3 个运营商（异构网络）。
5. 单个节点上传占比 < 50%（非中心化）。
6. 涉及 ≥10 个地市（广泛地理分布）。


## ⚙️ 配置说明

### 1. IP 数据库路径
修改代码中的数据库路径：
```python
db_path = os.path.join(script_dir, "ip2region.xdb")
# 建议：将数据库文件放置在项目的根目录下
```

### 2. 内网 IP 过滤
自动过滤以下内网 IP 段：
- `10.0.0.0/8`
- `172.16.0.0/12`
- `192.168.0.0/16`


## 📄 版权声明
```
版权所有 (C) [网上之星] 2023-2025  
未经授权禁止任何形式的复制、修改和传播。  

本程序基于以下开源项目：  
- Scapy：https://scapy.net/  
- pandas：https://pandas.pydata.org/  
- ip2region：https://github.com/lionsoul2014/ip2region  
```


## 🐞 常见问题
1. **`xdbSearcher` 安装失败**：  
   - 确认库的来源（如：私有仓库或 PyPI），使用正确的安装命令。  
   - 示例：`pip install git+https://github.com/your-username/xdbSearcher.git`

2. **Excel 保存失败**：  
   - 确保已安装 `openpyxl`：`pip install openpyxl`。

3. **IP 归属地缺失**：  
   - 检查 `ip2region.xdb` 是否最新，或替换为包含地市数据的版本。


## 📚 示例输出
```
==================================================
          PCDN 流量分析报告          
==================================================
📅 分析时间: 2025-03-18 15:00:00  
🔍 分析文件: tcpdump.pcap  
📊 总数据包数: 100000  
⬆️ 总上行流量: 45000.00 KB  
⬇️ 总下行流量: 60000.00 KB  
协议分布: UDP 55.0% | TCP 45.0%  
🌍 涉及省份: 8 个 | 🌆 涉及地市: 15 个 | 📡 涉及运营商: 4 家  

📌 PCDN 特征检测:  
  ✅ 上行流量占比高（42.9% > 20%）  
  ✅ UDP 流量占比高（55.0% > 40%）  
  ✅ 多省份节点（8 ≥ 5）  
  ✅ 多运营商节点（4 ≥ 3）  
  ✅ 分布式上传（TOP1 节点占比 25.0% < 50%）  
  ✅ 多地市节点（15 ≥ 10）  

📢 综合结论: 符合 PCDN 特征  
📥 结果已保存: pcdn_analysis_results_20250318150000.xlsx  
```


## 📖 版本说明
- **版本**：1.0.0（稳定版）  
- **更新日志**：  
  - 2025-03-18：初始版本，支持 PCDN 特征检测、地市维度分析。  
  - 2025-03-20：修复上行/下行流量统计逻辑，优化 IP 归属地查询。


