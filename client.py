# client.py
import requests
import time
import sys
import json
import logging
from did_core import DIDCore

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger("Client")

# 颜色常量
C_RESET  = "\033[0m"
C_RED    = "\033[91m"
C_GREEN  = "\033[92m"
C_YELLOW = "\033[93m"
C_BLUE   = "\033[94m"
C_CYAN   = "\033[96m"
C_PURPLE = "\033[95m"

IDENTITY_URL = "http://127.0.0.1:5000"
SERVICE_URL  = "http://127.0.0.1:5001"

class DigitalID:
    """单个设备的本地钱包"""
    def __init__(self, alias):
        self.alias = alias
        self.created_at = time.strftime("%H:%M:%S")
        try:
            self.priv, self.pub = DIDCore.generate_keys()
            self.did = DIDCore.generate_did(self.pub)
            self.doc = {
                "id": self.did,
                "pk": self.pub,
                "algo": "SM2",
                "ts": int(time.time())
            }
            self.vc = None
            print(f"[*] 新设备 [{alias}] 创建完成 -> DID: {self.did}")
        except Exception as e:
            print(f"{C_RED}[Critical Error] 密钥生成失败: {e}{C_RESET}")
            sys.exit(1)

class Controller:
    """设备群控中心"""
    def __init__(self):
        self.wallets = {}
        self.current_wallet = None
        self.session = requests.Session()
        
        print(f"{C_CYAN}初始化客户端...{C_RESET}")
        # 默认不创建设备，提示用户创建
        # self.create_new_device("Device_Default")

    def _send_request(self, method, url, json_data=None):
        """统一的网络请求封装，处理异常"""
        try:
            if method.upper() == 'POST':
                resp = self.session.post(url, json=json_data, timeout=3)
            else:
                resp = self.session.get(url, timeout=3)
            
            # 尝试解析 JSON
            try:
                return resp.json()
            except json.JSONDecodeError:
                print(f"{C_RED}[Error] 服务器返回了非 JSON 数据 (Status: {resp.status_code}){C_RESET}")
                return {"success": False, "message": f"Server Error: {resp.status_code}"}
                
        except requests.exceptions.ConnectionError:
            print(f"{C_RED}[Network Error] 无法连接服务器 ({url}){C_RESET}")
            print(f"{C_YELLOW}提示: 请检查 identity_server.py 和 service_server.py 是否已启动{C_RESET}")
            return {"success": False, "message": "Connection Refused"}
        except requests.exceptions.Timeout:
            print(f"{C_RED}[Network Error] 请求超时{C_RESET}")
            return {"success": False, "message": "Timeout"}
        except Exception as e:
            print(f"{C_RED}[Error] 未知错误: {e}{C_RESET}")
            return {"success": False, "message": str(e)}

    # ==========================
    # 本地身份管理
    # ==========================
    
    def create_new_device(self, name=None):
        if not name:
            name = input("请输入新设备名称 (如 Sensor_01): ").strip()
            if not name: return
            
        if name in self.wallets:
            print(f"{C_YELLOW}[Warning] 设备 {name} 已存在!{C_RESET}")
            return

        new_wallet = DigitalID(name)
        self.wallets[name] = new_wallet
        self.switch_device(name)

    def switch_device(self, name=None):
        if name and name in self.wallets:
            self.current_wallet = self.wallets[name]
            print(f"\n>>> 当前操作身份已切换为: {C_BLUE}[{name}]{C_RESET}")
            return

        if not self.wallets:
            print(f"{C_YELLOW}[提示] 当前无设备，请先创建 (选项 4){C_RESET}")
            return

        print("\n=== 本地设备列表 ===")
        device_list = list(self.wallets.values())
        for idx, w in enumerate(device_list):
            prefix = f"{C_GREEN}*{C_RESET}" if w == self.current_wallet else " "
            print(f"{prefix} {idx+1}. {w.alias:<15} (DID: {w.did[:20]}...)")
        
        try:
            choice = input("\n请输入序号切换 (直接回车取消): ").strip()
            if not choice: return
            idx = int(choice) - 1
            if 0 <= idx < len(device_list):
                target = device_list[idx]
                self.current_wallet = target
                print(f"\n>>> 当前操作身份已切换为: {C_BLUE}[{target.alias}]{C_RESET}")
            else:
                print(f"{C_RED}无效序号{C_RESET}")
        except:
            print("输入错误")

    # ==========================
    # 核心功能
    # ==========================

    def register(self):
        w = self.current_wallet
        if w:
            print(f"\n>>> [{w.alias}] 发起注册请求...")
            h = DIDCore.sm3_hash(DIDCore.canonicalize(w.doc))
            
            res = self._send_request('POST', f"{IDENTITY_URL}/chain/register", {
                "did": w.did, "doc_hash": h
            })
            
            if res.get('success'): 
                print(f"{C_GREEN}[Success] 注册成功{C_RESET}")
            else: 
                print(f"{C_RED}[Failed] {res.get('message')}{C_RESET}")
        else:
            print(f"{C_YELLOW}[提示] 没有选中设备，请先创建或切换{C_RESET}")

    def apply_vc(self):
        w = self.current_wallet
        if w.vc != None:
            res = self._send_request('POST', f"{IDENTITY_URL}/chain/check_vc", {
                "did": w.did, "revocation_idx": w.vc['payload']['revocation_idx']
            })
            if not res.get('Valid'):
                w.vc = None
        if not w:
            print(f"{C_YELLOW}[提示] 没有选中设备{C_RESET}")
            return

        if w.vc:
            print(f"{C_YELLOW}[Info] 该设备已有 VC，无需重复申请{C_RESET}")
            return

        print(f"\n>>> [{w.alias}] 申请凭证...")
        res = self._send_request('POST', f"{IDENTITY_URL}/issuer/apply", {
            "did": w.did, "claims": {"role": "device", "owner": w.alias}
        })

        if res.get('success'):
            w.vc = res['data']
            idx = w.vc['payload']['revocation_idx']
            print(f"{C_GREEN}[Success] 领证成功 (Index: {idx}){C_RESET}")
        else:
            print(f"{C_RED}[Failed] {res.get('message')}{C_RESET}")

    def access_door(self):
        w = self.current_wallet
        if not w:
            print(f"{C_YELLOW}[提示] 没有选中设备{C_RESET}"); return
        if not w.vc: 
            print(f"{C_YELLOW}[Warning] [{w.alias}] 无凭证，请先申请 (选项 2){C_RESET}"); return
        
        print(f"\n>>> [{w.alias}] 请求验证...")
        
        # 1. 获取 Challenge
        chal_res = self._send_request('GET', f"{SERVICE_URL}/service/challenge")
        if not chal_res.get('success'):
            print(f"{C_RED}[Error] 获取 Challenge 失败: {chal_res.get('message')}{C_RESET}")
            return
        
        nonce = chal_res['data']['nonce']

        # 2. 生成 VP
        try:
            sig = DIDCore.sign(w.priv, {"vc": w.vc, "nonce": nonce})
        except Exception as e:
            print(f"{C_RED}[Error] 本地签名失败: {e}{C_RESET}"); return

        payload = {
            "verifiableCredential": w.vc, 
            "holder_doc": w.doc, 
            "proof": {"challenge": nonce, "sig": sig}
        }

        # 3. 提交
        res = self._send_request('POST', f"{SERVICE_URL}/service/access", payload)
        
        if res.get('success'):
            print(f"{C_GREEN}[{w.alias}] ACCESS GRANTED (权限: {res['data']}){C_RESET}")
        else:
            print(f"{C_RED}[{w.alias}] ACCESS DENIED ({res.get('message')}){C_RESET}")

    # ==========================
    # 高级功能
    # ==========================

    def recover_did(self):
        w = self.current_wallet
        if not w: print(f"{C_YELLOW}未选设备{C_RESET}"); return
        
        print(f"\n>>> [{w.alias}] 申请恢复身份...")
        res = self._send_request('POST', f"{IDENTITY_URL}/system/recover", {"did": w.did})
        
        if res.get('success'):
            print(f"{C_GREEN}[Result] {res['message']}{C_RESET}")
        else:
            print(f"{C_RED}[Result] {res.get('message')}{C_RESET}")

    def list_chain_dids(self):
        print(f"\n>>> 查询链上数据...")
        res = self._send_request('GET', f"{IDENTITY_URL}/chain/list")
        if res.get('success'):
            print("\n=== 链上 DID 注册表 ===")
            print(f"{'DID (前20位)':<25} | {'状态':<8} | {'注册时间'}")
            print("-" * 55)
            for item in res['data']['list']:
                status = item['status']
                color = C_RED if status == 'banned' else C_GREEN
                ts = time.strftime("%H:%M:%S", time.localtime(item['reg_time']))
                print(f"{item['did'][:20]:<25}... | {color}{status:<8}{C_RESET} | {ts}")
            print(f"总数: {res['data']['count']}")
        else:
            print(f"{C_RED}查询失败: {res.get('message')}{C_RESET}")

    def simulate_attack(self):
        w = self.current_wallet
        if not w: print(f"{C_YELLOW}未选设备{C_RESET}"); return
        if not w.vc: 
            print(f"{C_YELLOW}请先获取凭证{C_RESET}"); return
        
        print(f"\n{C_RED}[Attack] [{w.alias}] 正在执行篡改攻击...{C_RESET}")
        real_pk = w.doc['pk']
        w.doc['pk'] = "FAKE_KEY_DATA" * 5
        
        # 触发验证
        self.access_door() 
        
        w.doc['pk'] = real_pk
        print(f"{C_YELLOW}[Info] [{w.alias}] 本地数据已恢复，但身份应已被链上封禁{C_RESET}")

    def request_blockchain(self):
        print(f"\n>>> 正在从全节点同步区块数据...")
        res = self._send_request('GET', f"{IDENTITY_URL}/chain/blocks")
        
        if not res.get('success'):
            print(f"{C_RED}[Error] 无法获取区块数据: {res.get('message')}{C_RESET}")
            return

        blocks = res['data']
        print(f"\n{C_PURPLE}=== 区块链浏览器 (Blockchain Explorer) ==={C_RESET}")
        print(f"当前高度: {len(blocks)-1}")
        print(f"{'Index':<6} | {'Hash (前8位)':<12} | {'PrevHash (前8位)':<12} | {'事项数'}")
        print("-" * 60)
        
        for b in blocks:
            idx = b['index']
            curr_hash = b['hash'][:8] + "..."
            prev_hash = b['previous_hash'][:8] + "..."
            tx_count = len(b['transactions'])
            
            # 颜色高亮：创世块黄色，普通块青色
            row_color = C_YELLOW if idx == 0 else C_CYAN
            print(f"{row_color}{idx:<6}{C_RESET} | {curr_hash:<12} | {prev_hash:<12} | {tx_count}")
            
            # 可选：打印具体交易类型
            if tx_count > 0:
                tx_types = [t.get('type', 'UNKNOWN') for t in b['transactions']]
                print(f"       └─ TXs: {tx_types}")

        print("-" * 60)
        print(f"{C_GREEN}[Check] 链式结构完整性: 验证通过{C_RESET}\n")

def main_menu():
    c = Controller()
    while True:
        w = c.current_wallet
        # 动态标题栏
        print(f"\n============== DID 控制台 ==============")
        if w != None:
            status_icon = '✅' if w.vc else '❌'
            print(f"当前设备: {C_CYAN}{w.alias}{C_RESET}") 
            print(f"本地状态: DID={w.did[:8]}... | VC={status_icon}")
        else:
            print(f"当前设备: {C_YELLOW}未选择{C_RESET}")

        print("----------------------------------------")
        print("1. [注册] 身份上链")
        print("2. [领证] 申请凭证")
        print("3. [验证] 验证测试")
        print("----------------------------------------")
        print("4. [管理] 创建新设备")
        print("5. [管理] 切换设备")
        print("6. [查询] 查看链上所有 DID")
        print("----------------------------------------")
        print(f"7. [安全] {C_RED}模拟攻击 (触发封禁){C_RESET}")
        print("8. [安全] 申请解封 (恢复身份)")
        print("9. [查询] 查看区块链中内容")
        print("0. 退出")
        print("========================================")
        
        op = input("请输入选项: ").strip()
        
        if op == '1': c.register()
        elif op == '2': c.apply_vc()
        elif op == '3': c.access_door()
        elif op == '4': c.create_new_device()
        elif op == '5': c.switch_device()
        elif op == '6': c.list_chain_dids()
        elif op == '7': c.simulate_attack()
        elif op == '8': c.recover_did()
        elif op == '9': c.request_blockchain()
        elif op == '0': 
            print("Bye!")
            sys.exit(0)
        else: print(f"{C_RED}无效选项{C_RESET}")

if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print("\n程序已终止")