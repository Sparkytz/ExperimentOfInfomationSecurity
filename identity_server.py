# identity_server.py
import logging
import time
import json
import hashlib
from typing import Dict, List, Optional, Set, Any
from flask import Flask, request, jsonify
from did_core import DIDCore, ValidationError

# 配置更清晰的日志格式
logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s | \033[95m[ChainNode]\033[0m %(levelname)-8s | %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger("IdentityNode")
app = Flask(__name__)

# ==========================================
# 区块链核心组件
# ==========================================
class Block:
    def __init__(self, index: int, transactions: List[Dict], timestamp: int, previous_hash: str):
        self.index = index
        self.transactions = transactions
        self.timestamp = timestamp
        self.previous_hash = previous_hash
        self.nonce = 0
        self.hash = self.compute_hash()

    def compute_hash(self) -> str:
        """计算区块哈希：SHA256(index + prev_hash + txs + timestamp + nonce)"""
        block_string = json.dumps({
            "index": self.index,
            "timestamp": self.timestamp,
            "previous_hash": self.previous_hash,
            "transactions": self.transactions,
            "nonce": self.nonce
        }, sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()

class BlockchainDB:
    """
    模拟区块链数据库。
    数据写入 -> 生成事项 -> 打包区块 -> 更新状态(State)
    数据读取 -> 直接读取状态(State)
    """
    def __init__(self):
        # 1. 链式账本
        self.chain: List[Block] = []
        self.pending_transactions: List[Dict] = []
        
        # 2. 状态
        self.state = {
            "anchors": {},      # { did: {"hash": ..., "reg_time": ...} }
            "revocation": [0] * 10240, # 位图
            "blacklist": set(), # 黑名单
            "stats": {"total_dids": 0, "total_vcs": 0, "total_bans": 0}
        }
        
        # 初始化创世区块
        self.create_genesis_block()

    def create_genesis_block(self):
        genesis_tx = [{"type": "GENESIS", "payload": "Identity Chain Launched"}]
        genesis_block = Block(0, genesis_tx, int(time.time()), "0"*64)
        self.chain.append(genesis_block)
        logger.info(f"创世区块已生成 | Hash: {genesis_block.hash[:16]}...")

    def _add_transaction(self, tx_type: str, **kwargs):
        """提交事项到缓冲池"""
        tx = {"type": tx_type, "timestamp": int(time.time()), **kwargs}
        self.pending_transactions.append(tx)
        # 模拟：每笔交易立即出块 (Instant Mine)
        self.handle_block()

    def handle_block(self):
        """打包交易，生成新块，更新状态"""
        if not self.pending_transactions:
            return

        last_block = self.chain[-1]
        new_block = Block(
            index=len(self.chain),
            transactions=self.pending_transactions,
            timestamp=int(time.time()),
            previous_hash=last_block.hash
        )
        
        # 简单工作量证明 (可选，此处略过直接上链)
        self.chain.append(new_block)
        
        # *** 关键：执行状态转换 (State Transition) ***
        self._update_state(self.pending_transactions)
        
        logger.info(f"⛏️  新区块 #{new_block.index} 上链 | Txs: {len(new_block.transactions)} | Prev: {new_block.previous_hash[:8]}")
        self.pending_transactions = [] # 清空缓冲池

    def _update_state(self, transactions):
        """更新内存字典"""
        for tx in transactions:
            t_type = tx['type']
            
            if t_type == "REGISTER_DID":
                did, doc_hash = tx['did'], tx['doc_hash']
                if did not in self.state["anchors"]:
                    self.state["stats"]["total_dids"] += 1
                self.state["anchors"][did] = {"hash": doc_hash, "reg_time": tx['timestamp']}
                
            elif t_type == "ISSUE_VC":
                self.state["stats"]["total_vcs"] += 1
                
            elif t_type == "REVOKE_VC":
                idx = tx['idx']
                if 0 <= idx < len(self.state["revocation"]):
                    self.state["revocation"][idx] = 1
                    
            elif t_type == "BAN_DID":
                if tx['did'] not in self.state["blacklist"]:
                    self.state["blacklist"].add(tx['did'])
                    self.state["stats"]["total_bans"] += 1
                    
            elif t_type == "UNBAN_DID":
                if tx['did'] in self.state["blacklist"]:
                    self.state["blacklist"].remove(tx['did'])
                    self.state["stats"]["total_bans"] -= 1

    # ==========================
    # 接口方法
    # ==========================
    
    def save_anchor(self, did: str, doc_hash: str):
        self._add_transaction("REGISTER_DID", did=did, doc_hash=doc_hash)

    def set_revoked(self, index: int):
        self._add_transaction("REVOKE_VC", idx=index)

    def allocate_index(self) -> int:
        # 分配索引同时也记录一次发证
        idx = int(time.time() * 1000) % len(self.state["revocation"])
        self._add_transaction("ISSUE_VC", idx=idx)
        return idx

    def add_to_blacklist(self, did: str):
        self._add_transaction("BAN_DID", did=did)

    def remove_from_blacklist(self, did: str):
        self._add_transaction("UNBAN_DID", did=did)

    # [Read] 所有的读操作读取 self.state
    def get_anchor(self, did: str) -> Optional[str]:
        data = self.state["anchors"].get(did)
        return data["hash"] if data else None

    def get_all_dids(self):
        results = []
        for did, info in self.state["anchors"].items():
            status = "banned" if did in self.state["blacklist"] else "active"
            results.append({"did": did, "status": status, "reg_time": info["reg_time"]})
        return results

    def is_revoked(self, index: int) -> bool:
        if 0 <= index < len(self.state["revocation"]):
            return self.state["revocation"][index] == 1
        return True

    def is_blacklisted(self, did: str) -> bool:
        return did in self.state["blacklist"]

# ==========================================
# 业务逻辑层
# ==========================================
class IdentityAuthority:
    def __init__(self, db: BlockchainDB):
        self.db = db
        try:
            self.priv_key, self.pub_key = DIDCore.generate_keys()
            self.did = DIDCore.generate_did(self.pub_key)
            
            # 注册根 Issuer
            self_doc = {"id": self.did, "pk": self.pub_key, "role": "RootIssuer"}
            doc_hash = DIDCore.sm3_hash(DIDCore.canonicalize(self_doc))
            self.db.save_anchor(self.did, doc_hash)
            logger.info(f"系统初始化完成. Root Issuer DID: \033[94m{self.did}\033[0m")
        except Exception as e:
            logger.critical(f"密钥生成失败，系统无法启动: {e}")
            raise e

    def register_did(self, did: str, doc_hash: str) -> bool:
        if not did or not doc_hash:
            raise ValidationError("DID 或 文档哈希 不能为空")
        if not DIDCore.validate_did_format(did): 
            raise ValidationError(f"DID格式错误: {did}")
        
        self.db.save_anchor(did, doc_hash)
        logger.info(f"注册请求已提交上链 -> {did[:20]}...")
        return True

    def issue_credential(self, subject_did: str, claims: Dict) -> Dict:
        if not subject_did: raise ValidationError("申请人 DID 不能为空")
        
        if self.db.is_blacklisted(subject_did):
            logger.warning(f"拒绝为黑名单用户发证: {subject_did}")
            raise ValidationError("DID已被列入黑名单，禁止申请凭证")
        
        if not self.db.get_anchor(subject_did):
            raise ValidationError(f"DID {subject_did} 未在链上注册")

        rev_idx = self.db.allocate_index()
        vc_payload = {
            "issuer": self.did, "sub": subject_did, "iat": int(time.time()),
            "claims": claims, "revocation_idx": rev_idx
        }
        
        try:
            sig = DIDCore.sign(self.priv_key, vc_payload)
        except Exception as e:
            logger.error(f"签名失败: {e}")
            raise ValidationError("服务器内部签名错误")

        return {"payload": vc_payload, "proof": {"type": "SM2Signature", "sig": sig}}

    def handle_anomaly(self, did: str, reason: str, rev_idx: Optional[int] = None):
        if not did: return
        logger.warning(f"\033[91m收到异常上报 -> 交易生成: 拉黑 {did}\033[0m")
        self.db.add_to_blacklist(did)
        if rev_idx is not None:
            self.db.set_revoked(rev_idx)

    def recover_anomaly(self, did: str):
        if not did: return False
        if self.db.is_blacklisted(did):
            logger.info(f"收到恢复请求 -> 交易生成: 解封 {did}")
            self.db.remove_from_blacklist(did)
            return True
        return False

    def check_vc_status(self, subject_did: str, rev_idx: int) -> Dict:
        # 读操作，直接查 State，速度极快
        if not self.db.get_anchor(subject_did):
             return {"valid": False, "reason": "DID Not Registered", "status_code": 1001}
        if self.db.is_blacklisted(subject_did):
            return {"valid": False, "reason": "Subject DID is Banned", "status_code": 1002}
        if self.db.is_revoked(rev_idx):
            return {"valid": False, "reason": "Credential Revoked", "status_code": 1003}
        return {"valid": True, "reason": "Valid", "status_code": 0}

# 单例
db_instance = BlockchainDB()
authority = IdentityAuthority(db_instance)

# ==========================================
# 辅助函数
# ==========================================
def response_wrapper(data=None, msg="Success", code=200, success=True):
    return jsonify({"success": success, "message": msg, "data": data}), code

def validate_json_params(required_fields: List[str]):
    if not request.json:
        raise ValidationError("Request body must be JSON")
    for field in required_fields:
        if field not in request.json:
            raise ValidationError(f"Missing required field: {field}")
    return request.json

# ==========================================
# 接口定义
# ==========================================

@app.route('/chain/blocks', methods=['GET'])
def get_chain_blocks():
    """返回完整的区块链数据，用于可视化"""
    chain_data = [
        {
            "index": b.index,
            "hash": b.hash,
            "previous_hash": b.previous_hash,
            "timestamp": b.timestamp,
            "transactions": b.transactions
        } 
        for b in db_instance.chain
    ]
    return response_wrapper(data=chain_data)

@app.route('/chain/anchor/<did>', methods=['GET'])
def query_anchor(did):
    hash_val = db_instance.get_anchor(did)
    if hash_val:
        status = "banned" if db_instance.is_blacklisted(did) else "active"
        return response_wrapper(data={"doc_hash": hash_val, "status": status})
    return response_wrapper(success=False, msg="DID Not Found", code=404)

@app.route('/chain/list', methods=['GET'])
def list_dids():
    dids = db_instance.get_all_dids()
    return response_wrapper(data={"count": len(dids), "list": dids})

@app.route('/chain/revocation/<int:index>', methods=['GET'])
def query_revocation(index):
    return response_wrapper(data={"is_revoked": db_instance.is_revoked(index)})

@app.route('/chain/check_vc', methods=['POST'])
def check_vc_api():
    try:
        data = validate_json_params(['did', 'revocation_idx'])
        result = authority.check_vc_status(data['did'], int(data['revocation_idx']))
        return response_wrapper(data=result)
    except ValidationError as e:
        return response_wrapper(success=False, msg=str(e), code=400)
    except Exception as e:
        logger.error(f"VC查询接口异常: {e}")
        return response_wrapper(success=False, msg="Internal Server Error", code=500)

@app.route('/issuer/info', methods=['GET'])
def get_issuer_pubkey():
    return response_wrapper(data={"did": authority.did, "pk": authority.pub_key})

@app.route('/chain/register', methods=['POST'])
def register_api():
    try:
        data = validate_json_params(['did', 'doc_hash'])
        authority.register_did(data['did'], data['doc_hash'])
        return response_wrapper(msg="DID Registered Successfully")
    except ValidationError as e:
        return response_wrapper(success=False, msg=str(e), code=400)
    except Exception as e:
        logger.error(f"注册接口异常: {e}")
        return response_wrapper(success=False, msg="Internal Server Error", code=500)

@app.route('/issuer/apply', methods=['POST'])
def issue_api():
    try:
        data = validate_json_params(['did', 'claims'])
        vc = authority.issue_credential(data['did'], data['claims'])
        return response_wrapper(data=vc)
    except ValidationError as e:
        return response_wrapper(success=False, msg=str(e), code=403)
    except Exception as e:
        logger.error(f"发证接口异常: {e}")
        return response_wrapper(success=False, msg="Internal Server Error", code=500)

@app.route('/system/report_anomaly', methods=['POST'])
def report_anomaly_api():
    try:
        d = validate_json_params(['did', 'reason'])
        authority.handle_anomaly(d['did'], d['reason'], d.get('revocation_idx'))
        return response_wrapper(msg="Anomaly Processed")
    except Exception:
        return response_wrapper(success=False, msg="Invalid Report", code=400)

@app.route('/system/recover', methods=['POST'])
def recover_api():
    try:
        data = validate_json_params(['did'])
        if authority.recover_anomaly(data['did']):
            return response_wrapper(msg=f"DID {data['did']} recovered")
        return response_wrapper(success=False, msg="DID not found or not banned", code=404)
    except Exception as e:
        return response_wrapper(success=False, msg=str(e), code=400)

if __name__ == '__main__':
    print("\n" + "="*60)
    print("   Identity Server Running on Port 5000")
    print("   [Feature] Simulated Blockchain Ledger (Linked Hash)")
    print("   [Feature] Tamper-Evident Transaction Log")
    print("   [功能] DID注册 | VC签发 | 黑名单管理 | 异常处理")
    print("="*60 + "\n")
    app.run(port=5000, debug=False)