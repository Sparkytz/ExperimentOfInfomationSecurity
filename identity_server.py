# identity_server.py
import logging
import time
from typing import Dict, List, Optional, Set
from flask import Flask, request, jsonify
from did_core import DIDCore, ValidationError

# 日志格式
logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s | \033[95m[Identity]\033[0m %(levelname)-8s | %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger("IdentityNode")
app = Flask(__name__)

# ==========================================
# 数据存储层
# ==========================================
class InMemoryDB:
    def __init__(self):
        # 存储结构: { did: {"hash": doc_hash, "reg_time": timestamp} }
        self._anchors: Dict[str, Dict] = {} 
        self._revocation_bitmap: List[int] = [0] * 10240
        self._blacklist: Set[str] = set()
        # 统计信息
        self.stats = {"total_dids": 0, "total_vcs": 0, "total_bans": 0}

    def save_anchor(self, did: str, doc_hash: str):
        if did not in self._anchors:
            self.stats["total_dids"] += 1
        self._anchors[did] = {"hash": doc_hash, "reg_time": int(time.time())}

    def get_anchor(self, did: str) -> Optional[str]:
        data = self._anchors.get(did)
        return data["hash"] if data else None

    def get_all_dids(self):
        results = []
        for did, info in self._anchors.items():
            status = "banned" if did in self._blacklist else "active"
            results.append({"did": did, "status": status, "reg_time": info["reg_time"]})
        return results

    def set_revoked(self, index: int):
        if 0 <= index < len(self._revocation_bitmap):
            self._revocation_bitmap[index] = 1

    def is_revoked(self, index: int) -> bool:
        if 0 <= index < len(self._revocation_bitmap):
            return self._revocation_bitmap[index] == 1
        return True # 越界默认视为撤销，安全优先

    def allocate_index(self) -> int:
        self.stats["total_vcs"] += 1
        return int(time.time() * 1000) % len(self._revocation_bitmap)

    def add_to_blacklist(self, did: str):
        if did not in self._blacklist:
            self._blacklist.add(did)
            self.stats["total_bans"] += 1
            logger.warning(f"DID [{did}] 已加入黑名单")

    def remove_from_blacklist(self, did: str):
        if did in self._blacklist:
            self._blacklist.remove(did)
            self.stats["total_bans"] -= 1
            logger.info(f"DID [{did}] 已从黑名单移除")
            
    def is_blacklisted(self, did: str) -> bool:
        return did in self._blacklist

# ==========================================
# 业务逻辑层
# ==========================================
class IdentityAuthority:
    def __init__(self, db: InMemoryDB):
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
        logger.info(f"注册新锚点 -> {did[:20]}...")
        return True

    def issue_credential(self, subject_did: str, claims: Dict) -> Dict:
        if not subject_did: raise ValidationError("申请人 DID 不能为空")
        
        # 检查黑名单
        if self.db.is_blacklisted(subject_did):
            logger.warning(f"拒绝为黑名单用户发证: {subject_did}")
            raise ValidationError("DID已被列入黑名单，禁止申请凭证")
        
        # 检查注册状态
        if not self.db.get_anchor(subject_did):
            raise ValidationError(f"DID {subject_did} 未在链上注册")

        rev_idx = self.db.allocate_index()
        vc_payload = {
            "issuer": self.did, "sub": subject_did, "iat": int(time.time()),
            "claims": claims, "revocation_idx": rev_idx
        }
        
        # 签名
        try:
            sig = DIDCore.sign(self.priv_key, vc_payload)
        except Exception as e:
            logger.error(f"签名失败: {e}")
            raise ValidationError("服务器内部签名错误")

        return {"payload": vc_payload, "proof": {"type": "SM2Signature", "sig": sig}}

    def handle_anomaly(self, did: str, reason: str, rev_idx: Optional[int] = None):
        if not did: return
        logger.warning(f"\033[91m收到异常上报 -> 拉黑: {did} | 原因: {reason}\033[0m")
        self.db.add_to_blacklist(did)
        if rev_idx is not None:
            self.db.set_revoked(rev_idx)
            logger.info(f"关联证书 Index [{rev_idx}] 已撤销")

    def recover_anomaly(self, did: str):
        if not did: return False
        if self.db.is_blacklisted(did):
            logger.info(f"收到恢复请求 -> 解封: {did}")
            self.db.remove_from_blacklist(did)
            return True
        return False
    
    def check_vc_status(self, subject_did: str, rev_idx: int) -> Dict:
        """
        [新增功能] 综合查询 VC 是否有效
        检查项：DID是否存在 + 是否被黑名单封禁 + 证书是否被撤销
        """
        # 1. 检查 DID 注册状态
        if not self.db.get_anchor(subject_did):
             return {"valid": False, "reason": "DID Not Registered", "status_code": 1001}
             
        # 2. 检查黑名单 (Global Ban)
        if self.db.is_blacklisted(subject_did):
            return {"valid": False, "reason": "Subject DID is Banned", "status_code": 1002}
            
        # 3. 检查撤销状态 (Specific Revocation)
        if self.db.is_revoked(rev_idx):
            return {"valid": False, "reason": "Credential Revoked", "status_code": 1003}
            
        return {"valid": True, "reason": "Valid", "status_code": 0}

# 单例
db_instance = InMemoryDB()
authority = IdentityAuthority(db_instance)

# ==========================================
# 辅助函数
# ==========================================
def response_wrapper(data=None, msg="Success", code=200, success=True):
    return jsonify({"success": success, "message": msg, "data": data}), code

def validate_json_params(required_fields: List[str]):
    """校验 JSON 参数是否存在"""
    if not request.json:
        raise ValidationError("Request body must be JSON")
    for field in required_fields:
        if field not in request.json:
            raise ValidationError(f"Missing required field: {field}")
    return request.json

# ==========================================
# 接口定义
# ==========================================
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
    print("   [功能] DID注册 | VC签发 | 黑名单管理 | 异常处理")
    print("="*60 + "\n")
    app.run(port=5000, debug=False)