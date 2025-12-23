# service_server.py
import logging
import time
import uuid
import requests
from flask import Flask, request, jsonify
from did_core import DIDCore

logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s | \033[96m[Service]\033[0m  %(levelname)-8s | %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger("ServiceNode")
app = Flask(__name__)
IDENTITY_HOST = "http://127.0.0.1:5000"

# ==========================================
# 远程调用客户端
# ==========================================
class TrustAnchorClient:
    """封装与 Identity Server 的通信，包含错误处理"""
    
    @staticmethod
    def _safe_get(endpoint, timeout=2):
        try:
            resp = requests.get(f"{IDENTITY_HOST}{endpoint}", timeout=timeout)
            if resp.status_code == 200:
                return resp.json()
            logger.error(f"Identity Server Error [{endpoint}]: {resp.status_code}")
            return None
        except requests.exceptions.ConnectionError:
            logger.error(f"\033[91m连接失败: 无法连接到 Identity Server ({IDENTITY_HOST})\033[0m")
            return None
        except Exception as e:
            logger.error(f"请求异常: {e}")
            return None

    @staticmethod
    def get_anchor_info(did: str):
        data = TrustAnchorClient._safe_get(f"/chain/anchor/{did}")
        if data and data.get('success'):
            d = data['data']
            return d.get('doc_hash'), d.get('status', 'active')
        return None, None

    @staticmethod
    def check_revocation(index: int):
        if index is None: return True
        data = TrustAnchorClient._safe_get(f"/chain/revocation/{index}")
        if data:
            return data['data']['is_revoked']
        return True # 如果连不上服务器，默认视为不安全

    @staticmethod
    def get_issuer_pk():
        data = TrustAnchorClient._safe_get(f"/issuer/info")
        if data:
            return data['data']['pk']
        return None

    @staticmethod
    def report_misbehavior(did: str, reason: str, rev_idx: int = None):
        try:
            payload = {"did": did, "reason": reason}
            if rev_idx is not None: payload["revocation_idx"] = rev_idx
            requests.post(f"{IDENTITY_HOST}/system/report_anomaly", json=payload, timeout=1)
            logger.warning(f"已上报恶意行为 -> {did} ({reason})")
        except Exception as e:
            logger.error(f"上报失败 (Identity Server 可能离线): {e}")

# ==========================================
# 验证核心逻辑
# ==========================================
class Gatekeeper:
    def __init__(self):
        self.nonce_cache = {}

    def generate_challenge(self) -> str:
        nonce = uuid.uuid4().hex
        self.nonce_cache[nonce] = time.time()
        # 清理过期 nonce
        now = time.time()
        self.nonce_cache = {k:v for k,v in self.nonce_cache.items() if now - v < 60}
        return nonce

    def verify_access_request(self, vp_data: dict) -> tuple[bool, str, dict]:
        # 1. 基础结构校验
        vc = vp_data.get('verifiableCredential')
        holder_doc = vp_data.get('holder_doc')
        proof = vp_data.get('proof')

        if not all([vc, holder_doc, proof]):
            return False, "请求数据结构不完整", {}

        holder_did = holder_doc.get('id')
        rev_idx = vc.get('payload', {}).get('revocation_idx')

        # 2. 身份中心查验 (Anchor & Blacklist)
        chain_hash, status = TrustAnchorClient.get_anchor_info(holder_did)
        if chain_hash is None:
            return False, "用户未注册或身份中心不可用", {}
        
        # [检查黑名单]
        if status == 'banned':
            logger.warning(f"拦截黑名单用户访问: {holder_did}")
            return False, "您的身份已被全局封禁 (Blacklisted)，禁止访问", {}

        # 3. 文档完整性校验
        try:
            local_hash = DIDCore.sm3_hash(DIDCore.canonicalize(holder_doc))
        except Exception:
            return False, "DID 文档格式错误", {}

        if local_hash != chain_hash:
            TrustAnchorClient.report_misbehavior(holder_did, "Doc Tampered", rev_idx)
            return False, "DID 文档哈希校验失败 (检测到篡改，已上报)", {}

        # 4. VC 有效性校验
        issuer_pk = TrustAnchorClient.get_issuer_pk()
        if not issuer_pk:
            return False, "无法获取 Issuer 公钥，服务暂停", {}

        if not DIDCore.verify(issuer_pk, vc['payload'], vc['proof']['sig']):
            TrustAnchorClient.report_misbehavior(holder_did, "Fake VC Signature", rev_idx)
            return False, "凭证签名无效 (伪造凭证，已上报)", {}
        
        if TrustAnchorClient.check_revocation(rev_idx):
            return False, "凭证已被撤销或过期", {}

        # 5. VP 持有权校验 (Challenge-Response)
        nonce = proof.get('challenge')
        if nonce not in self.nonce_cache:
            return False, "Challenge Nonce 无效或已过期", {}
        del self.nonce_cache[nonce] # 防重放

        holder_pk = holder_doc.get('pk')
        sign_target = {"vc": vc, "nonce": nonce}
        
        if not DIDCore.verify(holder_pk, sign_target, proof.get('sig')):
            TrustAnchorClient.report_misbehavior(holder_did, "Invalid VP Signature", rev_idx)
            return False, "持有者签名校验失败 (非本人操作，已上报)", {}

        return True, "验证通过", vc['payload']['claims']

gatekeeper = Gatekeeper()

# ==========================================
# 接口定义
# ==========================================
def api_resp(success=True, msg="Success", data=None):
    return jsonify({"success": success, "message": msg, "data": data})

@app.route('/service/challenge', methods=['GET'])
def challenge_api():
    return jsonify({"success": True, "data": {"nonce": gatekeeper.generate_challenge()}})

@app.route('/service/access', methods=['POST'])
def access_api():
    if not request.json:
        return api_resp(False, "Missing JSON Body")
        
    logger.info(">>> 收到访问请求，开始验证...")
    is_valid, msg, claims = gatekeeper.verify_access_request(request.json)
    
    if is_valid:
        logger.info(f"\033[92m[Access Granted] 用户: {claims.get('owner', 'Unknown')}\033[0m")
        return api_resp(True, "门禁已开启", claims)
    else:
        logger.error(f"\033[91m[Access Denied] 原因: {msg}\033[0m")
        return api_resp(False, msg)

if __name__ == '__main__':
    print("\n" + "="*60)
    print("   Service Server Running on Port 5001")
    print("   [功能] 验证控制 | 异常上报 | 远程身份查验")
    print("="*60 + "\n")
    app.run(port=5001, debug=False)