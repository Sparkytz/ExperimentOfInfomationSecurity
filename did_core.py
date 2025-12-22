# did_core.py
import json
import base64
import binascii
import os
import re
import logging
from typing import Tuple, Dict, Any, Union
try:
    from gmssl import sm2, sm3, func
except ImportError:
    raise ImportError("请先安装 gmssl 库: pip install gmssl")

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("DIDCore")

# =========================================================================
#  自定义异常类
# =========================================================================
class DIDError(Exception):
    """DID 相关操作的基础异常类"""
    pass

class CryptoError(DIDError):
    """加密/解密/签名过程中的异常"""
    pass

class ValidationError(DIDError):
    """数据格式验证异常"""
    pass

# =========================================================================
#  SM2 数学核心层
#  (基于国密标准 GM/T 0003.5-2012 实现椭圆曲线运算)
# =========================================================================
class SM2Math:
    """
    SM2 椭圆曲线数学工具类。
    用于弥补 gmssl 纯 Python 库无法从私钥直接导出公钥的不足。
    引用源: did_core.py
    """
    # 椭圆曲线参数定义
    _p = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
    _a = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
    _b = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
    _n = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
    _Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
    _Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0

    @classmethod
    def _inv(cls, a: int, n: int) -> int:
        """求模逆元 (Fermat's Little Theorem or Extended Euclidean)"""
        return pow(a, n - 2, n)

    @classmethod
    def _add(cls, P1: Tuple[int, int], P2: Tuple[int, int]) -> Union[Tuple[int, int], None]:
        """椭圆曲线点加法 P1 + P2"""
        if P1 is None: return P2
        if P2 is None: return P1
        x1, y1 = P1
        x2, y2 = P2
        if x1 == x2 and y1 != y2: return None
        
        if P1 == P2:
            # 点倍积公式 (Doubling)
            lam = (3 * x1 * x1 + cls._a) * cls._inv(2 * y1, cls._p)
        else:
            # 普通加法公式 (Addition)
            lam = (y2 - y1) * cls._inv(x2 - x1, cls._p)
        
        lam %= cls._p
        x3 = (lam * lam - x1 - x2) % cls._p
        y3 = (lam * (x1 - x3) - y1) % cls._p
        return (x3, y3)

    @classmethod
    def _scalar_mult(cls, k: int, P: Tuple[int, int]) -> Union[Tuple[int, int], None]:
        """椭圆曲线标量乘法: Q = k * P (使用 Double-and-Add 算法)"""
        Q = None
        for i in range(255, -1, -1):
            Q = cls._add(Q, Q) # Double
            if (k >> i) & 1:
                Q = cls._add(Q, P) # Add
        return Q

    @classmethod
    def derive_public_key(cls, private_key_hex: str) -> str:
        """
        从 32字节私钥推导 64字节公钥 (未压缩格式)。
        
        Args:
            private_key_hex (str): 16进制字符串格式的私钥
            
        Returns:
            str: 16进制字符串格式的公钥 ('04' + X + Y)
            
        Raises:
            CryptoError: 当私钥无效导致无法计算公钥时抛出
        """
        try:
            k = int(private_key_hex, 16)
            # 计算 P = k * G
            P = cls._scalar_mult(k, (cls._Gx, cls._Gy))
            if P is None:
                raise ValueError("Point at infinity generated")
            
            # 格式化为 64 字节 Hex (32字节X + 32字节Y)
            x_hex = '{:064x}'.format(P[0])
            y_hex = '{:064x}'.format(P[1])
            
            # SM2 标准公钥通常以 '04' 开头表示未压缩
            return "04" + x_hex + y_hex
        except Exception as e:
            logger.error(f"公钥推导失败: {str(e)}")
            raise CryptoError("无效的私钥，无法推导公钥") from e

# =========================================================================
#  DID 核心协议层
# =========================================================================
class DIDCore:
    """
    分布式数字身份(DID)核心工具类。
    提供密钥生成、哈希计算、DID 标识符生成、Canonicalize 以及 SM2 签名验签功能。
    """

    DID_PREFIX = "did:lab:IoT"

    @staticmethod
    def generate_keys() -> Tuple[str, str]:
        """
        生成符合国密标准的 SM2 密钥对。
        
        Returns:
            Tuple[str, str]: (私钥Hex, 公钥Hex)
        """
        try:
            # 1. 使用 os.urandom 生成密码学安全的随机数 (32字节/256位)
            priv_bytes = os.urandom(32)
            priv_hex = binascii.hexlify(priv_bytes).decode('utf-8')
            
            # 2. 使用数学库从私钥推导公钥
            pub_hex = SM2Math.derive_public_key(priv_hex)
            
            logger.debug("SM2 密钥对生成成功")
            return priv_hex, pub_hex
        except Exception as e:
            logger.critical(f"密钥生成严重错误: {str(e)}")
            raise CryptoError("密钥生成失败")

    @staticmethod
    def sm3_hash(data_input: Union[str, bytes]) -> str:
        """
        计算数据的 SM3 摘要值。
        
        Args:
            data_input: 输入字符串或字节流
            
        Returns:
            str: 16进制格式的哈希值
        """
        if isinstance(data_input, str):
            data_bytes = data_input.encode('utf-8')
        else:
            data_bytes = data_input
        
        # gmssl 库接收 list[int] 作为输入
        return sm3.sm3_hash(func.bytes_to_list(data_bytes))

    @staticmethod
    def generate_did(pub_hex: str) -> str:
        """
        生成 DID 标识符。
        格式: did:lab:IoT:<Base64URL-SM3-Hash>
        
        Args:
            pub_hex (str): 公钥 Hex 字符串
            
        Returns:
            str: 生成的 DID 字符串
        """
        # 1. 计算公钥的 SM3 哈希
        hash_hex = DIDCore.sm3_hash(pub_hex)
        hash_bytes = binascii.unhexlify(hash_hex)
        
        # 2. Base64 URL-Safe 编码 (替换 +/ 为 -_, 去掉换行)
        b64_bytes = base64.urlsafe_b64encode(hash_bytes)
        did_suffix = b64_bytes.decode('utf-8').rstrip('=')
        
        # 3. 截取前 16 位作为短 ID，确保紧凑
        did = f"{DIDCore.DID_PREFIX}:{did_suffix[:16]}"
        return did

    @staticmethod
    def validate_did_format(did: str) -> bool:
        """
        验证 DID 格式是否合法。
        """
        pattern = re.compile(rf"^{DIDCore.DID_PREFIX}:[a-zA-Z0-9_-]+$")
        return bool(pattern.match(did))

    @staticmethod
    def canonicalize(data: Dict[str, Any]) -> str:
        """
        JSON 规范化 (Canonicalization)。
        确保 JSON 对象序列化后的字符串唯一，保证签名哈希一致性。
        规则: 按键名字母顺序排序，去除空格。
        """
        return json.dumps(data, sort_keys=True, separators=(',', ':'))

    @staticmethod
    def sign(priv_hex: str, data_dict: Dict[str, Any]) -> str:
        """
        使用 SM2 私钥对数据字典进行签名。
        
        Args:
            priv_hex: 私钥 Hex
            data_dict: 待签名的字典数据
            
        Returns:
            str: 签名的 Hex 字符串
        """
        try:
            # 初始化 CryptSM2 对象
            sm2_crypt = sm2.CryptSM2(public_key="", private_key=priv_hex)
            
            # 规范化数据
            data_str = DIDCore.canonicalize(data_dict)
            data_bytes = data_str.encode('utf-8')
            
            # 生成随机数 k (SM2签名需要强随机数)
            random_hex_str = func.random_hex(32)
            
            # 执行签名
            signature = sm2_crypt.sign(data_bytes, random_hex_str)
            return signature
        except Exception as e:
            logger.error(f"签名失败: {str(e)}")
            raise CryptoError("SM2 签名操作失败")

    @staticmethod
    def verify(pub_hex: str, data_dict: Dict[str, Any], sig_hex: str) -> bool:
        """
        使用 SM2 公钥验证签名。
        
        Args:
            pub_hex: 公钥 Hex ('04'开头)
            data_dict: 原始数据字典
            sig_hex: 签名 Hex
            
        Returns:
            bool: 验证通过返回 True，否则 False
        """
        try:
            # 初始化 CryptSM2 对象，传入公钥
            sm2_crypt = sm2.CryptSM2(public_key=pub_hex, private_key="")
            
            data_str = DIDCore.canonicalize(data_dict)
            data_bytes = data_str.encode('utf-8')
            
            return sm2_crypt.verify(sig_hex, data_bytes)
        except Exception as e:
            logger.warning(f"验签过程发生异常: {str(e)}")
            return False
# =========================================================================
#  简单测试代码
# =========================================================================
if __name__ == "__main__":
    print("Testing Real SM2 Key Generation...")
    
    # 1. 生成密钥
    sk, pk = DIDCore.generate_keys()
    print(f"Private Key ({len(sk)} chars): {sk}")
    print(f"Public Key  ({len(pk)} chars): {pk}")
    
    # 2. 生成 DID
    did = DIDCore.generate_did(pk)
    print(f"DID: {did}")
    
    # 3. 签名与验签测试
    msg = {"hello": "world", "timestamp": 12345}
    sig = DIDCore.sign(sk, msg)
    print(f"Signature: {sig}")
    
    is_valid = DIDCore.verify(pk, msg, sig)
    print(f"Verification Result: {is_valid}")