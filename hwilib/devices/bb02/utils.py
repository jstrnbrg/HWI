import re
from bitbox02 import bitbox02
from bitbox02.communication import HARDENED

BIP32_PRIME = 0x80000000
UINT32_MAX = (1 << 32) - 1

def check_keypath(key_path):
    if key_path == "m/44'/0'/0'":
        raise Exception("The path m/44' is not supported")
    parts = re.split("/", key_path)
    if parts[0] != "m":
        return False
    if parts[1] != "49'" and parts[1] != "49h" and parts[1] != "84'" and parts[1] != "84h" and parts[1] != "48'" and parts[1] != "49h":
        return False
    # strip hardening chars
    for index in parts[1:]:
        index_int = re.sub('[hH\']', '', index)
        if not index_int.isdigit():
            return False
        if int(index_int) > 0x80000000:
            return False
    return True

def convert_bip32_path_to_list_of_uint32(n):
    """Convert bip32 path to list of uint32 integers with prime flags
    m/0/-1/1' -> [0, 0x80000001, 0x80000001]

    based on code in trezorlib
    """
    if not n:
        return []
    if n.endswith("/"):
        n = n[:-1]
    n = n.split('/')
    # cut leading "m" if present, but do not require it
    if n[0] == "m":
        n = n[1:]
    path = []
    for x in n:
        if x == '':
            # gracefully allow repeating "/" chars in path.
            # makes concatenating paths easier
            continue
        prime = 0
        if x.endswith("'") or x.endswith("h"):
            x = x[:-1]
            prime = BIP32_PRIME
        if x.startswith('-'):
            if prime:
                raise ValueError(f"bip32 path child index is signalling hardened level in multiple ways")
            prime = BIP32_PRIME
        child_index = abs(int(x)) | prime
        if child_index > UINT32_MAX:
            raise ValueError(f"bip32 path child index too large: {child_index} > {UINT32_MAX}")
        path.append(child_index)
    return path

def coin_network_from_bip32_list(keypath):
        if len(keypath) > 2:
            if keypath[1] == 1 + HARDENED:
                return bitbox02.btc.TBTC
        return bitbox02.btc.BTC

def get_xpub_type(self, path):
    script_type = path.split("/")[1]
    if self.is_testnet:
        return bitbox02.btc.BTCPubRequest.TPUB
    elif "49" in script_type:
        return bitbox02.btc.BTCPubRequest.YPUB
    elif "84" in script_type:
        return bitbox02.btc.BTCPubRequest.ZPUB
    else:
        return bitbox02.btc.BTCPubRequest.XPUB
