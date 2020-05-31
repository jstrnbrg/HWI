import re
from bitbox02 import bitbox02
from bitbox02.communication import HARDENED
from ...serializations import ser_uint256

BIP32_PRIME = 0x80000000
UINT32_MAX = (1 << 32) - 1

py_enumerate = enumerate # Need to use the enumerate built-in but there's another function already named that

def check_keypath(key_path):
    parts = re.split("/", key_path)
    if key_path == "m/44'/0'/0'":
        return False
    if parts[0] != "m":
        return False
    if parts[1] not in ["49h", "84h"]:
        return False
    if not check_account(parts[2]):
        return False
    # strip hardening chars
    for index in parts[1:]:
        index_int = re.sub('[hH\']', '', index)
        if not index_int.isdigit():
            return False
        # not sure why this check is needed
        if int(index_int) > 0x80000000:
            return False
    return True

def check_account(account):
    if "h" not in account:
        return False
    else:
        if int(account.strip("h")) not in range(0,100):
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

def create_inputs(tx, master_fp):
    inputs: List[bitbox02.BTCInputType] = []
    for input_num, (psbt_in, txin) in py_enumerate(list(zip(tx.inputs, tx.tx.vin))):
        for key in psbt_in.hd_keypaths.keys():
            full_path = list(psbt_in.hd_keypaths[key])
            full_path[0] = HARDENED + 5 # my test psbt has a really weird account index (1421706179), BitBox requires account index to be between 0-99 + HARDENED
            break

        prevout_hash = ser_uint256(txin.prevout.hash)[::-1]
        inputs.append(
            {
                "prev_out_hash": prevout_hash,
                "prev_out_index": txin.prevout.n,
                "prev_out_value": psbt_in.witness_utxo.nValue,
                "sequence": txin.nSequence,
                "keypath": [84 + HARDENED, 0 + HARDENED] + full_path
            }
        )
        return inputs

def create_outputs(tx, master_fp):
    outputs = []
    for i, txout in py_enumerate(tx.tx.vout):
        change_path = []
        is_change = False

        # check for change
        for pubkey, path in tx.outputs[i].hd_keypaths.items():
            if path[0] == master_fp and len(path) > 2 and path[-2] == 1:
                # For possible matches, check if pubkey matches possible template
                if hash160(pubkey) in txout.scriptPubKey or hash160(bytearray.fromhex("0014") + hash160(pubkey)) in txout.scriptPubKey:
                    change_path = list(path[1:])
                    is_change = True
                    break

        if is_change:
            print("Internatl output change path" ,change_path)
            outputs.append(
                bitbox02.BTCOutputInternal(
                    keypath=change_path,
                    value=txout.nValue,
                    )
            )
        else:
            if txout.is_p2pkh():
                output_hash = txout.scriptPubKey
                output_type = bitbox02.btc.P2PKH
            elif txout.is_p2sh():
                output_hash = txout.scriptPubKey
                output_type = bitbox02.btc.P2SH
            else:
                _, _, output_hash = txout.is_witness()
                if len(output_hash) == 20:
                    output_type = bitbox02.btc.P2WPKH
                elif len(output_hash) == 32:
                    output_type = bitbox02.btc.P2WSH
                else:
                    raise BadArgumentError("No good witness program found")
            if output_hash == None:
                raise BadArgumentError("Output is not an address")

            outputs.append(
                bitbox02.BTCOutputExternal(
                    output_type=output_type,
                    output_hash=output_hash,
                    value=txout.nValue,
                )
            )
    return outputs

# def get_account(tx):
#     key_paths = []
#     for input_num, (psbt_in, txin) in py_enumerate(list(zip(tx.inputs, tx.tx.vin))):
#         for key in psbt_in.hd_keypaths.keys():
#             full_path = list(psbt_in.hd_keypaths[key])
#             return full_path[0] + HARDENED
