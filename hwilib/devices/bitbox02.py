from bitbox02.communication import u2fhid, devices, HARDENED, bitbox_api_protocol
from bitbox02 import bitbox02, util
from ..hwwclient import HardwareWalletClient
from ..errors import ActionCanceledError, BadArgumentError, DeviceConnectionError, DeviceFailureError, UnavailableActionError, common_err_msgs, handle_errors

import base64
from binascii import hexlify, unhexlify
import hid
import struct
from .. import base58
from ..base58 import get_xpub_fingerprint_hex
from ..serializations import hash256, hash160, CTransaction, CTxOut, ser_uint256, ExtendedKey
import logging
import re
from typing import Callable, List


BITBOX02_VENDOR_ID = 0x03eb
BITBOX02_DEVICE_ID = 0x2403
BIP32_PRIME = 0x80000000
UINT32_MAX = (1 << 32) - 1

py_enumerate = enumerate # Need to use the enumerate built-in but there's another function already named that

class NoiseConfig(util.NoiseConfigUserCache):
    """NoiseConfig extends BitBoxNoiseConfig"""

    def show_pairing(self, code: str, device_response: Callable[[], bool]) -> bool:
        msg = "Please compare and confirm the pairing code on your BitBox02:" + "\n"
        print(msg + code)
        if not device_response():
                return False
        return True

    def attestation_check(self, result: bool) -> None:
        if result:
            print("Device attestation PASSED")
        else:
            print("Device attestation FAILED")

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

class Bitbox02Client(HardwareWalletClient):

    def __init__(self, path, password='', expert=False):
        super(Bitbox02Client, self).__init__(path, password, expert)

        APP_ID = "HWI"
        hid_device = hid.device()
        hid_device.open_path(path.encode())
        hid_device.set_nonblocking(True)

        bitboxes = devices.get_any_bitbox02s()
        bitbox_hid = {}
        for bitbox in bitboxes:
            if bitbox["path"] == path.encode():
                bitbox_hid = bitbox

        self.app = bitbox02.BitBox02(
            transport=u2fhid.U2FHid(hid_device),
            device_info=bitbox_hid,
            noise_config=NoiseConfig(APP_ID),
        )

    def get_master_fingerprint(self):
        return self.app.root_fingerprint().hex()

    # Must return a dict with the xpub
    # Retrieves the public key at the specified BIP 32 derivation path
    def get_pubkey_at_path(self, path):
        # QUESTION: As BB02 does not support m/44'/0'/0' which is used by `getmasterxpub` should it convert to m/44'/0'/0' or return error ?
        # path = "m/49'/0'/0'" if path == "m/44'/0'/0'" else path
        if not check_keypath(path):
            raise Exception("The entered keypath is invalid. Note: The BitBox02 only supports BIP 84 p2wpkh and BIP 49 p2wpkh_p2sh.")
        keypath = convert_bip32_path_to_list_of_uint32(path)
        coin_network = coin_network_from_bip32_list(keypath)
        xpub_type = get_xpub_type(self, path)
        xpub = self.app.btc_xpub(
            keypath=keypath,
            xpub_type=xpub_type,
            coin=coin_network,
            display=True,
        )
        result = {'xpub': xpub}
        if self.expert:
            xpub_obj = ExtendedKey()
            xpub_obj.deserialize(xpub)
            result.update(xpub_obj.get_printable_dict())
        return result

    # Must return a hex string with the signed transaction
    # The tx must be in the combined unsigned transaction format
    # Current only supports segwit signing
    def sign_tx(self, tx):
        coin = bitbox02.btc.BTC
        if self.is_testnet:
            coin = bitbox02.btc.TBTC

        tx_script_type = None
        master_fp = self.get_master_fingerprint()
        master_fp = struct.unpack("<I", unhexlify(master_fp.encode()))[0]

        # Build BTCInputType list
        inputs = []
        for input_num, (psbt_in, txin) in py_enumerate(list(zip(tx.inputs, tx.tx.vin))):

            for key in psbt_in.hd_keypaths.keys():
                full_path = list(psbt_in.hd_keypaths[key])
                if full_path[0] == master_fp:
                    key_path = full_path[1:]
                    break

            prevout_hash = ser_uint256(txin.prevout.hash)[::-1]
            inputs.append(
                {
                    "prev_out_hash": prevout_hash,
                    "prev_out_index": txin.prevout.n,
                    "prev_out_value": psbt_in.witness_utxo.nValue,
                    "sequence": txin.nSequence,
                    "keypath": key_path,
                }
            )

        # Build BTCOutputType list
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

        print(outputs, inputs)
        sigs = self.app.btc_sign(
            coin,
            bitbox02.btc.BTCScriptConfig(
                simple_type=bitbox02.btc.BTCScriptConfig.P2WPKH  # pylint: disable=no-member
            ),
            keypath_account=key_path[:3],
            inputs=inputs,
            outputs=outputs,
            locktime=tx.tx.nLockTime,
            version=tx.tx.nVersion,
        )

        # Fill signatures
        if len(sigs) != len(tx.inputs()):
            raise Exception("Incorrect number of inputs signed.")  # Should never occur
        signatures = [
            bh2u(ecc.der_sig_from_sig_string(x[1], ecc.CURVE_ORDER)) + "01"
            for x in sigs
        ]
        tx.update_signatures(signatures)

        return "lol"

    def sign_message(self, message, keypath):
        raise UnailableActionError('The BitBox02 does not support message signing')

    # def btc_multisig_config(
    #     self, coin: bitbox02.btc.BTCCoin, bip32_path: List[int], wallet: Multisig_Wallet
    # ) -> bitbox02.btc.BTCScriptConfig:
    #     """
    #     Get a mock multisig 1-of-2 multisig with the current device and some other arbitrary xpub.
    #     Registers it on the device if not already registered.
    #     """
    #     account_keypath = bip32_path[:4]
    #     xpubs = wallet.get_master_public_keys()
    #     our_xpub = self.get_xpub(
    #         bip32.convert_bip32_intpath_to_strpath(account_keypath), "p2wsh"
    #     )
    #
    #     multisig_config = bitbox02.btc.BTCScriptConfig(
    #         multisig=bitbox02.btc.BTCScriptConfig.Multisig(
    #             threshold=wallet.m,
    #             xpubs=[util.parse_xpub(xpub) for xpub in xpubs],
    #             our_xpub_index=xpubs.index(our_xpub),
    #         )
    #     )
    #
    #     is_registered = self.app.btc_is_script_config_registered(
    #         coin, multisig_config, account_keypath
    #     )
    #     if not is_registered:
    #         self.app.btc_register_script_config(
    #             coin=coin,
    #             script_config=multisig_config,
    #             keypath=account_keypath,
    #             name=name,
    #         )
    #     return multisig_config


    # Display address of specified type on the device. Only supports single-key based addresses.
    def display_address(self, keypath, p2sh_p2wpkh, bech32):
        if not check_keypath(keypath):
            raise Exception("Invalid keypath")
        address_keypath = convert_bip32_path_to_list_of_uint32(keypath)
        coin_network = coin_network_from_bip32_list(address_keypath)
        if bech32 and address_keypath[0] == 84 + HARDENED:
            script_config = bitbox02.btc.BTCScriptConfig(
                simple_type=bitbox02.btc.BTCScriptConfig.P2WPKH
            )
        elif p2sh_p2wpkh and address_keypath[0] == 49 + HARDENED:
            script_config = bitbox02.btc.BTCScriptConfig(
                simple_type=bitbox02.btc.BTCScriptConfig.P2WPKH_P2SH
            )
        else:
            raise Exception("invalid keypath or address_type, only supports BIP 84 p2wpkh bech32 addresses and BIP 49 p2wpkh_p2sh sript hash addresses")

        address = self.app.btc_address(
            keypath=address_keypath,
            coin=coin_network,
            script_config=script_config,
            display=True,
        )
        return {'address': address}

    # Get root fingerprint of device
    def request_root_fingerprint_from_device(self):
        return self.app.root_fingerprint().hex()

    # Close the device
    def close(self):
        self.app.close()

    # Setup a new device
    def setup_device(self, label='', passphrase=''):
        raise UnavailableActionError('The BitBox02 does not support software setup')

    # Wipe this device
    def wipe_device(self):
        raise UnavailableActionError('The BitBox02 does not support wiping via software yet')

    # Restore device from mnemonic or xprv
    def restore_device(self, label=''):
        raise UnavailableActionError('The BitBox02 does not support restoring via software yet')

    # Begin backup process
    def backup_device(self, label='', passphrase=''):
        raise UnavailableActionError('The BitBox02 does not supporrt creating a backup from software yet')

        # Prompt pin
    def prompt_pin(self):
        raise UnavailableActionError('The BitBox02 does not need a PIN sent from the host')

    # Send pin
    def send_pin(self, pin):
        raise UnavailableActionError('The BitBox02 does not need a PIN sent from the host')

    # Toggle passhrase
    def toggle_passphrase(self):
        device_info = self.app.device_info()
        passphrase_status = device_info['mnemonic_passphrase_enabled']
        if passphrase_status:
            return self.app.disable_mnemonic_passphrase()
        else:
            return self.app.enable_mnemonic_passphrase()

def enumerate(password=''):
    results = []
    for d in devices.get_any_bitbox02s():
        # TODO:  why did seb use that if statement?
        # if ('interface_number' in d and d['interface_number'] == 0
        #         or ('usage_page' in d and d['usage_page'] == 0xffa0)):
        print(d)
        d_data = {}
        path = d['path'].decode()
        d_data['type'] = "BitBox02"
        d_data['model'] = d['product_string']
        d_data['path'] = path

        client = None
        with handle_errors(common_err_msgs["enumerate"], d_data):
            client = Bitbox02Client(d['path'].decode(), password)
            d_data['fingerprint'] = client.get_master_fingerprint()
            # master_xpub = "LOL"
            d_data['needs_pin_sent'] = False
            d_data['needs_passphrase_sent'] = False

        if client:
            client.close()

        results.append(d_data)
    return results
