import bitbox02
from communication import u2fhid, devices, HARDENED
from ..hwwclient import HardwareWalletClient
from ..errors import ActionCanceledError, BadArgumentError, DeviceConnectionError, DeviceFailureError, UnavailableActionError, common_err_msgs, handle_errors

import base64
import hid
import struct
from .. import base58
from ..base58 import get_xpub_fingerprint_hex
from ..serializations import hash256, hash160, CTransaction
import logging
import re


BITBOX02_VENDOR_ID = 0x03eb
BITBOX02_DEVICE_ID = 0x2403
BIP32_PRIME = 0x80000000
UINT32_MAX = (1 << 32) - 1


def check_keypath(key_path):
    if key_path == "m/44'/0'/0'":
        raise Exception("The path m/44' is not supported")
    parts = re.split("/", key_path)
    if parts[0] != "m":
        return False
    if parts[1] != "49'" and parts[1] != "84'":
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


class Bitbox02Client(HardwareWalletClient):

    def __init__(self, path, password=''):
        super(Bitbox02Client, self).__init__(path, password)
        hid_device = hid.device()
        hid_device.open_path(path.encode())
        hid_device.set_nonblocking(True)

        bitboxes = devices.get_any_bitbox02s()
        bitbox_hid = {}
        for bitbox in bitboxes:
            if bitbox["path"] == path.encode():
                bitbox_hid = bitbox

        def show_pairing(code: str) -> bool:
            msg = "Please compare and confirm the pairing code on your BitBox02:" + "\n"
            print(msg + code)
            return True

        def attestation_check(result: bool) -> None:
            if result:
                print("Device attestation PASSED")
            else:
                print("Device attestation FAILED")
                print(bitbox_hid)

        self.app = bitbox02.BitBox02(
            transport=u2fhid.U2FHid(hid_device),
            device_info=bitbox_hid,
            show_pairing_callback=show_pairing,
            attestation_check_callback=attestation_check,
        )

    # Must return a dict with the xpub
    # Retrieves the public key at the specified BIP 32 derivation path
    def get_pubkey_at_path(self, path):
        print(path)
        if path == "m/44'/0'/0'":
            path = "m/49'/0'/0'"
        if not check_keypath(path):
            raise Exception("Invalid keypath")
        keypath = convert_bip32_path_to_list_of_uint32(path)
        coin_network = coin_network_from_bip32_list(keypath)

        print(path)
        xpub = self.app.btc_pub(
            keypath=keypath,
            output_type=bitbox02.btc.BTCPubRequest.XPUB,
            coin=coin_network,
            display=False,
        )
        print(xpub)
        xpub = self.app.btc_pub(
            keypath=keypath,
            output_type=bitbox02.btc.BTCPubRequest.XPUB,
            coin=coin_network,
        )
        return {'xpub': xpub}

    # Must return a hex string with the signed transaction
    # The tx must be in the combined unsigned transaction format
    # Current only supports segwit signing
    def sign_tx(self, tx):
        return "lol"

    def sign_message(self, message, keypath):
        return "lol"

    def display_address(self, keypath, p2sh_p2wpkh, bech32):
        return "lol"

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
        raise UnavailableActionError('The BitBox02 does not support wiping via software')

    # Restore device from mnemonic or xprv
    def restore_device(self, label=''):
        raise UnavailableActionError('The BitBox02 does not support restoring via software')

    # Begin backup process
    def backup_device(self, label='', passphrase=''):
        raise UnavailableActionError('The BitBox02 does not support creating a backup via software')

        # Prompt pin
    def prompt_pin(self):
        raise UnavailableActionError('The BitBox02 does not need a PIN sent from the host')

    # Send pin
    def send_pin(self, pin):
        raise UnavailableActionError('The BitBox02 does not need a PIN sent from the host')

def enumerate(password=''):
    results = []
    for d in devices.get_any_bitbox02s():
        if ('interface_number' in d and d['interface_number'] == 0
                or ('usage_page' in d and d['usage_page'] == 0xffa0)):
            d_data = {}

            path = d['path'].decode()
            print("This is the path", path)
            d_data['type'] = 'BitBox02'
            d_data['model'] = 'BitBox02-BTC' #if device_id == 0x0004 else 'ledger_nano_s'
            d_data['path'] = path

            client = None
            with handle_errors(common_err_msgs["enumerate"], d_data):
                client = Bitbox02Client(d['path'].decode(), password)
                d_data['fingerprint'] = client.request_root_fingerprint_from_device()
                master_xpub = "LOL"
                d_data['needs_pin_sent'] = False
                d_data['needs_passphrase_sent'] = False

            if client:
                client.close()

            results.append(d_data)
    return results
