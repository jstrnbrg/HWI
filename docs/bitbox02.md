# BitBox02

The BitBox02 is supported by HWI

Current implemented commands are:

- `displayaddress`
- `getxpub` (with some caveats)
- `togglepassphrase` (with some caveats)
- `getmasterxpub`  (with some caveats)
- `signtx`  (TODO)


## Usage Notes

## `togglepassphrase` Caveats
Calling `togglepassphrase` enables passphrase support on the BitBox02. To input enter a passphrase, the BitBox02 needs to be unplugged and replugged.

## `getxpub` Caveats
- Which levels need to be hardened?
- The BitBox02 only supports BIP 84 p2wpkh and BIP 49 p2wpkh_p2sh

## `getmasterxpub` Caveats
By default HWI tries to get the master_xpub via the m/44'/0'/0' derivation path. As that path isn't supported by the BitBox02, calling `getmasterxpub` will instead return the extended public key via the  m/49'/0'/0' derivation path.

## Note on `setup` & `restore`
The BitBox02 needs to be set up and restored via the BitBoxApp.
