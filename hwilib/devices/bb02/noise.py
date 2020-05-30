from bitbox02 import util
from typing import Callable

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
