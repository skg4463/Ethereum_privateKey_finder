# ed4c8673284446f4a4c24137e4b60a74
from web3 import Web3
from Crypto.Hash import keccak
import ecdsa
import time
import winsound

w3 = Web3(Web3.HTTPProvider('https://mainnet.infura.io/v3/ed4c8673284446f4a4c24137e4b60a74'))


def keccak256(data):
    k_hash = keccak.new(digest_bits=256)
    k_hash.update(data)
    return k_hash.hexdigest()


def generate_ethereum_address():
    private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    private_key_hex = private_key.to_string().hex()

    public_key = private_key.get_verifying_key().to_string()
    public_key_hex = "04" + public_key.hex()

    # Get the keccak-256 hash of the public key
    hashed_public_key = keccak256(bytes.fromhex(public_key_hex))

    # Take the last 20 bytes of this hash
    address = "0x" + hashed_public_key[-40:]
    return private_key_hex, address


def check_balance(address):
    checksum_address = Web3.to_checksum_address(address)
    balance = w3.eth.get_balance(checksum_address)
    return balance / (10**18)


# The main loop
try:
    winsound.Beep(frequency=400, duration=1000)
    print('start')
    count = 0

    private_key_hex, address = generate_ethereum_address()
    balance = check_balance(address)
    print(
        f"First Checking Address : {address}, Balance: {balance}, Private Key: {private_key_hex}")

    while True:
        count += 1
        private_key_hex, address = generate_ethereum_address()
        balance = check_balance(address)

        if balance > 0:
            print(
                f"Found an address with a balance! Address : {address}, Balance: {balance}, Private Key: {private_key_hex}")
            winsound.Beep(frequency=400,duration=1000)

        if count % 100 == 0:
            timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
            print(f"{count} addresses checked at {timestamp}")

        time.sleep(0.01)  # Small delay to not overwhelm the CPU
except KeyboardInterrupt:
    # Handle any manual interruption (Ctrl+C)
    print("\nProgram has been stopped manually.")
