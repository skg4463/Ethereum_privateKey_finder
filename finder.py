from web3 import Web3
from Crypto.Hash import keccak
import ecdsa
import time
import keyboard  # Using keyboard to detect key press to stop the program

w3 = Web3(Web3.HTTPProvider('https://mainnet.infura.io/v3/cc3faa47b8dc4c26ae1ad24898dc47ba'))


def keccak256(data):
    k_hash = keccak.new(digest_bits=256)
    k_hash.update(data)
    return k_hash.hexdigest()


def generate_ethereum_address():0xED44e4F02904a28a7A28E05dF78BeE02626435D1
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
    count = 0
    while True:
        count += 1
        private_key_hex, address = generate_ethereum_address()
        balance = check_balance(address)

        if balance > 0:
            print(
                f"Found an address with a balance! Address : {address}, Balance: {balance}, Private Key: {private_key_hex}")

        if count % 10 == 0:
            timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
            print(f"{count} addresses checked at {timestamp}")

        # Stop if 'esc' key is pressed
        # if keyboard.is_pressed(''):
        #     timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        #     print(f"Stopping at {timestamp}, after checking {count} addresses.")
        #     break

        time.sleep(0.01)  # Small delay to not overwhelm the CPU
except KeyboardInterrupt:
    # Handle any manual interruption (Ctrl+C)
    print("\nProgram has been stopped manually.")
