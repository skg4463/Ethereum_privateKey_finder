from eth_keys import keys
from eth_utils import to_checksum_address
import ecdsa
from web3 import Web3
import time

# Web3 프로바이더 설정
w3 = Web3(Web3.HTTPProvider('https://mainnet.infura.io/v3/ed4c8673284446f4a4c24137e4b60a74'))


def generate_ethereum_address():
    # ECDSA SECP256k1 커브를 사용하여 개인키 생성
    private_key_bytes = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1).to_string()
    private_key = keys.PrivateKey(private_key_bytes)

    # 공개키를 얻음
    public_key = private_key.public_key
    address = public_key.to_checksum_address()

    return private_key.to_hex(), address


def check_balance(address):
    # 주어진 이더리움 주소의 잔액 확인
    balance = w3.eth.get_balance(address)
    return Web3.from_wei(balance, 'ether')


def main():
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
                f"Found an address with a balance! Address: {address}, Balance: {balance} ETH, Private Key: {private_key_hex}")

        if count % 100 == 0:
            print(f"{count} addresses checked so far...")

        time.sleep(0.01)  # 네트워크 요청 사이에 짧은 딜레이를 두어 API 제한을 피함


if __name__ == "__main__":
    main()
