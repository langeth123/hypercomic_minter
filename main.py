import requests 
import json
import time
import random
from loguru import logger
import hashlib
from cryptography.fernet import Fernet
import cryptography
import traceback
from platform import system
from os import getcwd
from threading import Thread
from eth_account import *
from web3 import Web3
from eth_account.signers.local import LocalAccount
from eth_abi.abi import encode

PLATFORM = system()


NFTS = {
    "0": "0x4041Db404315d7c63AAadc8D6E3b93c0bd99b779",
    "1": "0x976Af522E63fA603b9d48e9207831bffb5dd4829",
    "2": "0xD092E42453D6864ea98597461C50190e372d2448",
    "3": "0x3C2F9D813584dB751B5EA7829B280b8cD160DE7B",
    "4": "0x8F7b0e3407E55834F35e8c6656DaCcBF9f816964",
    "5": "0x5798C80608ede921E7028a740596b98aE0d8095A",
    "6": "0x9d405d767b5d2c3F6E2ffBFE07589c468d3fc04E",
    "7": "0x02E1eb4547A6869da1e416cfd5916C213655aA24",
    "8": "0x9f5417Dc26622A4804Aa4852dfBf75Db6f8c6F9F",
    "9": "0x761cCCE4a16A670Db9527b1A17eCa4216507946f"
}


def retry(
        infinity: bool = False, max_retries: int = 5,
        timing: float = 5,
        custom_message: str = "Random error:",
        catch_exception: bool = False,
        info_message: bool = False
):
    if infinity: max_retries = 9**1000
    def retry_decorator(func):
        def _wrapper(*args, **kwargs):
            for _ in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except Exception as error:
                    if "Aleady Minted!" in str(error): 
                        logger.info(f'{custom_message} Aleady Minted!')
                        return
                    if catch_exception:
                        print(traceback.format_exc())
                    
                    if info_message:
                        logger.info(f'{custom_message} {error}')
                    else: logger.error(f'{custom_message} | {error}')

                    time.sleep(timing)

        return _wrapper
    return retry_decorator

def make_request(
        method: str, 
        url: str, 
        custom_response: bool = True, 
        **kwargs
) -> dict or requests.Response:
    response = requests.request(
        method=method.upper(),
        url=url,
        **kwargs
    )
    if custom_response:
        return response.json()
    else:
        return response

if PLATFORM != "Darwin":
    import wmi

def get_correct_path(path: str) -> str:
    if PLATFORM == "Windows":
        return path.replace("/", "\\")
    elif PLATFORM == "Darwin":
        return path.replace("\\", "/")

def decrypt_files(password: str) -> dict:
    logger.info("Decrypting your secret keys.. ")

    key = hashlib.sha256(password.replace('"', '').encode()).hexdigest()[:43] + "="
    f = Fernet(key)
    try:
        path = get_correct_path(getcwd() + "/encoded_secrets.txt")
        with open(path, 'rb') as file:
            return json.loads(f.decrypt(file.read()).decode())
        
    except cryptography.fernet.InvalidToken:
        error = "Key to Decrypt files is incorrect!"
        logger.error(error)

    except Exception as error:
        error = traceback.format_exc()

    return error

@retry(custom_message="Failed to get runner wallets: ", infinity=True, timing=0.01)
def get_runner_wallets() -> list:
    addresses = [row.strip().lower() for row in open("addresses.txt").readlines() if len(row.strip()) == 42]
    all_secrets_data = decrypt_files(input("write ur password: ")) #input("write ur password: ")

    return [
        all_secrets_data[address] for address in all_secrets_data.keys() if address.lower() in addresses
    ]


def check_eligible(address: str, proxies: list, nonce: int, nft_number: int) -> str:
    proxy = random.choice(proxies)
    kwargs = {
        "proxies": {
            "http" : "http://" + proxy,
            "https": "http://" + proxy
        },
        "data": {
            'trancnt': str(nonce),
            'walletgbn': 'Metamask',
            'wallet': address.lower(),
            'nftNumber': str(nft_number),
        },
        "verify": False
    }
    response: str = make_request("post", "https://play.hypercomic.io/Claim/actionZK/conditionsCheck2", custom_response=False, **kwargs).text
    if "notEnough" in response: raise Exception(response)

    return response.replace("\n", "")

@retry(custom_message="Failed to mint nft: ")
def mint_nft(eth_account: LocalAccount, signature: str, number: int) -> bool:
    gas_price = w3.eth.gas_price * 1.1
    transaction = {
        "chainId" : 324, 
        "nonce"   : w3.eth.get_transaction_count(eth_account.address),  
        "from"    : eth_account.address, 
        "value"   : Web3.to_wei(0.00012, 'ether'),
        "gasPrice": int(gas_price),
        "to"      : NFTS[str(number)],
        "data"    : "0x7ba0e2e7" + encode(["bytes"], [bytes.fromhex(signature[2:])]).hex()
    }

    transaction["gas"] = w3.eth.estimate_gas(transaction)

    signed_txn = eth_account.sign_transaction(transaction)
    tx_token = Web3.to_hex(w3.eth.send_raw_transaction(signed_txn.rawTransaction))

    logger.success(f'[{eth_account.address}] minted nft with number: {number} | {tx_token}')


def check_and_mint_all(secret_key: str, proxies: list) -> None:
    eth_account = Account.from_key(secret_key)
    nft_numbers = [i for i in range(6, 10)]
    random.shuffle(nft_numbers)

    account_nonce = w3.eth.get_transaction_count(eth_account.address)
    
    for number in nft_numbers:
        try:
            signature = check_eligible(eth_account.address, proxies, account_nonce, number)
            mint_nft(eth_account, signature, number)
            time.sleep(random.uniform(settings["mint_nft_delay"][0], settings["mint_nft_delay"][1]))
        except:
            #print(traceback.format_exc())
            logger.error(f'[{eth_account.address}] cant mint nft with number: {number}')

def main():
    proxies = [row.strip() for row in open("proxies.txt").readlines()]
    secrets = get_runner_wallets()

    threads = []

    for secret in secrets:
        threads.append(
            Thread(target=check_and_mint_all, args=(secret, proxies, ))
        )

    for thread in threads:
        thread.start()
        time.sleep(random.uniform(settings["threads_run_timeout"][0], settings["threads_run_timeout"][1]))
    
    for thread in threads:
        thread.join()


if __name__ == "__main__":
    settings = json.load(open("settings.json"))
    w3 = Web3(Web3.HTTPProvider(settings["web3_provider"]))
    main()