import asyncio
import sqlite3
from json import load
from multiprocessing.dummy import Pool
from sys import stderr
from threading import Thread

import aiohttp
import aiohttp_proxy.errors
import aiosqlite
import web3.exceptions
from aiohttp_proxy import ProxyConnector
from loguru import logger
from pyrogram import Client
from pyrogram.enums import ParseMode
from pyuseragents import random as random_useragent
from web3 import Web3, HTTPProvider

logger.remove()
logger.add(stderr, format="<white>{time:HH:mm:ss}</white>"
                          " | <level>{level: <8}</level>"
                          " | <cyan>{line}</cyan>"
                          " - <white>{message}</white>")

headers = {
    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/'
              'webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
    'accept-language': 'ru,en;q=0.9,vi;q=0.8,es;q=0.7,cy;q=0.6',
    'cache-control': 'max-age=0'
}


async def send_telegram_message(tx_data) -> None:
    async with Client(name='telegram_session',
                      api_hash='b18441a1ff607e10a989891a5462e627',
                      api_id=2040,
                      bot_token=BOT_TOKEN) as telegram_session:
        await telegram_session.send_message(chat_id=OWNER_USER_ID,
                                            text=f'<b>New Transaction</b>\n<code>{tx_data}</code>',
                                            parse_mode=ParseMode.HTML)


def check_address_in_database(address: str) -> bool:
    with sqlite3.connect('addresses.db') as db:
        result_data = db.execute(f'SELECT * FROM `addresses` WHERE `address` = \'{address.lower()}\'').fetchall()

    if result_data:
        return True

    return False


def check_tx_data(current_transaction: str) -> None:
    transaction_data = w3.eth.getTransaction(transaction_hash=current_transaction)

    if check_address_in_database(address=transaction_data['from']):
        for current_method_data in tx_methods_data:
            if transaction_data['input'][:len(current_method_data['method_id'])] == current_method_data['method_id']:
                logger.success(f'{current_transaction} | Found method: {current_method_data["method_id"]}')
                asyncio.run(send_telegram_message(tx_data=current_transaction))
                return

    logger.error(f'{current_transaction} | Not Found')


class App:
    @staticmethod
    def get_last_block(last_block_id_old: int | None) -> int:
        while True:
            try:
                w3.eth.get_block(block_identifier=last_block_id_old + 1)

            except (web3.exceptions.BlockNotFound, web3.exceptions.BadResponseFormat):
                continue

            except Exception as error:
                logger.error(f'{last_block_id_old + 1} | Error When Check Block: {error}')

            else:
                return last_block_id_old + 1

    @staticmethod
    def get_block_transactions(block_id: int) -> list:
        while True:
            try:
                block_transactions = [current_transaction.hex() for current_transaction
                                      in w3.eth.get_block(block_id).transactions]

            except (web3.exceptions.BadResponseFormat, web3.exceptions.BlockNotFound):
                continue

            else:
                return block_transactions

    def main_work(self):
        logger.info('Запускаю парсер транзакций')
        previous_block_id = w3.eth.block_number

        while True:
            last_block_id = self.get_last_block(last_block_id_old=previous_block_id)
            previous_block_id = last_block_id

            block_transactions = self.get_block_transactions(block_id=last_block_id)

            with Pool(processes=CHECK_TRANSACTIONS_THREADS) as executor:
                executor.map(check_tx_data, block_transactions)


class ParsEtherscan:
    @staticmethod
    async def check_key_in_database(value: str) -> bool:
        async with aiosqlite.connect('addresses.db') as db:
            result_data = await (await db.execute(f'SELECT * FROM `addresses` WHERE `key` = \'{value}\' LIMIT 1')) \
                .fetchall()

        if result_data:
            return True

        return False

    @staticmethod
    async def add_to_database(key: str,
                              value: str) -> None:
        async with aiosqlite.connect('addresses.db') as db:
            await db.execute(f'INSERT INTO addresses (\'address\', \'key\') VALUES (\'{value.lower()}\', \'{key}\')')
            await db.commit()

    @staticmethod
    async def get_last_address_data() -> int:
        async with aiosqlite.connect('addresses.db') as db:
            result_data = await (await db.execute(f'SELECT * FROM \'addresses\' ORDER BY id DESC')) \
                .fetchall()

        if result_data is None:
            return 0

        sorted_result_data = [int(current_data[-1].split('Fake_Phishing')[-1]) for current_data in result_data]

        return max(sorted_result_data)

    async def main(self):
        logger.info('Запускаю парс Fake_Phishing адресов')

        i = 0
        total_empty = 0

        while True:
            if total_empty >= 10 and i > await self.get_last_address_data():
                i = 0
                total_empty = 0

            while True:
                check_key_result = await self.check_key_in_database(value=f'Fake_Phishing{i}')

                if check_key_result:
                    i += 1
                    continue

                try:
                    async with aiohttp.ClientSession(headers={
                        **headers,
                        'user-agent': random_useragent(),
                    },
                            connector=ProxyConnector.from_url(PROXY_STRING)) as session:
                        async with session.get(f'https://etherscan.io/search?f=0&q=Fake_Phishing{i}',
                                               allow_redirects=False) as r:
                            if r.headers.get('Location'):
                                if r.headers['Location'] == '/busy':
                                    logger.info(f'Fake_Phishing{i} | Busy')

                                    async with aiohttp.ClientSession() as change_proxy_session:
                                        async with change_proxy_session.get(PROXY_CHANGE_URL) as change_status:
                                            logger.info(f'Fake_Phishing{i} | Proxy Change Status: '
                                                        f'{change_status.status}')

                                    continue

                                elif '/address/' not in r.headers['Location']:
                                    i += 1
                                    total_empty += 1
                                    break

                                logger.success(f'Fake_Phishing{i} | {r.headers["Location"]}')
                                new_address = r.headers["Location"].split('/address/')[-1]

                                await self.add_to_database(key=f'Fake_Phishing{i}',
                                                           value=new_address)

                                total_empty = 0
                                i += 1
                                break

                            else:
                                logger.error(f'Fake_Phishing{i} | No Location')

                                if i > await self.get_last_address_data():
                                    total_empty += 1

                                i += 1
                                break

                except aiohttp_proxy.errors.SocksError:
                    logger.error(f'Fake_Phishing{i} | SocksError')
                    continue

                except Exception as error:
                    logger.error(f'Fake_Phishing{i} | Unexpected Error: {error}')
                    break


def parse_etherscan_wrapper():
    asyncio.run(ParsEtherscan().main())


if __name__ == '__main__':
    connector = sqlite3.connect('addresses.db')
    connector.execute('''CREATE TABLE if not exists addresses
                             (id integer primary key autoincrement, address str, key str)''')
    connector.commit()
    connector.close()

    with open('tx_method_ids.json', 'r', encoding='utf-8-sig') as file:
        tx_methods_data = load(file)

    with open('settings.json', 'r', encoding='utf-8-sig') as file:
        settings_json = load(file)

    PROXY_STRING = settings_json['proxy_string']
    PROXY_CHANGE_URL = settings_json['proxy_change_url']
    BOT_TOKEN = settings_json['bot_token']
    NODE_URL = settings_json['node_url']
    OWNER_USER_ID = int(settings_json['owner_user_id'])
    CHECK_TRANSACTIONS_THREADS = int(settings_json['check_transactions_threads'])

    w3 = Web3(HTTPProvider(NODE_URL))

    Thread(target=parse_etherscan_wrapper).start()

    App().main_work()
