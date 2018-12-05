# MIT License
#
# Copyright (c) 2018 Omidiora Samuel, samparsky@gmail.com
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.


from bitcoinetl.domain.transaction import BtcTransaction
from bitcoinetl.mappers.txn_input_mapper import BtcTransactionInputMapper
from bitcoinetl.mappers.txn_output_mapper import BtcTransactionOutputMapper


class BtcTransactionMapper(object):
    def json_dict_to_transaction(self, json_dict, block=None):
        transaction = BtcTransaction()
        transaction.hex = json_dict.get('hex')
        transaction.hash = json_dict.get('hash')
        transaction.size = json_dict.get('size')
        transaction.vsize = json_dict.get('vsize')
        transaction.version = json_dict.get('version')
        transaction.lock_time = json_dict.get('locktime')

        transaction.block_hash = json_dict.get('blockhash')
        if block is not None:
            transaction.block_hash = block.hash

        transaction.block_time = json_dict.get('blocktime')
        if block is not None:
            transaction.block_time = block.time

        transaction.vin = BtcTransactionInputMapper().json_dict_to_input(json_dict)
        transaction.vout = BtcTransactionOutputMapper().json_dict_to_output(json_dict)

        return transaction

    def transaction_to_dict(self, transaction):
        result = {
            'type': 'transaction',
            'hex': transaction.hex,
            'hash': transaction.hash,
            'size': transaction.size,
            'vsize': transaction.vsize,
            'version': transaction.version,
            'lock_time': transaction.lock_time,
            'block_hash': transaction.block_hash,
            'block_time': transaction.block_time,

            'vout': BtcTransactionOutputMapper().output_to_dict(transaction.vout),
            'vin': BtcTransactionInputMapper().input_to_dict(transaction.vin)
        }
        return result