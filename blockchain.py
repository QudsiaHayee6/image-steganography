import hashlib
import time
class Blockchain:
    """Simple blockchain implementation for transaction logging"""
    def __init__(self):
        self.chain = []
        self.create_genesis_block()

    def create_genesis_block(self):
        """Create the first block in the chain"""
        genesis_block = {
            'index': 1,
            'timestamp': str(time.time()),
            'transaction_data': "Genesis Block",
            'previous_hash': '0',
            'hash': self._hash_block("Genesis Block")
        }
        self.chain.append(genesis_block)

    @staticmethod
    def _hash_block(transaction_data):
        """Calculate SHA-256 hash of block data"""
        return hashlib.sha256(transaction_data.encode()).hexdigest()

    def add_transaction(self, transaction_data):
        """Add a new transaction to the blockchain"""
        last_block = self.chain[-1]
        new_block = {
            'index': last_block['index'] + 1,
            'timestamp': str(time.time()),
            'transaction_data': transaction_data,
            'previous_hash': last_block['hash'],
            'hash': self._hash_block(transaction_data + last_block['hash'])
        }
        self.chain.append(new_block)
        return new_block