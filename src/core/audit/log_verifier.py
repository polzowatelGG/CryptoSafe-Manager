#Реализация класса LogVerifier для проверки целостности и подлинности записей аудита
# LogVerifier использует LogSigner для проверки цифровых подписей и обеспечивает проверку цепочки записей, 
# а также целостности данных. Он может быть использован для регулярного аудита логов и выявления любых 
# нарушений или изменений в записях.
import hashlib
from typing import Dict, Any, Optional
from .log_signer import LogSigner
from database import DatabasePool as db

class LogVerifier: # класс для проверки целостности и подлинности записей аудита
    def __init__(self, db: db, signer: LogSigner):
        self.db = db
        self.signer = signer
        
    def verify_log(self, start_seq: int = 0, end_seq: Optional[int] = None) -> Dict[str, Any]:
        # получаем записи из базы данных в указанном диапазоне. каждая запись содержит данные, подпись, хеш и предыдущий хеш для проверки целостности цепочки.
        query = """
            SELECT sequence_number, entry_data, signature, entry_hash, previous_hash
            FROM audit_log
            WHERE sequence_number >= ?
        """
        params = [start_seq]

        if end_seq:
            query += " AND sequence_number <= ?"
            params.append(end_seq)

        query += " ORDER BY sequence_number"

        rows = self.db.execute(query, params).fetchall()

        results = {
            'total_entries': len(rows),
            'valid_entries': 0,
            'invalid_entries': [],
            'chain_breaks': [],
            'verified': True
        }

        previous_hash = None

        for row in rows:
            seq_num, entry_data, signature_hex, entry_hash, prev_hash = row

            # Проверяем подпись
            signature = bytes.fromhex(signature_hex)
            if not self.signer.verify(entry_data.encode(), signature):
                results['invalid_entries'].append({
                    'sequence': seq_num,
                    'reason': 'Invalid signature'
                })
                results['verified'] = False
                continue

            # прроверяем целостность цепочки
            if previous_hash is not None and prev_hash != previous_hash:
                results['chain_breaks'].append({
                    'sequence': seq_num,
                    'expected': previous_hash,
                    'actual': prev_hash
                })
                results['verified'] = False

            # проверяем хеш записи
            computed_hash = hashlib.sha256(entry_data.encode()).hexdigest()
            if computed_hash != entry_hash:
                results['invalid_entries'].append({
                    'sequence': seq_num,
                    'reason': 'Hash mismatch'
                })
                results['verified'] = False
                continue

            previous_hash = entry_hash
            results['valid_entries'] += 1

        return results