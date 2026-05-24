#Реализация класса LogVerifier для проверки целостности и подлинности записей аудита
# LogVerifier использует LogSigner для проверки цифровых подписей и обеспечивает проверку цепочки записей, 
# а также целостности данных. Он может быть использован для регулярного аудита логов и выявления любых 
# нарушений или изменений в записях.
import datetime
import hashlib
import threading
from typing import Dict, Any, Optional
from .log_signer import LogSigner
from database.db import DatabasePool as db

class LogVerifier: # класс для проверки целостности и подлинности записей аудита
    def __init__(self, db: db, signer: LogSigner):
        self.db = db
        self.signer = signer
        self._periodic_running = False
        self._periodic_thread = None
        self._periodic_callback = None
        
    def verify_log(self, start_seq: int = 0, end_seq: Optional[int] = None) -> Dict[str, Any]:
        # получаем записи из базы данных в указанном диапазоне. каждая запись содержит данные, подпись, хеш и предыдущий хеш для проверки целостности цепочки.
        query = """
            SELECT sequence_number, entry_data, signature, entry_hash, previous_hash
            FROM audit_log
            WHERE sequence_number >= ?
        """
        params = [start_seq]

        if end_seq is not None:
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
    
    def verify_integrity(
        self,
        start_seq: int = 0,
        end_seq=None,
    ) -> dict:
        # алиас для verify_log() —
        # используется в GUI и периодической верификации
        return self.verify_log(start_seq=start_seq, end_seq=end_seq)
    
    def start_periodic_verification(
        self,
        interval_hours: int = 24,
        on_result=None,
    ):
        self._periodic_running = True
        self._periodic_callback = on_result

        def _loop():
            while self._periodic_running:
                waited = 0
                interval_seconds = interval_hours * 3600
                while (
                    waited < interval_seconds
                    and self._periodic_running
                ):
                    threading.Event().wait(timeout=1)
                    waited += 1

                if not self._periodic_running:
                    break

                try:
                    result = self._verify_last_n(n=1000)
                    result['checked_at'] = (
                        datetime.datetime.utcnow().isoformat() + "Z"
                    )
                    if self._periodic_callback:
                        self._periodic_callback(result)
                except Exception as e:
                    if self._periodic_callback:
                        self._periodic_callback({
                            'verified':   False,
                            'error':      str(e),
                            'checked_at': datetime.datetime.utcnow().isoformat() + "Z",
                        })

        self._periodic_thread = threading.Thread(
            target=_loop,
            daemon=True,
            name="audit-periodic-verifier"
        )
        self._periodic_thread.start()

    def stop_periodic_verification(self):
        # останавливаем периодическую верификацию
        # вызывается при закрытии приложения
        self._periodic_running = False

    def _verify_last_n(self, n: int = 1000) -> dict:
        # верифицируем последние N записей
        # используется в периодической проверке
        row = self.db.execute(
            "SELECT MAX(sequence_number) as max_seq FROM audit_log"
        ).fetchone()

        max_seq = (
            row["max_seq"]
            if row and row["max_seq"] is not None
            else 0
        )
        start_seq = max(0, max_seq - n + 1)
        return self.verify_log(start_seq=start_seq)