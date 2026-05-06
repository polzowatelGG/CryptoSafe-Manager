# логика форматирования и экспорта аудит-логов в разные форматы (JSON, CSV, PDF)
# обеспечивает удобство для внешних систем и пользователей, а также поддерживает требования безопасности (нелогирование чувствительных данных)
import json
import csv
from datetime import datetime
from typing import Dict, Any, Optional
from database.db import DatabasePool
from core.audit.log_signer import LogSigner


class LogFormatter: # класс для форматирования и экспорта логов аудита в разные форматы (JSON, CSV, PDF)
    def __init__(self, db: DatabasePool, signer: LogSigner):
        self.db = db
        self.signer = signer

    # публичный API для экспорта логов в разные форматы
    def export_json(
        self,
        filepath: str,
        start_seq: int = 0,
        end_seq: Optional[int] = None,
    ) -> int: # экспорт в JSON — для обмена данными и интеграции с внешними системами. возвращает количество экспортированных записей.
        rows = self._fetch_rows(start_seq, end_seq)
        entries = [self._row_to_dict(row) for row in rows] 

        payload = {
            "export_meta": {
                "exported_at":    datetime.utcnow().isoformat() + "Z",
                "total_entries":  len(entries),
                "format_version": 1,
                # публичный ключ для независимой верификации подписей
                "public_key_hex": self.signer.get_public_key_bytes().hex(),
            },
            "entries": entries,
        }

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)

        return len(entries)

    def export_csv(
        self,
        filepath: str,
        start_seq: int = 0,
        end_seq: Optional[int] = None,
    ) -> int: # экспорт в CSV — для удобного просмотра и анализа в табличных редакторах. возвращает количество экспортированных записей.
        rows = self._fetch_rows(start_seq, end_seq)

        fieldnames = [
            "sequence_number",
            "timestamp",
            "event_type",
            "severity",
            "source",
            "user_id",
            "details",
            "entry_hash",
            "signature",
        ]

        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()

            count = 0
            for row in rows:
                entry_data = json.loads(row["entry_data"])
                writer.writerow({
                    "sequence_number": row["sequence_number"],
                    "timestamp":       row["timestamp"],
                    "event_type":      entry_data.get("event_type", ""),
                    "severity":        entry_data.get("severity", ""),
                    "source":          entry_data.get("source", ""),
                    "user_id":         entry_data.get("user_id", ""),
                    # details сериализуем обратно в строку для CSV
                    "details":         json.dumps(
                                           entry_data.get("details", {}),
                                           ensure_ascii=False
                                       ),
                    "entry_hash":      row["entry_hash"],
                    "signature":       row["signature"],
                }) #
                count += 1

        return count

    def export_pdf(self, filepath: str, **kwargs) -> int: # экспорт в PDF — для создания отчетов и печати. возвращает количество экспортированных записей.
        raise NotImplementedError(
            "PDF export будет реализован в Sprint 6. "
            "Используйте export_json() или export_csv()."
        )

    #внутренние методы для работы с базой данных и форматированием данных 

    def _fetch_rows(self, start_seq: int, end_seq: Optional[int]): # извлекаем записи из базы данных в указанном диапазоне sequence_number, 
        # сортируем по возрастанию для правильной последовательности. возвращаем результат запроса.
        query  = """
            SELECT sequence_number, entry_data, entry_hash, signature, timestamp
            FROM audit_log
            WHERE sequence_number >= ?
        """
        params = [start_seq]

        if end_seq is not None:
            query  += " AND sequence_number <= ?"
            params.append(end_seq)

        query += " ORDER BY sequence_number ASC"
        return self.db.execute(query, tuple(params)).fetchall() 

    def _row_to_dict(self, row) -> Dict[str, Any]: # преобразуем строку из базы данных в словарь с полями для экспорта, 
        # включая декодирование JSON из entry_data и сохранение остальных полей как есть.
        return {
            "sequence_number": row["sequence_number"],
            "timestamp":       row["timestamp"],
            "entry_data":      json.loads(row["entry_data"]),
            "entry_hash":      row["entry_hash"],
            "signature":       row["signature"],
        }