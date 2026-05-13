# логика форматирования и экспорта аудит-логов в разные форматы (JSON, CSV, PDF)
# обеспечивает удобство для внешних систем и пользователей, а также поддерживает требования безопасности (нелогирование чувствительных данных)
import json
import os
import csv
from datetime import datetime
from typing import Dict, Any, Optional
from database.db import DatabasePool
from core.audit.log_signer import LogSigner


class LogFormatter: # класс для форматирования и экспорта логов аудита в разные форматы (JSON, CSV, PDF)
    def __init__(self, db: DatabasePool, signer: LogSigner, key_manager: None, audit_logger: None):
        self.db = db
        self.signer = signer
        self.key_manager = key_manager
        self.audit_logger = audit_logger

    # публичный API для экспорта логов в разные форматы
    def export_json(
        self,
        filepath: str,
        start_seq: int = 0,
        end_seq: Optional[int] = None,
        password: Optional[str] = None,
    ) -> int: # экспорт в JSON — для обмена данными и интеграции с внешними системами. возвращает количество экспортированных записей.
            if not self._confirm_password(password or ""):
                raise PermissionError(
                    "Неверный мастер-пароль. Экспорт отклонён."
                )
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

            self._log_export("JSON", filepath, len(entries))

            return len(entries)

    def export_csv(
        self,
        filepath: str,
        start_seq: int = 0,
        end_seq: Optional[int] = None,
        password: Optional[str] = None,
    ) -> int: # экспорт в CSV — для удобного просмотра и анализа в табличных редакторах. возвращает количество экспортированных записей.
        
        if not self._confirm_password(password or ""):
            raise PermissionError(
                "Неверный мастер-пароль. Экспорт отклонён."
            )
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

        self._log_export("CSV", filepath, count)
        return count
    
    # экспорт в PDF — для создания отчетов и печати. возвращает количество экспортированных записей.
    def export_pdf(
        self,
        filepath: str,
        start_seq: int = 0,
        end_seq: Optional[int] = None,
        password: Optional[str] = None,
    ) -> int:
        if not self._confirm_password(password or ""):
            raise PermissionError(
                "Неверный мастер-пароль. Экспорт отклонён."
            )
        # экспорт в PDF — человекочитаемый отчёт с итоговой статистикой (EXP-1)
        # использует reportlab для генерации PDF без внешних сервисов
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import cm
            from reportlab.lib import colors
            from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer,
            Table, TableStyle, HRFlowable
        )
        except ImportError:
            raise ImportError(
                "reportlab не установлен. "
                "Выполните: pip install reportlab"
            )

        rows = self._fetch_rows(start_seq, end_seq)
        entries = [self._row_to_dict(row) for row in rows]

        doc = SimpleDocTemplate(
            filepath,
            pagesize=A4,
            rightMargin=2*cm, leftMargin=2*cm,
            topMargin=2*cm, bottomMargin=2*cm
        )

        styles = getSampleStyleSheet()
        story  = []

        # заголовок отчёта
        title_style = ParagraphStyle(
            'Title',
            parent=styles['Heading1'],
            fontSize=16,
            spaceAfter=6,
        )
        story.append(Paragraph("CryptoSafe Manager — Журнал аудита", title_style))

        # метаданные экспорта
        exported_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        story.append(Paragraph(
            f"Экспортировано: {exported_at} | "
            f"Записей: {len(entries)} | "
            f"Публичный ключ: {self.signer.get_public_key_bytes().hex()[:16]}…",
            styles['Normal']
        ))
        story.append(Spacer(1, 0.4*cm))
        story.append(HRFlowable(width="100%", thickness=1))
        story.append(Spacer(1, 0.4*cm))

        # итоговая статистика по типам событий
        story.append(Paragraph("Статистика событий", styles['Heading2']))

        stats: dict = {}
        severity_counts: dict = {}
        for e in entries:
            event_type = e['entry_data'].get('event_type', 'UNKNOWN')
            severity   = e['entry_data'].get('severity',   'INFO')
            stats[event_type]       = stats.get(event_type, 0) + 1
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        # таблица статистики по типам
        stats_data = [["Тип события", "Количество"]]
        for event_type, count in sorted(
            stats.items(), key=lambda x: x[1], reverse=True
        ):
            stats_data.append([event_type, str(count)])

        stats_table = Table(stats_data, colWidths=[12*cm, 4*cm])
        stats_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2C3E50')),
            ('TEXTCOLOR',  (0, 0), (-1, 0), colors.white),
            ('FONTNAME',   (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE',   (0, 0), (-1, 0), 10),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1),
            [colors.HexColor('#F8F9FA'), colors.white]),
            ('GRID',  (0, 0), (-1, -1), 0.5, colors.HexColor('#DEE2E6')),
            ('ALIGN', (1, 0), (1, -1), 'CENTER'),
            ('FONTSIZE', (0, 1), (-1, -1), 9),
            ('TOPPADDING',    (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(stats_table)
        story.append(Spacer(1, 0.4*cm))

        # статистика по severity
        sev_data = [["Severity", "Количество"]]
        sev_colors_map = {
            'INFO':     colors.HexColor('#D4EDDA'),
            'WARN':     colors.HexColor('#FFF3CD'),
            'ERROR':    colors.HexColor('#F8D7DA'),
            'CRITICAL': colors.HexColor('#F5C6CB'),
        }
        for sev, count in sorted(
            severity_counts.items(), key=lambda x: x[1], reverse=True
        ):
            sev_data.append([sev, str(count)])

        sev_table = Table(sev_data, colWidths=[12*cm, 4*cm])
        sev_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2C3E50')),
            ('TEXTCOLOR',  (0, 0), (-1, 0), colors.white),
            ('FONTNAME',   (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#DEE2E6')),
            ('ALIGN', (1, 0), (1, -1), 'CENTER'),
            ('FONTSIZE', (0, 1), (-1, -1), 9),
            ('TOPPADDING',    (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(sev_table)
        story.append(Spacer(1, 0.6*cm))
        story.append(HRFlowable(width="100%", thickness=1))
        story.append(Spacer(1, 0.4*cm))

        # таблица записей (последние 500 чтобы не раздувать PDF)
        story.append(Paragraph("Записи журнала", styles['Heading2']))

        MAX_ROWS = 500
        display_entries = entries[-MAX_ROWS:] if len(entries) > MAX_ROWS else entries

        if len(entries) > MAX_ROWS:
            story.append(Paragraph(
                f"Показаны последние {MAX_ROWS} из {len(entries)} записей.",
                styles['Italic']
            ))

        log_data = [["#", "Время", "Тип события", "Severity"]]
        for e in display_entries:
            data       = e['entry_data']
            seq        = str(e['sequence_number'])
            ts         = e.get('timestamp', '')[:19]  # обрезаем миллисекунды
            event_type = data.get('event_type', '')
            severity   = data.get('severity',   'INFO')
            log_data.append([seq, ts, event_type, severity])

        log_table = Table(
            log_data,
            colWidths=[1.5*cm, 4.5*cm, 8*cm, 2.5*cm]
        )
        log_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2C3E50')),
            ('TEXTCOLOR',  (0, 0), (-1, 0), colors.white),
            ('FONTNAME',   (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE',   (0, 0), (-1, 0), 9),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1),
            [colors.HexColor('#F8F9FA'), colors.white]),
            ('GRID',  (0, 0), (-1, -1), 0.5, colors.HexColor('#DEE2E6')),
            ('FONTSIZE', (0, 1), (-1, -1), 8),
            ('TOPPADDING',    (0, 0), (-1, -1), 3),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
            ('ALIGN', (0, 0), (0, -1), 'CENTER'),
            ('ALIGN', (3, 0), (3, -1), 'CENTER'),
        ]))
        story.append(log_table)

        doc.build(story)
        
        self._log_export("PDF", filepath, len(entries))
        return len(entries)

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
    
    def _confirm_password(self, password: str) -> bool:
        # вспомогательный метод для подтверждения пароля при экспорте логов, если это требуется политикой безопасности. 
        # может быть вызван из UI перед началом экспорта, чтобы убедиться, что пользователь имеет право экспортировать логи.
        if self.key_manager is None:
            return True  # если менеджер ключей не инициализирован, пропускаем проверку (можно изменить логику по необходимости)
        
        try : # используем существующий метод верификации пароля из менеджера ключей для подтверждения пароля. если пароль неверный, возвращаем False, иначе True.
            return self.key_manager.derivation.verify_master_key(password, self.key_manager.storage.get_auth_hash())
        except Exception:
            return False
        
    def _log_export (self, format_name : str, filepath : str, count : int):
        # вспомогательный метод для логирования события экспорта логов в аудит-лог, чтобы сохранять запись о том, что был выполнен экспорт, в каком формате и сколько записей было экспортировано. может быть вызван после успешного экспорта для создания соответствующей записи в аудит-логе.
        if self.audit_logger is None:
            return  # если аудит-логгер не инициализирован, пропускаем логирование (можно изменить логику по необходимости)
        try:
            self.audit_logger.log_event(
            event_type = "AUDIT_LOG_EXPORT",
            severity   = "INFO",
            source     = "log_formatters",
            details    = {
                "format": format_name,
                "filename": os.path.basename(filepath),
                "entries": count,
                "exported_at": datetime.utcnow().isoformat() + "Z",
            }
            )
            
        except Exception:
            pass