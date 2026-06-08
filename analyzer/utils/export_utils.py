import json
import csv
import pandas as pd
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List
from utils.logger import get_logger

logger = get_logger(__name__)


def export_to_json(data: Dict[str, Any], filename: str, indent: int = 2) -> bool:
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=indent, default=str, ensure_ascii=False)
        return True
    except (IOError, TypeError) as e:
        logger.error("JSON export failed: %s", e)
        return False


def export_to_csv(data: List[Dict[str, Any]], filename: str) -> bool:
    if not data:
        return False
    try:
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=data[0].keys())
            writer.writeheader()
            writer.writerows(data)
        return True
    except (IOError, csv.Error) as e:
        logger.error("CSV export failed: %s", e)
        return False


def export_to_excel(dataframes: Dict[str, pd.DataFrame], filename: str) -> bool:
    try:
        with pd.ExcelWriter(filename, engine='openpyxl') as writer:
            for sheet_name, df in dataframes.items():
                if df is not None and not df.empty:
                    df.to_excel(writer, sheet_name=sheet_name[:31], index=False)
        return True
    except Exception as e:
        logger.error("Excel export failed: %s", e)
        return False


def generate_report_filename(base_name: str, extension: str) -> str:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{base_name}_{timestamp}.{extension}"


def create_report_directory() -> str:
    report_dir = Path("reports")
    report_dir.mkdir(exist_ok=True)
    return str(report_dir)


def export_analysis_results(analyzer, processors: Dict[str, Any], fmt: str = "json") -> bool:
    try:
        report_dir = create_report_directory()
        base = f"{report_dir}/analysis_report"

        if fmt == "json":
            report_data = {
                'overview': analyzer.stats,
                'processor_stats': {
                    name: proc.get_stats()
                    for name, proc in processors.items()
                    if hasattr(proc, 'get_stats')
                },
            }
            return export_to_json(report_data, generate_report_filename(base, "json"))

        if fmt == "excel":
            pa = processors.get('pandas')
            if pa and hasattr(pa, 'export_to_excel'):
                pa.export_to_excel(generate_report_filename(base, "xlsx"))
                return True

        return False

    except Exception as e:
        logger.error("Report export failed: %s", e)
        return False
