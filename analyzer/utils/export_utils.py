import json
import csv
import pandas as pd
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List

def export_to_json(data: Dict[str, Any], filename: str, indent: int = 2) -> bool:
    """Exporta datos a formato JSON"""
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=indent, default=str, ensure_ascii=False)
        return True
    except (IOError, TypeError) as e:
        print(f"❌ JSON export failed: {e}")
        return False

def export_to_csv(data: List[Dict[str, Any]], filename: str) -> bool:
    """Exporta datos a formato CSV"""
    if not data:
        return False
    
    try:
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=data[0].keys())
            writer.writeheader()
            writer.writerows(data)
        return True
    except (IOError, csv.Error) as e:
        print(f"❌ CSV export failed: {e}")
        return False

def export_to_excel(dataframes: Dict[str, pd.DataFrame], filename: str) -> bool:
    """Exporta múltiples DataFrames a un archivo Excel"""
    try:
        with pd.ExcelWriter(filename, engine='openpyxl') as writer:
            for sheet_name, df in dataframes.items():
                if df is not None and not df.empty:
                    df.to_excel(writer, sheet_name=sheet_name[:31], index=False)
        return True
    except Exception as e:
        print(f"❌ Excel export failed: {e}")
        return False

def generate_report_filename(base_name: str, extension: str) -> str:
    """Genera un nombre de archivo único para reportes"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{base_name}_{timestamp}.{extension}"

def create_report_directory() -> str:
    """Crea un directorio para reportes si no existe"""
    report_dir = Path("reports")
    report_dir.mkdir(exist_ok=True)
    return str(report_dir)

def export_analysis_results(analyzer, processors: Dict[str, Any], format: str = "json") -> bool:
    """Exporta resultados completos del análisis"""
    try:
        report_dir = create_report_directory()
        base_filename = f"{report_dir}/analysis_report"
        
        if format == "json":
            # Recopilar datos de todos los procesadores
            report_data = {
                'overview': analyzer.stats,
                'processor_stats': {name: proc.get_stats() for name, proc in processors.items() if hasattr(proc, 'get_stats')}
            }
            filename = generate_report_filename(base_filename, "json")
            return export_to_json(report_data, filename)
        
        elif format == "excel":
            # Para pandas analyzer
            pandas_analyzer = processors.get('pandas')
            if pandas_analyzer and hasattr(pandas_analyzer, 'export_to_excel'):
                filename = generate_report_filename(base_filename, "xlsx")
                pandas_analyzer.export_to_excel(filename)
                return True
        
        return False
        
    except Exception as e:
        print(f"❌ Report export failed: {e}")
        return False