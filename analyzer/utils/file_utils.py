import os
from pathlib import Path


def validate_file_path(file_path: str) -> bool:
    """Valida si la ruta del archivo existe y es accesible"""
    try:
        path = Path(file_path)
        return path.exists() and path.is_file() and os.access(file_path, os.R_OK)
    except (OSError, TypeError):
        return False


def get_file_size(file_path: str) -> tuple:
    """Obtiene el tamaño del archivo en bytes y formato legible"""
    try:
        size_bytes: float = os.path.getsize(file_path)
        for unit in ["B", "KB", "MB", "GB"]:
            if size_bytes < 1024.0:
                return size_bytes, f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024.0
        return size_bytes * 1024, f"{size_bytes:.2f} TB"
    except OSError:
        return 0, "0 B"


def create_output_dir(directory: str) -> bool:
    """Crea un directorio de salida si no existe"""
    try:
        Path(directory).mkdir(parents=True, exist_ok=True)
        return True
    except OSError:
        return False


def get_file_extension(file_path: str) -> str:
    """Obtiene la extensión del archivo en minúsculas"""
    return Path(file_path).suffix.lower()


def is_pcap_file(file_path: str) -> bool:
    """Verifica si el archivo es un PCAP válido"""
    ext = get_file_extension(file_path)
    return ext in [".pcap", ".pcapng", ".cap"]


def find_pcap_files(directory: str) -> list:
    """Encuentra todos los archivos PCAP en un directorio"""
    pcap_files = []
    try:
        for root, _, files in os.walk(directory):
            for file in files:
                if is_pcap_file(file):
                    pcap_files.append(os.path.join(root, file))
    except OSError:
        pass
    return pcap_files
