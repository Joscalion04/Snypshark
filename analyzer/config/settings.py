import os
from pathlib import Path
from typing import Dict, Any

class Settings:
    """Configuración general de la aplicación"""
    
    # Configuración por defecto
    DEFAULTS = {
        'max_packets_to_process': 0,  # 0 = todos los paquetes
        'default_timeout': 30,
        'output_directory': 'reports',
        'log_level': 'INFO',
        'enable_ansi_colors': True,
        'auto_open_reports': False,
        'cache_size': 1000,
        'parallel_processing': True,
        'max_workers': 'auto'
    }
    
    def __init__(self):
        self.settings = self.DEFAULTS.copy()
        self.load_from_env()
    
    def load_from_env(self):
        """Carga configuración desde variables de entorno"""
        for key in self.settings.keys():
            env_var = f"SNYPSHARK_{key.upper()}"
            if env_var in os.environ:
                value = os.environ[env_var]
                # Convertir tipos
                if isinstance(self.settings[key], bool):
                    self.settings[key] = value.lower() in ('true', '1', 'yes')
                elif isinstance(self.settings[key], int):
                    try:
                        self.settings[key] = int(value)
                    except ValueError:
                        pass
                else:
                    self.settings[key] = value
    
    def get(self, key: str, default: Any = None) -> Any:
        """Obtiene un valor de configuración"""
        return self.settings.get(key, default)
    
    def set(self, key: str, value: Any) -> None:
        """Establece un valor de configuración"""
        if key in self.settings:
            self.settings[key] = value
    
    def save_to_file(self, filename: str = "snypshark.conf") -> bool:
        """Guarda la configuración en un archivo"""
        try:
            with open(filename, 'w') as f:
                for key, value in self.settings.items():
                    f.write(f"{key}={value}\n")
            return True
        except IOError:
            return False
    
    def load_from_file(self, filename: str = "snypshark.conf") -> bool:
        """Carga la configuración desde un archivo"""
        try:
            if Path(filename).exists():
                with open(filename, 'r') as f:
                    for line in f:
                        if '=' in line:
                            key, value = line.strip().split('=', 1)
                            if key in self.settings:
                                self.set(key, value)
                return True
            return False
        except IOError:
            return False