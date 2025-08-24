from typing import Dict, Callable, Any
import os

class MenuSystem:
    """Sistema de menús jerárquico para la interfaz de usuario"""
    
    def __init__(self):
        self.menus = {}
        self.current_menu = "main"
        self.history = []
    
    def add_menu(self, name: str, options: Dict[str, tuple]):
        """Añade un menú al sistema"""
        self.menus[name] = options
    
    def display_current_menu(self):
        """Muestra el menú actual"""
        if self.current_menu not in self.menus:
            print(f"❌ Menu '{self.current_menu}' not found")
            return False
        
        options = self.menus[self.current_menu]
        
        print(f"\n🎯 {self.current_menu.upper()} MENU")
        print("═" * 50)
        
        for key, (desc, _) in options.items():
            print(f"{key}. {desc}")
        
        return True
    
    def handle_choice(self, choice: str) -> Any:
        """Maneja la elección del usuario"""
        if self.current_menu not in self.menus:
            return None
        
        options = self.menus[self.current_menu]
        
        if choice not in options:
            print("❌ Invalid option")
            return None
        
        description, action = options[choice]
        
        if callable(action):
            return action()
        elif isinstance(action, str) and action in self.menus:
            # Navegación a submenú
            self.history.append(self.current_menu)
            self.current_menu = action
            return f"Navigated to {action}"
        elif action is None:
            # Volver atrás
            if self.history:
                self.current_menu = self.history.pop()
                return f"Returned to {self.current_menu}"
            else:
                return "exit"
        
        return None
    
    def clear_screen(self):
        """Limpia la pantalla"""
        try:
            os.system('cls' if os.name == 'nt' else 'clear')
        except:
            print("\n" * 50)