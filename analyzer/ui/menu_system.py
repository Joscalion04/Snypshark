import os
from typing import Any, Dict

from utils.logger import get_logger

logger = get_logger(__name__)


class MenuSystem:
    """Hierarchical menu system, available for future UI extensions."""

    def __init__(self):
        self.menus: Dict[str, Dict] = {}
        self.current_menu = "main"
        self.history: list = []

    def add_menu(self, name: str, options: Dict[str, tuple]) -> None:
        self.menus[name] = options

    def display_current_menu(self) -> bool:
        if self.current_menu not in self.menus:
            logger.error("Menu '%s' not found.", self.current_menu)
            return False

        options = self.menus[self.current_menu]
        print(f"\n{self.current_menu.upper()} MENU")
        print("=" * 50)
        for key, (desc, _) in options.items():
            print(f"  {key}. {desc}")
        return True

    def handle_choice(self, choice: str) -> Any:
        if self.current_menu not in self.menus:
            return None

        options = self.menus[self.current_menu]
        if choice not in options:
            logger.warning("Invalid menu option: '%s'", choice)
            return None

        description, action = options[choice]

        if callable(action):
            return action()
        elif isinstance(action, str) and action in self.menus:
            self.history.append(self.current_menu)
            self.current_menu = action
            return f"Navigated to {action}"
        elif action is None:
            if self.history:
                self.current_menu = self.history.pop()
                return f"Returned to {self.current_menu}"
            return "exit"

        return None

    def clear_screen(self) -> None:
        try:
            os.system("cls" if os.name == "nt" else "clear")
        except Exception:
            print("\n" * 50)
