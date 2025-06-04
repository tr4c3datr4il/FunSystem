import colorama

class Color:
    """Handle colored terminal output using colorama."""
    
    def __init__(self):
        colorama.init(autoreset=True)
        self.WRONG = colorama.Fore.RED
        self.CORRECT = colorama.Fore.GREEN
        self.WARNING = colorama.Fore.YELLOW

    def reset(self):
        colorama.deinit()
        colorama.init(autoreset=True)
        self.WRONG = colorama.Fore.RED
        self.CORRECT = colorama.Fore.GREEN
        self.WARNING = colorama.Fore.YELLOW

    def _print(self, text, color):
        print(f"{color}{text}{colorama.Style.RESET_ALL}")