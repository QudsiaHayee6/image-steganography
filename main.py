import tkinter as tk
from ui import SteganographyApp


def main():
    root = tk.Tk()

    # Window configuration
    window_width = 800
    window_height = 700
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    center_x = int(screen_width / 2 - window_width / 2)
    center_y = int(screen_height / 2 - window_height / 2)
    root.geometry(f'{window_width}x{window_height}+{center_x}+{center_y}')

    try:
        root.iconbitmap('icon.ico')
    except:
        pass  # Continue if icon not found

    app = SteganographyApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()