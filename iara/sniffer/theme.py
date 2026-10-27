"""HXARK desktop colors, fonts and window sizing."""
import os
import tkinter as tk
from tkinter import font, ttk

from .resources import brand_icon

BG = '#141414'
SURFACE = '#1c1c1c'
HOVER = '#282828'
BORDER = '#363636'
TEXT = '#f5f5f5'
MUTED = '#a8a8a8'
DANGER = '#f58383'


def fit_content(root, panel):
    """Keep controls visible with native fonts and Windows display scaling."""
    root.update_idletasks()
    minimum = (max(540, panel.winfo_reqwidth()), max(340, panel.winfo_reqheight()))
    if root.minsize() != minimum:
        root.minsize(*minimum)


def window_identity(window):
    window.configure(background=BG)
    image = tk.PhotoImage(master=window, file=str(brand_icon()))
    window._hxark_icon = image
    window.iconphoto(True, image)
    if os.name == 'nt':
        # Set dark title bars on this window only.
        import ctypes as c
        try:
            window.update_idletasks()
            user = c.WinDLL('user32')
            user.GetAncestor.argtypes = [c.c_void_p, c.c_uint]
            user.GetAncestor.restype = c.c_void_p
            hwnd = user.GetAncestor(window.winfo_id(), 2)
            dwm = c.WinDLL('dwmapi')
            dwm.DwmSetWindowAttribute.argtypes = [c.c_void_p, c.c_uint, c.c_void_p, c.c_uint]
            enabled = c.c_int(1)
            if dwm.DwmSetWindowAttribute(hwnd, 20, c.byref(enabled), c.sizeof(enabled)):
                dwm.DwmSetWindowAttribute(hwnd, 19, c.byref(enabled), c.sizeof(enabled))
        except OSError:
            pass  # Older Windows keeps its native title bar.


def apply(root):
    family = 'Inter' if 'Inter' in font.families(root) else 'Segoe UI'
    style = ttk.Style(root)
    style.theme_use('clam')
    style.configure('.', background=BG, foreground=TEXT, font=(family, 10))
    style.configure('TFrame', background=BG)
    style.configure('TLabel', background=BG, foreground=TEXT)
    style.configure('Muted.TLabel', foreground=MUTED)
    style.configure('Card.TFrame', background=SURFACE, bordercolor=BORDER,
                    lightcolor=BORDER, darkcolor=BORDER, borderwidth=1, relief='solid')
    style.configure('Card.TLabel', background=SURFACE, foreground=TEXT)
    style.configure('CardMuted.TLabel', background=SURFACE, foreground=MUTED)
    style.configure('TButton', background=SURFACE, foreground=TEXT,
                    bordercolor=BORDER, lightcolor=BORDER, darkcolor=BORDER,
                    borderwidth=1, focusthickness=1, focuscolor=TEXT, padding=(14, 9))
    style.map('TButton', background=[('active', HOVER), ('pressed', BORDER)],
              foreground=[('disabled', MUTED)], bordercolor=[('focus', TEXT)])
    style.configure('Primary.TButton', background=TEXT, foreground=BG,
                    bordercolor=TEXT, lightcolor=TEXT, darkcolor=TEXT, focuscolor=BG,
                    font=(family, 10, 'bold'))
    style.map('Primary.TButton', background=[('pressed', '#cacaca'), ('active', '#dedede')],
              foreground=[('disabled', MUTED), ('!disabled', BG)],
              bordercolor=[('active', '#dedede'), ('!active', TEXT)])
    style.configure('Ghost.TButton', background=BG, borderwidth=0,
                    bordercolor=BG, lightcolor=BG, darkcolor=BG, foreground=MUTED, padding=(10, 7))
    style.map('Ghost.TButton', background=[('active', HOVER)], foreground=[('active', TEXT)])
    style.configure('TNotebook', background=BG, borderwidth=0)
    style.configure('TNotebook.Tab', background=BG, foreground=MUTED, padding=(14, 9))
    style.map('TNotebook.Tab', background=[('selected', SURFACE)], foreground=[('selected', TEXT)])
    style.configure('Vertical.TScrollbar', background=HOVER, troughcolor=SURFACE,
                    bordercolor=SURFACE, arrowcolor=MUTED)
    window_identity(root)
    return family
