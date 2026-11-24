import tkinter as tk
from tkinter import messagebox
from urllib.parse import urlparse
import os

MALWARE_FILE = 'malware_links.txt'
BENIGN_FILE = 'benign_domains.txt'


def load_lines(filepath):
    if not os.path.exists(filepath):
        print(f"[WARN] Файл {filepath} не найден. База будет пустой.")
        return set()
    with open(filepath, 'r', encoding='utf-8') as f:
        return {line.strip() for line in f if line.strip()}


def get_domain(url):
    try:
        parsed = urlparse(url if '://' in url else f'http://{url}')
        host = parsed.netloc.lower()
        if host.startswith('www.'):
            host = host[4:]
        return host
    except Exception:
        return ''


class LinkCheckerApp:
    def __init__(self, root):
        self.root = root
        self.root.title('Проверка ссылок на безопасность')
        self.root.geometry('560x260')
        self.root.resizable(False, False)

        self.malware_links = load_lines(MALWARE_FILE)
        self.benign_domains = load_lines(BENIGN_FILE)
        print(f"Загружено вредоносных ссылок: {len(self.malware_links)}")
        print(f"Загружено безопасных доменов: {len(self.benign_domains)}")

        self._build_ui()

    def _build_ui(self):
        frame_input = tk.Frame(self.root)
        frame_input.pack(pady=15, padx=15, fill='x')

        tk.Label(frame_input, text='Ссылка для проверки:').pack(anchor='w')
        self.entry_url = tk.Entry(frame_input, width=70, font=('Arial', 11))
        self.entry_url.pack(fill='x', pady=(5, 0))
        self.entry_url.bind('<Return>', lambda e: self.check_link())

        self.btn_check = tk.Button(
            self.root,
            text='Проверить',
            font=('Arial', 11, 'bold'),
            bg='#4CAF50',
            fg='white',
            width=20,
            command=self.check_link
        )
        self.btn_check.pack(pady=5)

        frame_verdict = tk.Frame(self.root)
        frame_verdict.pack(pady=10, padx=15, fill='x')

        tk.Label(frame_verdict, text='Вердикт:').pack(anchor='w')
        self.verdict_label = tk.Label(
            frame_verdict,
            text='— ожидание —',
            font=('Arial', 14, 'bold'),
            fg='gray',
            relief='groove',
            width=40,
            height=2
        )
        self.verdict_label.pack(fill='x', pady=(5, 0))

    def check_link(self):
        url = self.entry_url.get().strip()
        if not url:
            messagebox.showwarning('Внимание', 'Введите ссылку для проверки')
            return

        domain = get_domain(url)

        if url in self.malware_links:
            self._set_verdict('ВРЕДОНОСНЫЙ', 'red')
            return

        if domain and domain in self.benign_domains:
            self._set_verdict('БЕЗОПАСНЫЙ', 'green')
            return
            
        self._set_verdict('ПОДОЗРИТЕЛЬНЫЙ', 'orange')

    def _set_verdict(self, text, color):
        self.verdict_label.config(text=text, fg=color)


def main():
    root = tk.Tk()
    app = LinkCheckerApp(root)
    root.mainloop()


if __name__ == '__main__':
    main()