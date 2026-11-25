import tkinter as tk
from tkinter import messagebox
from urllib.parse import urlparse
import os
from abc import ABC, abstractmethod
from typing import Tuple

class ILinkDataSource(ABC):
    @abstractmethod
    def get_malware_links(self) -> set:
        pass

    @abstractmethod
    def get_benign_domains(self) -> set:
        pass

class IUrlParser(ABC):
    @abstractmethod
    def extract_domain(self, url: str) -> str:
        pass

class ILinkVerifier(ABC):
    @abstractmethod
    def check(self, url: str) -> Tuple[str, str]:
        pass

class FileLinkDataSource(ILinkDataSource):
    def __init__(self, malware_path: str, benign_path: str):
        self.malware_path = malware_path
        self.benign_path = benign_path

    def _load_file(self, filepath: str) -> set:
        if not os.path.exists(filepath):
            print(f"[WARN] Файл {filepath} не найден. База будет пустой.")
            return set()
        with open(filepath, 'r', encoding='utf-8') as f:
            return {line.strip() for line in f if line.strip()}

    def get_malware_links(self) -> set:
        return self._load_file(self.malware_path)

    def get_benign_domains(self) -> set:
        return self._load_file(self.benign_path)

class StandardUrlParser(IUrlParser):
    def extract_domain(self, url: str) -> str:
        try:
            parsed = urlparse(url if '://' in url else f'http://{url}')
            host = parsed.netloc.lower()
            if host.startswith('www.'):
                host = host[4:]
            return host
        except Exception:
            return ''

class RuleBasedLinkVerifier(ILinkVerifier):
    def __init__(self, data_source: ILinkDataSource, url_parser: IUrlParser):
        self.malware_links = data_source.get_malware_links()
        self.benign_domains = data_source.get_benign_domains()
        self.parser = url_parser
        
        print(f"Загружено вредоносных ссылок: {len(self.malware_links)}")
        print(f"Загружено безопасных доменов: {len(self.benign_domains)}")

    def check(self, url: str) -> Tuple[str, str]:
        if url in self.malware_links:
            return 'ВРЕДОНОСНЫЙ', 'red'

        domain = self.parser.extract_domain(url)
        if domain and domain in self.benign_domains:
            return 'БЕЗОПАСНЫЙ', 'green'

        return 'ПОДОЗРИТЕЛЬНЫЙ', 'orange'

class LinkCheckerApp:
    def __init__(self, root, verifier: ILinkVerifier):
        self.root = root
        self.verifier = verifier 
        
        self.root.title('Проверка ссылок на безопасность')
        self.root.geometry('560x260')
        self.root.resizable(False, False)
        self._build_ui()

    def _build_ui(self):
        frame_input = tk.Frame(self.root)
        frame_input.pack(pady=15, padx=15, fill='x')

        tk.Label(frame_input, text='Ссылка для проверки:').pack(anchor='w')
        self.entry_url = tk.Entry(frame_input, width=70, font=('Arial', 11))
        self.entry_url.pack(fill='x', pady=(5, 0))
        self.entry_url.bind('<Return>', lambda e: self.check_link())

        self.btn_check = tk.Button(
            self.root, text='Проверить',
            font=('Arial', 11, 'bold'), bg='#4CAF50', fg='white', width=20,
            command=self.check_link
        )
        self.btn_check.pack(pady=5)

        frame_verdict = tk.Frame(self.root)
        frame_verdict.pack(pady=10, padx=15, fill='x')

        tk.Label(frame_verdict, text='Вердикт:').pack(anchor='w')
        self.verdict_label = tk.Label(
            frame_verdict, text='— ожидание —',
            font=('Arial', 14, 'bold'), fg='gray',
            relief='groove', width=40, height=2
        )
        self.verdict_label.pack(fill='x', pady=(5, 0))

    def check_link(self):
        url = self.entry_url.get().strip()
        if not url:
            messagebox.showwarning('Внимание', 'Введите ссылку для проверки')
            return
        text, color = self.verifier.check(url)
        self.verdict_label.config(text=text, fg=color)

def main():
    data_source = FileLinkDataSource('malware_links.txt', 'benign_domains.txt')
    parser = StandardUrlParser()
    
    verifier = RuleBasedLinkVerifier(data_source, parser)

    root = tk.Tk()
    app = LinkCheckerApp(root, verifier)
    root.mainloop()

if __name__ == '__main__':
    main()