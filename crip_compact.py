import os, sys, hmac, hashlib, threading, tkinter as tk
from pathlib import Path
from datetime import datetime
from tkinter import filedialog, messagebox, scrolledtext
from cryptography.fernet import Fernet

# ---------------- Configuração ----------------
PASTA_CRIP    = os.environ.get("CRIPTO_PASTA", str(Path.home() / "Desktop" / "material crip"))
PASTA_DESCRIP = os.path.join(PASTA_CRIP, "descrip")
KEY_FILE      = os.path.join(PASTA_CRIP, "chave.key")
MARKER        = "ENCRYPTED_FILE_V1"
SPECIAL       = ".,!@#$%&-_+§"
ALPHABET      = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" + SPECIAL

# ---------------- Paleta de Cores Profissional ----------------
BG_MAIN       = "#F3F4F6"  # Fundo geral cinza bem claro
TEXT_MAIN     = "#1F2937"  # Cinza escuro para textos
TEXT_MUTED    = "#6B7280"  # Cinza para textos secundários
BG_INPUT      = "#FFFFFF"  # Fundo de campos
BORDER_COLOR  = "#D1D5DB"  # Borda suave

BTN_BLUE      = "#2563EB"  # Escolher arquivo
BTN_BLUE_H    = "#1D4ED8"
BTN_GREEN     = "#059669"  # Criptografar
BTN_GREEN_H   = "#047857"
BTN_ORANGE    = "#D97706"  # Descriptografar
BTN_ORANGE_H  = "#B45309"
BTN_INDIGO    = "#4F46E5"  # Automático
BTN_INDIGO_H  = "#4338CA"

# ---------------- Criptografia ----------------
def get_key():
    os.makedirs(PASTA_DESCRIP, exist_ok=True)
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            return f.read()
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(key)
    return key

def is_encrypted(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.readline().strip() == MARKER
    except (UnicodeDecodeError, OSError):
        return False

def gen_password(token, key, length=16):
    blocks, i = [], 0
    while len(b"".join(blocks)) < length + 4:
        blocks.append(hmac.new(key, token.encode() + i.to_bytes(4, "big"), hashlib.sha256).digest())
        i += 1
    raw = b"".join(blocks)
    chars = [ALPHABET[raw[j] % len(ALPHABET)] for j in range(length)]
    if not any(c in SPECIAL for c in chars):
        chars[raw[length] % length] = SPECIAL[raw[length + 1] % len(SPECIAL)]
    return "".join(chars)

def unique(directory, name):
    base, ext = os.path.splitext(name)
    p, i = os.path.join(directory, name), 1
    while os.path.exists(p):
        p = os.path.join(directory, f"{base}_{i}{ext}")
        i += 1
    return p

def encrypt_file(input_path, key):
    os.makedirs(PASTA_DESCRIP, exist_ok=True)
    with open(input_path, "rb") as f:
        token = Fernet(key).encrypt(f.read()).decode()
    name, stem = os.path.basename(input_path), os.path.splitext(os.path.basename(input_path))[0]

    enc_path = unique(PASTA_CRIP, f"{stem}_encrypted.txt")
    with open(enc_path, "w", encoding="utf-8") as f:
        f.write(f"{MARKER}\noriginal_name: {name}\n---\n{token}")

    pwd = gen_password(token, key)
    pwd_path = unique(PASTA_CRIP, f"{stem}_senha.txt")
    with open(pwd_path, "w", encoding="utf-8") as f:
        f.write(f"Arquivo original : {name}\nCriptografado    : {os.path.basename(enc_path)}\n"
                f"Senha (16 chars) : {pwd}\nGerada em        : {datetime.now():%Y-%m-%d %H:%M:%S}\n")
    return enc_path, pwd

def decrypt_file(input_path, key):
    os.makedirs(PASTA_DESCRIP, exist_ok=True)
    with open(input_path, "r", encoding="utf-8") as f:
        if f.readline().strip() != MARKER:
            raise ValueError("Formato inválido")
        original = os.path.basename(f.readline().split(":", 1)[1].strip())
        f.readline()
        token = f.read().strip()

    data = Fernet(key).decrypt(token.encode())
    stem, ext = os.path.splitext(original)
    out = unique(PASTA_DESCRIP, f"{stem}_decrypted{ext}")
    with open(out, "wb") as f:
        f.write(data)
    return out, gen_password(token, key)

# ---------------- Interface Moderna ----------------
class App:
    def __init__(self, root):
        self.root = root
        root.title("Gerenciador de Arquivos Seguros")
        root.geometry("680x640")
        root.resizable(False, False)
        root.configure(bg=BG_MAIN)
        os.makedirs(PASTA_DESCRIP, exist_ok=True)

        self.file    = tk.StringVar(value="Nenhum arquivo selecionado")
        self.pwd_var = tk.StringVar(value="—")

        # Cabeçalho
        tk.Label(root, text="🔐 Criptografia de Arquivos", bg=BG_MAIN, fg=TEXT_MAIN,
                 font=("Segoe UI", 16, "bold"), pady=15).pack()

        # Caminhos (Pastas)
        info = tk.Frame(root, bg=BG_MAIN, padx=25)
        info.pack(fill="x")
        tk.Label(info, text=f"Criptografados: {PASTA_CRIP}", bg=BG_MAIN, fg=TEXT_MUTED,
                 font=("Segoe UI", 9)).pack(anchor="w")
        tk.Label(info, text=f"Descriptografados: {PASTA_DESCRIP}", bg=BG_MAIN, fg=TEXT_MUTED,
                 font=("Segoe UI", 9)).pack(anchor="w")

        # Seleção de Arquivo
        ff = tk.Frame(root, bg=BG_MAIN, padx=25, pady=15)
        ff.pack(fill="x")
        tk.Label(ff, text="Selecione o arquivo de origem:", bg=BG_MAIN, fg=TEXT_MAIN,
                 font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 5))
        
        row = tk.Frame(ff, bg=BG_MAIN)
        row.pack(fill="x")
        
        # Falso input moderno
        lbl_file_bg = tk.Frame(row, bg=BG_INPUT, highlightbackground=BORDER_COLOR, 
                               highlightthickness=1, bd=0)
        lbl_file_bg.pack(side="left", fill="x", expand=True, ipady=5)
        
        tk.Label(lbl_file_bg, textvariable=self.file, bg=BG_INPUT, fg=TEXT_MAIN, 
                 anchor="w", font=("Segoe UI", 10), padx=10).pack(fill="x")

        btn_pick = tk.Button(row, text="📂 Procurar", command=self.pick, bg=BTN_BLUE, fg="white",
                             font=("Segoe UI", 9, "bold"), padx=15, pady=6, relief="flat", 
                             cursor="hand2", activebackground=BTN_BLUE_H, activeforeground="white", bd=0)
        btn_pick.pack(side="left", padx=(10, 0))

        # Botões de Ação
        fa = tk.Frame(root, bg=BG_MAIN, pady=10)
        fa.pack()
        
        st = {"font": ("Segoe UI", 10, "bold"), "fg": "white", "relief": "flat", 
              "width": 22, "pady": 8, "cursor": "hand2", "bd": 0}

        self.btn_enc = tk.Button(fa, text="🔒 Criptografar", command=self.do_enc, 
                                 bg=BTN_GREEN, activebackground=BTN_GREEN_H, activeforeground="white", **st)
        self.btn_dec = tk.Button(fa, text="🔓 Descriptografar", command=self.do_dec, 
                                 bg=BTN_ORANGE, activebackground=BTN_ORANGE_H, activeforeground="white", **st)
        self.btn_auto = tk.Button(fa, text="🤖 Automático", command=self.do_auto, 
                                  bg=BTN_INDIGO, activebackground=BTN_INDIGO_H, activeforeground="white", **st)

        self.btn_enc.grid(row=0, column=0, padx=6, pady=4)
        self.btn_dec.grid(row=0, column=1, padx=6, pady=4)
        self.btn_auto.grid(row=1, column=0, columnspan=2, pady=(8, 0))

        # Exibição da Senha (Agora com botão de copiar)
        fp = tk.Frame(root, bg=BG_MAIN, padx=25, pady=5)
        fp.pack(fill="x")
        tk.Label(fp, text="🔑 Senha de referência gerada:", bg=BG_MAIN, fg=BTN_INDIGO,
                 font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 4))
        
        pwd_box = tk.Frame(fp, bg=BG_INPUT, highlightbackground=BORDER_COLOR, highlightthickness=1)
        pwd_box.pack(fill="x")
        
        # Label da senha
        tk.Label(pwd_box, textvariable=self.pwd_var, bg=BG_INPUT, fg=BTN_INDIGO,
                 font=("Consolas", 14, "bold"), padx=10, pady=8).pack(side="left", fill="x", expand=True)
                 
        # Botão de copiar
        self.btn_copy = tk.Button(pwd_box, text="📋 Copiar", command=self.copy_password,
                                  bg=BG_INPUT, fg=BTN_INDIGO, font=("Segoe UI", 9, "bold"),
                                  relief="flat", cursor="hand2", bd=0, 
                                  activebackground=BG_INPUT, activeforeground=BTN_INDIGO_H)
        self.btn_copy.pack(side="right", padx=10)

        # Log de Operações
        fl = tk.Frame(root, bg=BG_MAIN, padx=25, pady=10)
        fl.pack(fill="both", expand=True)
        tk.Label(fl, text="Log do sistema:", bg=BG_MAIN, fg=TEXT_MAIN,
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(0, 5))
        
        self.log = scrolledtext.ScrolledText(fl, height=10, font=("Consolas", 9),
                                             bg="#1E1E1E", fg="#D4D4D4", insertbackground="white",
                                             relief="flat", bd=0)
        self.log.pack(fill="both", expand=True)
        self.log.configure(state="disabled")

        self.write(f"🔑 Chave mestre: {KEY_FILE}")
        self.write(f"⚠ Mantenha a chave em local seguro. Sem ela, os arquivos não podem ser recuperados.\n")

    def write(self, msg):
        self.log.configure(state="normal")
        self.log.insert("end", msg + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def copy_password(self):
        pwd = self.pwd_var.get()
        if pwd and pwd != "—":
            self.root.clipboard_clear()
            self.root.clipboard_append(pwd)
            self.write("📋 Senha copiada para a área de transferência.")
            
            # Feedback visual no botão
            self.btn_copy.configure(text="✔ Copiado!", fg=BTN_GREEN)
            self.root.after(1500, self.reset_copy_btn)
        else:
            messagebox.showwarning("Aviso", "Nenhuma senha gerada para copiar.")

    def reset_copy_btn(self):
        self.btn_copy.configure(text="📋 Copiar", fg=BTN_INDIGO)

    def pick(self):
        p = filedialog.askopenfilename(
            initialdir=PASTA_CRIP if os.path.isdir(PASTA_CRIP) else None,
            filetypes=[("Suportados", "*.pdf *.txt"), ("Todos", "*.*")],
        )
        if p:
            self.file.set(p)
            self.write(f"📂 Selecionado: {os.path.basename(p)}")

    def _toggle(self, on):
        state = "normal" if on else "disabled"
        for b in (self.btn_enc, self.btn_dec, self.btn_auto):
            b.configure(state=state)
            b.configure(bg=b.cget("bg") if on else BORDER_COLOR)

    def _path(self):
        p = self.file.get()
        if not p or p == "Nenhum arquivo selecionado" or not os.path.isfile(p):
            messagebox.showwarning("Aviso", "Selecione um arquivo válido.")
            return None
        return p

    def _run(self, fn):
        self._toggle(False)
        def worker():
            try:
                out, pwd = fn()
                self.root.after(0, lambda: self._done(out, pwd))
            except Exception as e:
                self.root.after(0, lambda: self._fail(str(e)))
        threading.Thread(target=worker, daemon=True).start()

    def _done(self, out, pwd):
        self.pwd_var.set(pwd)
        self.write(f"✔ Sucesso: {os.path.basename(out)}\n🔑 Senha: {pwd}")
        messagebox.showinfo("Concluído", f"Arquivo salvo em:\n{out}\n\nSenha gerada: {pwd}")
        try:
            if sys.platform.startswith("win"):
                os.startfile(os.path.dirname(out))
            elif sys.platform == "darwin":
                os.system(f'open "{os.path.dirname(out)}"')
            else:
                os.system(f'xdg-open "{os.path.dirname(out)}"')
        except Exception:
            pass
        self._toggle(True)

    def _fail(self, e):
        self.write(f"❌ Erro: {e}")
        messagebox.showerror("Erro", e)
        self._toggle(True)

    def do_enc(self):
        p = self._path()
        if not p or is_encrypted(p): return
        self._run(lambda: encrypt_file(p, get_key()))

    def do_dec(self):
        p = self._path()
        if not p or not is_encrypted(p): return
        self._run(lambda: decrypt_file(p, get_key()))

    def do_auto(self):
        p = self._path()
        if not p: return
        fn = decrypt_file if is_encrypted(p) else encrypt_file
        self._run(lambda: fn(p, get_key()))

if __name__ == "__main__":
    root = tk.Tk()
    # Melhora a renderização em telas de alta resolução (Windows)
    try:
        from ctypes import windll
        windll.shcore.SetProcessDpiAwareness(1)
    except:
        pass
    
    App(root)
    root.mainloop()
    