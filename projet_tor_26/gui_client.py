# gui_client.py — Interface graphique Client TOR (RSA + AES)
import tkinter as tk
from tkinter import scrolledtext, filedialog
import threading
import sys, io, os, hashlib
from datetime import datetime

from TOR_annuaire_v3 import annuaire_global


class ClientGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("📡  Client TOR — Chiffré RSA+AES")
        self.root.geometry("720x620")
        self.root.resizable(True, True)
        self.root.configure(bg="#1e1e2e")

        self.pem_ok = False
        self._build_ui()

    # ──────────────────────────────────────────── UI ──
    def _build_ui(self):
        # ── Titre ──
        tk.Label(self.root, text="📡  Client TOR Chiffré",
                 font=("Helvetica", 16, "bold"),
                 bg="#1e1e2e", fg="#cdd6f4").pack(pady=(12, 4))

        # ── Connexion ──
        conn = tk.LabelFrame(self.root, text="  🔌  Connexion  ",
                             bg="#313244", fg="#89b4fa",
                             font=("Helvetica", 10, "bold"),
                             padx=12, pady=10)
        conn.pack(fill=tk.X, padx=20, pady=6)

        tk.Label(conn, text="Adresse IP :", bg="#313244",
                 fg="#cdd6f4").grid(row=0, column=0, sticky="w", padx=6, pady=4)
        self.ip_var = tk.StringVar(value="127.0.0.1")
        tk.Entry(conn, textvariable=self.ip_var, width=18,
                 bg="#45475a", fg="#cdd6f4",
                 insertbackground="white").grid(row=0, column=1, padx=6)

        tk.Label(conn, text="Port :", bg="#313244",
                 fg="#cdd6f4").grid(row=0, column=2, sticky="w", padx=6)
        self.port_var = tk.StringVar(value="5000")
        tk.Entry(conn, textvariable=self.port_var, width=8,
                 bg="#45475a", fg="#cdd6f4",
                 insertbackground="white").grid(row=0, column=3, padx=6)

        tk.Label(conn, text="Nom serveur :", bg="#313244",
                 fg="#cdd6f4").grid(row=1, column=0, sticky="w", padx=6, pady=4)
        self.nom_var = tk.StringVar(value="ServeurEcho")
        tk.Entry(conn, textvariable=self.nom_var, width=18,
                 bg="#45475a", fg="#cdd6f4",
                 insertbackground="white").grid(row=1, column=1, padx=6)

        tk.Label(conn, text="Fichier .pem :", bg="#313244",
                 fg="#cdd6f4").grid(row=1, column=2, sticky="w", padx=6)
        self.pem_var = tk.StringVar(value="ServeurEcho.pem")
        tk.Entry(conn, textvariable=self.pem_var, width=18,
                 bg="#45475a", fg="#cdd6f4",
                 insertbackground="white").grid(row=1, column=3, padx=6)
        tk.Button(conn, text="📂", command=self._browse_pem,
                  bg="#89b4fa", fg="#1e1e2e",
                  relief=tk.FLAT, padx=4,
                  cursor="hand2").grid(row=1, column=4, padx=2)

        tk.Button(conn, text="🔗  Charger la clé publique",
                  command=self.charger_cle,
                  bg="#a6e3a1", fg="#1e1e2e",
                  font=("Helvetica", 10, "bold"),
                  relief=tk.FLAT, padx=12, pady=4,
                  cursor="hand2").grid(row=2, column=0, columnspan=5,
                                       pady=(8, 2))

        # ── Status clé ──
        self.pem_status = tk.StringVar(value="⚪  Clé non chargée")
        tk.Label(self.root, textvariable=self.pem_status,
                 bg="#1e1e2e", fg="#fab387",
                 font=("Helvetica", 10)).pack(pady=(0, 4))

        # ── Message ──
        msg_frame = tk.LabelFrame(self.root, text="  ✉️  Message  ",
                                  bg="#313244", fg="#cba6f7",
                                  font=("Helvetica", 10, "bold"),
                                  padx=12, pady=10)
        msg_frame.pack(fill=tk.X, padx=20, pady=4)

        self.msg_var = tk.StringVar()
        msg_entry = tk.Entry(msg_frame, textvariable=self.msg_var,
                             width=52, bg="#45475a", fg="#cdd6f4",
                             font=("Helvetica", 11),
                             insertbackground="white")
        msg_entry.pack(side=tk.LEFT, fill=tk.X, expand=True,
                       padx=(0, 8), pady=2)
        msg_entry.bind("<Return>", lambda _: self.envoyer())

        tk.Button(msg_frame, text="📤  Envoyer",
                  command=self.envoyer,
                  bg="#cba6f7", fg="#1e1e2e",
                  font=("Helvetica", 11, "bold"),
                  relief=tk.FLAT, padx=12, pady=3,
                  cursor="hand2").pack(side=tk.LEFT)

        # ── Raccourcis ──
        quick = tk.Frame(self.root, bg="#1e1e2e")
        quick.pack(fill=tk.X, padx=20, pady=(2, 0))

        tk.Label(quick, text="Raccourcis :", bg="#1e1e2e",
                 fg="#a6adc8").pack(side=tk.LEFT)
        for label, cmd in [("👋 Bonjour", "Bonjour serveur !"),
                           ("🔒 Test AES", "AES-GCM assure confidentialité ET intégrité."),
                           ("❌ QUIT",    "QUIT")]:
            tk.Button(quick, text=label,
                      command=lambda c=cmd: self._quick(c),
                      bg="#45475a", fg="#cdd6f4",
                      relief=tk.FLAT, padx=8,
                      cursor="hand2").pack(side=tk.LEFT, padx=3)

        tk.Button(quick, text="🗑  Effacer",
                  command=self.effacer,
                  bg="#45475a", fg="#cdd6f4",
                  relief=tk.FLAT, padx=8,
                  cursor="hand2").pack(side=tk.RIGHT, padx=3)

        # ── Logs ──
        tk.Label(self.root, text="📋  Logs",
                 bg="#1e1e2e", fg="#a6adc8",
                 font=("Helvetica", 10)).pack(anchor="w",
                                              padx=22, pady=(6, 0))

        self.logs = scrolledtext.ScrolledText(
            self.root, bg="#181825", fg="#cdd6f4",
            font=("Courier", 9), state="disabled", height=16,
            insertbackground="white")
        self.logs.pack(fill=tk.BOTH, expand=True, padx=20, pady=(4, 12))

        self.logs.tag_config("SEND", foreground="#a6e3a1")
        self.logs.tag_config("RECV", foreground="#89dceb")
        self.logs.tag_config("ERR",  foreground="#f38ba8")
        self.logs.tag_config("INFO", foreground="#fab387")

    # ──────────────────────────────────────────── UTILS ──
    def log(self, msg, tag="INFO"):
        ts = datetime.now().strftime("%H:%M:%S")
        self.logs.configure(state="normal")
        self.logs.insert(tk.END, f"[{ts}]  {msg}\n", tag)
        self.logs.see(tk.END)
        self.logs.configure(state="disabled")

    def effacer(self):
        self.logs.configure(state="normal")
        self.logs.delete("1.0", tk.END)
        self.logs.configure(state="disabled")

    def _browse_pem(self):
        path = filedialog.askopenfilename(
            title="Sélectionner le fichier PEM",
            filetypes=[("PEM files", "*.pem"), ("All files", "*.*")])
        if path:
            self.pem_var.set(path)

    def _quick(self, msg):
        self.msg_var.set(msg)
        self.envoyer()

    # ──────────────────────────────────────────── CLE ──
    def charger_cle(self):
        path = self.pem_var.get().strip()
        nom  = self.nom_var.get().strip()

        if not os.path.exists(path):
            self.log(f"❌  Fichier '{path}' introuvable. "
                     "Lance d'abord le serveur !", "ERR")
            self.pem_status.set("❌  Fichier PEM introuvable")
            return

        try:
            with open(path, "rb") as f:
                cle_pem = f.read()
            annuaire_global.enregistrer(nom, cle_pem)
            fp = hashlib.sha256(cle_pem).hexdigest()
            self.log(f"✅  Clé publique chargée pour '{nom}'")
            self.log(f"🔑  Fingerprint : {fp[:32]}…")
            self.pem_status.set(f"✅  Clé chargée — {nom}")
            self.pem_ok = True
        except Exception as e:
            self.log(f"❌  Erreur chargement PEM : {e}", "ERR")
            self.pem_status.set("❌  Erreur chargement")

    # ──────────────────────────────────────────── ENVOI ──
    def envoyer(self):
        if not self.pem_ok:
            self.log("⚠️   Charge d'abord la clé publique !", "ERR"); return

        message = self.msg_var.get().strip()
        if not message:
            self.log("⚠️   Message vide !", "ERR"); return

        try:
            ip   = self.ip_var.get().strip()
            port = int(self.port_var.get().strip())
            nom  = self.nom_var.get().strip()
        except ValueError:
            self.log("❌  Port invalide !", "ERR"); return

        self.msg_var.set("")
        self.log(f"📤  Envoi vers {ip}:{port}  →  « {message} »", "SEND")

        def _thread():
            try:
                from TOR_client_v3 import Client
                client = Client(hote=ip, port=port, nom_serveur=nom)

                buf = io.StringIO()
                old = sys.stdout
                sys.stdout = buf
                try:
                    client.envoyer(message)
                finally:
                    sys.stdout = old

                for line in buf.getvalue().strip().splitlines():
                    l = line.strip()
                    if not l:
                        continue
                    if "Réponse" in l or "ECHO" in l:
                        self.root.after(0, lambda t=l: self.log(f"📥  {t}", "RECV"))
                    elif "✘" in l or "Erreur" in l.lower():
                        self.root.after(0, lambda t=l: self.log(f"❌  {t}", "ERR"))
                    else:
                        self.root.after(0, lambda t=l: self.log(f"   {t}", "INFO"))

            except ConnectionRefusedError:
                self.root.after(0, lambda: self.log(
                    f"❌  Connexion refusée — serveur allumé sur {ip}:{port} ?", "ERR"))
            except Exception as e:
                self.root.after(0, lambda: self.log(f"❌  {e}", "ERR"))

        threading.Thread(target=_thread, daemon=True).start()


if __name__ == "__main__":
    root = tk.Tk()
    ClientGUI(root)
    root.mainloop()
