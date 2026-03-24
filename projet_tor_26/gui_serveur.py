# gui_serveur.py — Interface graphique Serveur TOR (RSA + AES)
import tkinter as tk
from tkinter import scrolledtext
import threading
import sys, io
from datetime import datetime

from TOR_serveur_v3 import Serveur
from TOR_annuaire_v3 import annuaire_global


class ServeurGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🖥️  Serveur TOR — Chiffré RSA+AES")
        self.root.geometry("720x580")
        self.root.resizable(True, True)
        self.root.configure(bg="#1e1e2e")

        self.serveur = None
        self.running = False
        self._build_ui()

    # ──────────────────────────────────────────── UI ──
    def _build_ui(self):
        # ── Titre ──
        tk.Label(self.root, text="🖥️  Serveur TOR Chiffré",
                 font=("Helvetica", 16, "bold"),
                 bg="#1e1e2e", fg="#cdd6f4").pack(pady=(12, 4))

        # ── Config ──
        cfg = tk.Frame(self.root, bg="#313244", padx=14, pady=10)
        cfg.pack(fill=tk.X, padx=20, pady=6)

        tk.Label(cfg, text="Nom du serveur :", bg="#313244",
                 fg="#cdd6f4").grid(row=0, column=0, sticky="w", padx=6)
        self.nom_var = tk.StringVar(value="ServeurEcho")
        tk.Entry(cfg, textvariable=self.nom_var, width=20,
                 bg="#45475a", fg="#cdd6f4",
                 insertbackground="white").grid(row=0, column=1, padx=6)

        tk.Label(cfg, text="Port :", bg="#313244",
                 fg="#cdd6f4").grid(row=0, column=2, sticky="w", padx=6)
        self.port_var = tk.StringVar(value="5000")
        tk.Entry(cfg, textvariable=self.port_var, width=8,
                 bg="#45475a", fg="#cdd6f4",
                 insertbackground="white").grid(row=0, column=3, padx=6)

        # ── Boutons ──
        btn_row = tk.Frame(self.root, bg="#1e1e2e")
        btn_row.pack(pady=8)

        self.btn_start = tk.Button(
            btn_row, text="▶  Démarrer", command=self.demarrer,
            bg="#a6e3a1", fg="#1e1e2e",
            font=("Helvetica", 11, "bold"),
            padx=14, pady=5, relief=tk.FLAT, cursor="hand2")
        self.btn_start.pack(side=tk.LEFT, padx=6)

        self.btn_stop = tk.Button(
            btn_row, text="⛔  Arrêter", command=self.arreter,
            bg="#f38ba8", fg="#1e1e2e",
            font=("Helvetica", 11, "bold"),
            padx=14, pady=5, relief=tk.FLAT,
            state=tk.DISABLED, cursor="hand2")
        self.btn_stop.pack(side=tk.LEFT, padx=6)

        tk.Button(btn_row, text="🗑  Effacer logs", command=self.effacer,
                  bg="#89b4fa", fg="#1e1e2e",
                  font=("Helvetica", 11, "bold"),
                  padx=14, pady=5, relief=tk.FLAT,
                  cursor="hand2").pack(side=tk.LEFT, padx=6)

        # ── Status ──
        self.status_var = tk.StringVar(value="⚪  Serveur arrêté")
        tk.Label(self.root, textvariable=self.status_var,
                 bg="#1e1e2e", fg="#fab387",
                 font=("Helvetica", 11)).pack()

        # ── Logs ──
        tk.Label(self.root, text="📋  Logs du serveur",
                 bg="#1e1e2e", fg="#a6adc8",
                 font=("Helvetica", 10)).pack(anchor="w", padx=22, pady=(6, 0))

        self.logs = scrolledtext.ScrolledText(
            self.root, bg="#181825", fg="#cdd6f4",
            font=("Courier", 9), state="disabled", height=22,
            insertbackground="white")
        self.logs.pack(fill=tk.BOTH, expand=True, padx=20, pady=(4, 12))

        self.logs.tag_config("OK",   foreground="#a6e3a1")
        self.logs.tag_config("ERR",  foreground="#f38ba8")
        self.logs.tag_config("RECV", foreground="#89dceb")
        self.logs.tag_config("INFO", foreground="#fab387")

    # ──────────────────────────────────────────── LOGS ──
    def log(self, msg, tag="OK"):
        ts = datetime.now().strftime("%H:%M:%S")
        self.logs.configure(state="normal")
        self.logs.insert(tk.END, f"[{ts}]  {msg}\n", tag)
        self.logs.see(tk.END)
        self.logs.configure(state="disabled")

    def effacer(self):
        self.logs.configure(state="normal")
        self.logs.delete("1.0", tk.END)
        self.logs.configure(state="disabled")

    # ──────────────────────────────────────────── SERVEUR ──
    def demarrer(self):
        try:
            port = int(self.port_var.get())
        except ValueError:
            self.log("❌  Port invalide !", "ERR"); return

        nom = self.nom_var.get().strip()
        self.running = True
        self.btn_start.config(state=tk.DISABLED)
        self.btn_stop.config(state=tk.NORMAL)
        self.status_var.set("🟢  Serveur en écoute…")
        self.log(f"🚀  Démarrage de '{nom}' sur le port {port}…")

        def _run():
            try:
                self.serveur = Serveur(hote="0.0.0.0", port=port, nom=nom)

                cle_pem, _ = annuaire_global.obtenir_cle(nom)
                fichier = f"{nom}.pem"
                with open(fichier, "wb") as f:
                    f.write(cle_pem)

                self.root.after(0, lambda: self.log(
                    f"🔑  Clé RSA exportée → '{fichier}'"))
                self.root.after(0, lambda: self.log(
                    f"📡  En écoute sur 0.0.0.0:{port}"))

                # ── Patch pour logger chaque connexion ──
                _orig = self.serveur._traiter_client

                def _patched(sock):
                    try:
                        addr = sock.getpeername()
                        label = f"{addr[0]}:{addr[1]}"
                    except Exception:
                        label = "inconnu"

                    buf = io.StringIO()
                    old = sys.stdout
                    sys.stdout = buf
                    try:
                        result = _orig(sock)
                    finally:
                        sys.stdout = old

                    output = buf.getvalue()
                    self.root.after(0, lambda a=label: self.log(
                        f"📨  Connexion depuis {a}", "RECV"))
                    for line in output.strip().splitlines():
                        l = line.strip()
                        if l:
                            tag = "INFO" if "reçu" in l.lower() else "OK"
                            self.root.after(0, lambda ln=l, t=tag: self.log(f"   {ln}", t))
                    return result

                self.serveur._traiter_client = _patched

                old_stdout = sys.stdout
                sys.stdout = _GUIStream(self.root, self.log)
                try:
                    self.serveur.demarrer()
                finally:
                    sys.stdout = old_stdout

            except OSError as e:
                self.root.after(0, lambda: self.log(f"❌  {e}", "ERR"))
            finally:
                self.running = False
                self.root.after(0, self._stopped)

        threading.Thread(target=_run, daemon=True).start()

    def arreter(self):
        self.log("🛑  Arrêt demandé…", "ERR")
        if self.serveur:
            try:
                self.serveur._socket_serveur.close()
            except Exception:
                pass
        self._stopped()

    def _stopped(self):
        self.btn_start.config(state=tk.NORMAL)
        self.btn_stop.config(state=tk.DISABLED)
        self.status_var.set("⚪  Serveur arrêté")
        self.log("🔴  Serveur arrêté.", "ERR")


class _GUIStream:
    """Redirige stdout vers le widget de log."""
    def __init__(self, root, log_fn):
        self.root = root
        self.log_fn = log_fn
        self._buf = ""

    def write(self, text):
        self._buf += text
        if "\n" in self._buf:
            lines = self._buf.split("\n")
            for l in lines[:-1]:
                if l.strip():
                    ln = l.strip()
                    tag = "RECV" if "reçu" in ln.lower() else "INFO"
                    self.root.after(0, lambda t=ln, g=tag: self.log_fn(t, g))
            self._buf = lines[-1]

    def flush(self):
        pass


if __name__ == "__main__":
    root = tk.Tk()
    ServeurGUI(root)
    root.mainloop()
