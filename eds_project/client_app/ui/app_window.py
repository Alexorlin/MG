import os
import shutil
import json
import base64
import hashlib
import customtkinter as ctk
from customtkinter import filedialog
from core.crypto_engine import CryptoEngine
from core.file_utils import FileUtils
from api_client import ApiClient

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")


class AppWindow(ctk.CTk):
    """Головне графічне вікно клієнтського додатку СЕД."""

    ALGO_DESCRIPTIONS = {
        "Ed25519": "⚡ Ed25519 (RFC 8032): Найшвидший сучасний алгоритм. Підпис: 64 байти. Детермінований та стійкий до бічних атак.",
        "ECDSA": "🛡️ ECDSA (NIST P-256 / secp256r1): Банківський та державний стандарт на еліптичних кривих. Підпис: ~71 байт.",
        "RSA-2048": "🏛️ RSA-2048 (PSS + SHA-256): Класичний базовий стандарт для зворотної сумісності. Підпис: 256 байт.",
        "RSA-4096": "🔒 RSA-4096 (PSS + SHA-256): Підвищена криптостійкість для довготривалого архівного зберігання. Підпис: 512 байт."
    }

    def __init__(self):
        super().__init__()
        self.title("СЕД: Програмний модуль електронного підпису v2.0")
        self.geometry("950x740")
        self.minsize(850, 650)

        self.api = ApiClient()
        self._setup_header()

        self.tabview = ctk.CTkTabview(self, corner_radius=12)
        self.tabview.pack(padx=20, pady=(5, 15), fill="both", expand=True)

        self.tab_gen = self.tabview.add("🔑 Ключі (PKI)")
        self.tab_sign = self.tabview.add("✍️ Підписання")
        self.tab_verify = self.tabview.add("🔍 Верифікація")
        self.tab_server = self.tabview.add("🌐 Сервер та TSA")
        self.tab_certs = self.tabview.add("📜 Сертифікати й Аудит")
        self.tab_history = self.tabview.add("📂 Мої документи")
        self.tab_settings = self.tabview.add("⚙️ Налаштування")

        self.setup_gen_tab()
        self.setup_sign_tab()
        self.setup_verify_tab()
        self.setup_server_tab()
        self.setup_certs_tab()
        self.setup_history_tab()
        self.setup_settings_tab()

    def _setup_header(self):
        header_frame = ctk.CTkFrame(self, height=65, corner_radius=12, fg_color=("#dce4ee", "#1a212d"))
        header_frame.pack(padx=20, pady=(15, 5), fill="x")

        title_box = ctk.CTkFrame(header_frame, fg_color="transparent")
        title_box.pack(side="left", padx=15, pady=8)

        lbl_title = ctk.CTkLabel(
            title_box,
            text="🛡️ Криптографічний Модуль ЕЦП (Zero-Trust PKI)",
            font=("Segoe UI", 18, "bold")
        )
        lbl_title.pack(anchor="w")

        lbl_sub = ctk.CTkLabel(
            title_box,
            text="AES-256 Key Protection  •  Multi-Algorithm (Ed25519 / ECDSA / RSA)  •  X.509 CA  •  RFC 3161 TSA  •  Hash-Chain",
            font=("Segoe UI", 11),
            text_color=("gray30", "gray70")
        )
        lbl_sub.pack(anchor="w")

        self.lbl_header_user = ctk.CTkLabel(
            header_frame,
            text="🔴 Статус: Не авторизовано",
            font=("Segoe UI", 12, "bold"),
            text_color="#ff6b6b",
            padx=15
        )
        self.lbl_header_user.pack(side="right", padx=15)

    def _update_header_auth(self):
        if self.api.token and self.api.username:
            self.lbl_header_user.configure(
                text=f"🟢 Користувач: {self.api.username}",
                text_color="#51cf66"
            )
        else:
            self.lbl_header_user.configure(
                text="🔴 Статус: Не авторизовано",
                text_color="#ff6b6b"
            )

    # Вкладка 1: Генерація ключів
    def setup_gen_tab(self):
        container = ctk.CTkFrame(self.tab_gen, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=20, pady=10)

        card_algo = ctk.CTkFrame(container, corner_radius=10)
        card_algo.pack(fill="x", pady=8, padx=5)

        ctk.CTkLabel(
            card_algo,
            text="1. Оберіть криптографічний алгоритм генерації ключів:",
            font=("Segoe UI", 14, "bold")
        ).pack(anchor="w", padx=15, pady=(12, 5))

        self.seg_algo = ctk.CTkSegmentedButton(
            card_algo,
            values=["Ed25519", "ECDSA", "RSA-2048", "RSA-4096"],
            command=self._on_algo_change,
            font=("Segoe UI", 13, "bold"),
            height=36
        )
        self.seg_algo.pack(fill="x", padx=15, pady=8)
        self.seg_algo.set("Ed25519")

        self.lbl_algo_desc = ctk.CTkLabel(
            card_algo,
            text=self.ALGO_DESCRIPTIONS["Ed25519"],
            font=("Segoe UI", 12),
            text_color=("#1f538d", "#66b2ff"),
            wraplength=780,
            justify="left"
        )
        self.lbl_algo_desc.pack(anchor="w", padx=15, pady=(0, 12))

        card_pin = ctk.CTkFrame(container, corner_radius=10)
        card_pin.pack(fill="x", pady=8, padx=5)

        ctk.CTkLabel(
            card_pin,
            text="2. Захист закритого ключа шифруванням AES-256 (PKCS#8):",
            font=("Segoe UI", 14, "bold")
        ).pack(anchor="w", padx=15, pady=(12, 5))

        self.var_use_pin = ctk.BooleanVar(value=True)
        self.chk_use_pin = ctk.CTkCheckBox(
            card_pin,
            text="Зашифрувати приватний ключ PIN-кодом / паролем (рекомендовано стандартом Zero-Trust)",
            variable=self.var_use_pin,
            command=self._toggle_gen_pin,
            font=("Segoe UI", 12)
        )
        self.chk_use_pin.pack(anchor="w", padx=15, pady=5)

        pin_row = ctk.CTkFrame(card_pin, fg_color="transparent")
        pin_row.pack(fill="x", padx=15, pady=(5, 15))

        self.entry_gen_pin = ctk.CTkEntry(
            pin_row,
            placeholder_text="Введіть секретний PIN-код або пароль для захисту ключа...",
            show="•",
            width=360,
            height=35
        )
        self.entry_gen_pin.pack(side="left", padx=(0, 10))

        self.entry_gen_pin_confirm = ctk.CTkEntry(
            pin_row,
            placeholder_text="Повторіть PIN-код...",
            show="•",
            width=250,
            height=35
        )
        self.entry_gen_pin_confirm.pack(side="left")

        card_action = ctk.CTkFrame(container, corner_radius=10)
        card_action.pack(fill="x", pady=8, padx=5)

        btn_gen = ctk.CTkButton(
            card_action,
            text="⚡ Згенерувати ключову пару та зберегти у папку",
            command=self.generate_keys,
            height=45,
            font=("Segoe UI", 14, "bold"),
            fg_color="#1f538d",
            hover_color="#14375e"
        )
        btn_gen.pack(pady=15, padx=20, fill="x")

        self.lbl_gen_status = ctk.CTkLabel(
            card_action,
            text="Оберіть параметри та натисніть кнопку для створення особистої пари ключів.",
            font=("Segoe UI", 12),
            wraplength=780
        )
        self.lbl_gen_status.pack(pady=(0, 15), padx=15)

    def _on_algo_change(self, selected_algo: str):
        desc = self.ALGO_DESCRIPTIONS.get(selected_algo, "")
        self.lbl_algo_desc.configure(text=desc)

    def _toggle_gen_pin(self):
        if self.var_use_pin.get():
            self.entry_gen_pin.configure(state="normal")
            self.entry_gen_pin_confirm.configure(state="normal")
        else:
            self.entry_gen_pin.delete(0, "end")
            self.entry_gen_pin_confirm.delete(0, "end")
            self.entry_gen_pin.configure(state="disabled")
            self.entry_gen_pin_confirm.configure(state="disabled")

    def generate_keys(self):
        algo = self.seg_algo.get()
        password = None

        if self.var_use_pin.get():
            pin1 = self.entry_gen_pin.get().strip()
            pin2 = self.entry_gen_pin_confirm.get().strip()
            if not pin1:
                self.lbl_gen_status.configure(
                    text="❌ Введіть PIN-код/пароль для шифрування або зніміть галочку захисту!",
                    text_color="#ff6b6b"
                )
                return
            if pin1 != pin2:
                self.lbl_gen_status.configure(
                    text="❌ Введені PIN-коди не збігаються! Перевірте правильність.",
                    text_color="#ff6b6b"
                )
                return
            password = pin1

        save_dir = filedialog.askdirectory(title="Оберіть папку для збереження ключів")
        if not save_dir:
            return

        self.lbl_gen_status.configure(text=f"⏳ Генерація ключів за алгоритмом {algo}...", text_color="yellow")
        self.update()

        try:
            priv_pem, pub_pem = CryptoEngine.generate_key_pair(algorithm=algo, password=password)
            priv_path = os.path.join(save_dir, "private_key.pem")
            pub_path = os.path.join(save_dir, "public_key.pem")

            FileUtils.save_key_to_file(priv_path, priv_pem)
            FileUtils.save_key_to_file(pub_path, pub_pem)

            enc_info = "Зашифровано AES-256 (PKCS#8)" if password else "Без шифрування"
            self.lbl_gen_status.configure(
                text=f"✅ УСПІХ! Ключі ({algo} | {enc_info}) збережено у:\n📁 {save_dir}",
                text_color="#51cf66"
            )
        except Exception as e:
            self.lbl_gen_status.configure(text=f"❌ Помилка генерації: {e}", text_color="#ff6b6b")

    # Вкладка 2: Підписання та мультипідпис
    def setup_sign_tab(self):
        self.sign_doc_path = None
        self.sign_key_path = None
        self.sign_cert_path = None

        container = ctk.CTkFrame(self.tab_sign, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=16, pady=2)

        card_files = ctk.CTkFrame(container, corner_radius=10)
        card_files.pack(fill="x", pady=3, padx=5)

        ctk.CTkLabel(
            card_files,
            text="1. Вибір електронного документа та особистого ключа:",
            font=("Segoe UI", 13, "bold")
        ).pack(anchor="w", padx=15, pady=(6, 2))

        row_doc = ctk.CTkFrame(card_files, fg_color="transparent")
        row_doc.pack(fill="x", padx=15, pady=2)
        ctk.CTkButton(row_doc, text="📄 Обрати документ", width=200, height=28, command=self.select_doc_to_sign).pack(side="left")
        self.lbl_sign_doc = ctk.CTkLabel(row_doc, text="Файл не обрано", text_color="gray")
        self.lbl_sign_doc.pack(side="left", padx=15)

        row_key = ctk.CTkFrame(card_files, fg_color="transparent")
        row_key.pack(fill="x", padx=15, pady=2)
        ctk.CTkButton(row_key, text="🔐 Обрати private_key.pem", width=200, height=28, command=self.select_priv_key).pack(side="left")
        self.lbl_sign_key = ctk.CTkLabel(row_key, text="Ключ не обрано", text_color="gray")
        self.lbl_sign_key.pack(side="left", padx=15)

        row_pin = ctk.CTkFrame(card_files, fg_color="transparent")
        row_pin.pack(fill="x", padx=15, pady=(2, 6))
        ctk.CTkLabel(row_pin, text="🔑 PIN-код / Пароль ключа:", width=200, anchor="w").pack(side="left")
        self.entry_sign_pin = ctk.CTkEntry(
            row_pin,
            placeholder_text="Введіть PIN-код (якщо ключ зашифровано AES-256)...",
            show="•",
            height=28,
            width=360
        )
        self.entry_sign_pin.pack(side="left", padx=15)

        card_mode = ctk.CTkFrame(container, corner_radius=10)
        card_mode.pack(fill="x", pady=3, padx=5)

        ctk.CTkLabel(
            card_mode,
            text="2. Формат цифрового підпису:",
            font=("Segoe UI", 13, "bold")
        ).pack(anchor="w", padx=15, pady=(6, 2))

        self.seg_sign_mode = ctk.CTkSegmentedButton(
            card_mode,
            values=["Одинарний підпис (.sig)", "Колективний Мультипідпис (.multisig.json)"],
            command=self._on_sign_mode_change,
            height=30
        )
        self.seg_sign_mode.pack(fill="x", padx=15, pady=3)
        self.seg_sign_mode.set("Одинарний підпис (.sig)")

        self.frame_multisig_opts = ctk.CTkFrame(card_mode, fg_color="transparent")

        row_ms1 = ctk.CTkFrame(self.frame_multisig_opts, fg_color="transparent")
        row_ms1.pack(fill="x", padx=15, pady=2)
        self.entry_ms_signer = ctk.CTkEntry(row_ms1, placeholder_text="Ваш логін (напр. Alex_dev)", height=28, width=240)
        self.entry_ms_signer.pack(side="left", padx=(0, 10))

        self.opt_ms_role = ctk.CTkOptionMenu(
            row_ms1,
            values=["Автор документа", "Погоджувач (Юрист)", "Головний бухгалтер", "Генеральний директор"],
            height=28,
            width=220
        )
        self.opt_ms_role.pack(side="left", padx=(0, 10))

        ctk.CTkButton(row_ms1, text="📜 Додати сертифікат (.crt)", height=28, width=190, command=self.select_sign_cert).pack(side="left")

        row_ms2 = ctk.CTkFrame(self.frame_multisig_opts, fg_color="transparent")
        row_ms2.pack(fill="x", padx=15, pady=2)
        ctk.CTkLabel(
            row_ms2,
            text="👥 Дозволені співпідписанти (логіни):",
            font=("Segoe UI", 12, "bold")
        ).pack(side="left", padx=(0, 10))
        self.entry_ms_allowed = ctk.CTkEntry(
            row_ms2,
            placeholder_text="Напр.: Boris_dev, ivan_dir (вказує автор при 1-му підписі; для 2-го залиште порожнім)",
            height=28,
            width=450
        )
        self.entry_ms_allowed.pack(side="left", fill="x", expand=True)

        self.lbl_ms_cert = ctk.CTkLabel(
            self.frame_multisig_opts,
            text="💡 Мультипідпис автоматично синхронізується з БД PostgreSQL за хешем документа (без ручного пошуку .json!).",
            font=("Segoe UI", 11),
            text_color="gray"
        )
        self.lbl_ms_cert.pack(anchor="w", padx=15, pady=(0, 4))

        card_act = ctk.CTkFrame(container, corner_radius=10)
        card_act.pack(fill="x", pady=3, padx=5)

        self.btn_sign = ctk.CTkButton(
            card_act,
            text="✍️ Накласти електронний цифровий підпис",
            command=self.sign_document,
            height=36,
            font=("Segoe UI", 13, "bold"),
            fg_color="#2b8a3e",
            hover_color="#1b5e20"
        )
        self.btn_sign.pack(pady=(6, 2), padx=20, fill="x")

        self.lbl_sign_status = ctk.CTkLabel(card_act, text="", font=("Segoe UI", 12, "bold"), wraplength=780)
        self.lbl_sign_status.pack(pady=(2, 6), padx=15)

    def _on_sign_mode_change(self, mode: str):
        if "Мультипідпис" in mode:
            self.frame_multisig_opts.pack(fill="x", pady=5)
        else:
            self.frame_multisig_opts.pack_forget()

    def select_doc_to_sign(self):
        path = filedialog.askopenfilename(title="Оберіть документ для підписання")
        if path:
            self.sign_doc_path = path
            size_kb = os.path.getsize(path) / 1024
            self.lbl_sign_doc.configure(
                text=f"✅ {os.path.basename(path)} ({size_kb:.1f} KB)",
                text_color="#51cf66"
            )

    def select_priv_key(self):
        path = filedialog.askopenfilename(
            title="Оберіть приватний ключ",
            filetypes=[("PEM Keys", "*.pem"), ("All Files", "*.*")]
        )
        if path:
            self.sign_key_path = path
            try:
                raw = FileUtils.read_file_bytes(path)
                is_enc = CryptoEngine.is_key_encrypted(raw)
                enc_badge = "🔒 Захищено AES-256 (введіть PIN)" if is_enc else "🔓 Без пароля"
                self.lbl_sign_key.configure(
                    text=f"✅ {os.path.basename(path)} [{enc_badge}]",
                    text_color="#51cf66" if not is_enc else "#fcc419"
                )
            except Exception:
                self.lbl_sign_key.configure(text=f"Обрано: {os.path.basename(path)}", text_color="white")

    def select_sign_cert(self):
        path = filedialog.askopenfilename(
            title="Оберіть файл сертифіката X.509",
            filetypes=[("Certificate", "*.crt *.pem"), ("All Files", "*.*")]
        )
        if path:
            self.sign_cert_path = path
            self.lbl_ms_cert.configure(text=f"✅ Обрано сертифікат: {os.path.basename(path)}", text_color="#51cf66")

    def sign_document(self):
        if not self.sign_doc_path or not self.sign_key_path:
            self.lbl_sign_status.configure(text="❌ Будь ласка, оберіть документ та приватний ключ!", text_color="#ff6b6b")
            return

        pin = self.entry_sign_pin.get().strip() or None

        try:
            doc_bytes = FileUtils.read_file_bytes(self.sign_doc_path)
            key_bytes = FileUtils.read_file_bytes(self.sign_key_path)

            signature = CryptoEngine.sign_data(doc_bytes, key_bytes, password=pin)
            algo_used = CryptoEngine.get_key_algorithm(key_bytes, password=pin)
            mode = self.seg_sign_mode.get()

            if "Одинарний" in mode:
                save_dir = filedialog.askdirectory(title="Оберіть папку для збереження підписаного документа та .sig")
                if not save_dir:
                    return

                filename = os.path.basename(self.sign_doc_path)
                dest_doc_path = os.path.join(save_dir, filename)
                dest_sig_path = f"{dest_doc_path}.sig"

                if os.path.abspath(self.sign_doc_path) != os.path.abspath(dest_doc_path):
                    shutil.copy2(self.sign_doc_path, dest_doc_path)

                FileUtils.write_file_bytes(dest_sig_path, signature)
                self.lbl_sign_status.configure(
                    text=f"✅ Підпис ({algo_used}, {len(signature)} байт) успішно створено!\nЗбережено файл: {dest_sig_path}",
                    text_color="#51cf66"
                )
            else:
                cert_pem = None
                if self.sign_cert_path and os.path.exists(self.sign_cert_path):
                    cert_pem = FileUtils.read_file_bytes(self.sign_cert_path).decode("utf-8")
                elif self.api.token:
                    ok, cert_data = self.api.get_my_certificate()
                    if ok and isinstance(cert_data, dict):
                        cert_pem = cert_data.get("certificate_pem")

                if not cert_pem:
                    self.lbl_sign_status.configure(
                        text="❌ Для мультипідпису потрібен сертифікат X.509! Авторизуйтесь на сервері або оберіть файл .crt вручну.",
                        text_color="#ff6b6b"
                    )
                    return

                signer_name = self.entry_ms_signer.get().strip() or self.api.username or "user"
                role = self.opt_ms_role.get()
                allowed_str = self.entry_ms_allowed.get().strip() or None
                sig_b64 = base64.b64encode(signature).decode("ascii")
                auto_ms_path = f"{self.sign_doc_path}.multisig.json"

                if self.api.token:
                    ok, srv_res = self.api.sign_multisig_on_server(
                        doc_path=self.sign_doc_path,
                        signature_b64=sig_b64,
                        certificate_pem=cert_pem,
                        role=role,
                        allowed_signers=allowed_str
                    )
                    if not ok:
                        self.lbl_sign_status.configure(text=f"{srv_res}", text_color="#ff6b6b")
                        return

                    container = srv_res.get("multisig_container", {})
                    if container:
                        try:
                            with open(auto_ms_path, "w", encoding="utf-8") as f:
                                json.dump(container, f, indent=2, ensure_ascii=False)
                        except Exception:
                            pass

                    total_sigs = srv_res.get("total_signatures", 1)
                    signed_users = ", ".join(srv_res.get("signed_users", []))
                    pending_users = srv_res.get("pending_signers", [])
                    pending_str = f"⏳ Очікується підпис від: {', '.join(pending_users)}" if pending_users else "🎉 Усі призначені учасники підписали!"

                    self.lbl_sign_status.configure(
                        text=(
                            f"✅ Мультипідпис ({self.api.username} — {role}, {algo_used}) збережено в БД PostgreSQL!\n"
                            f"Всього підписів у БД: {total_sigs} ({signed_users})  |  {pending_str}"
                        ),
                        text_color="#51cf66"
                    )
                else:
                    container = FileUtils.append_to_multisig_file(
                        doc_bytes=doc_bytes,
                        multisig_path=auto_ms_path,
                        signer_name=signer_name,
                        role=role,
                        certificate_pem=cert_pem,
                        signature_bytes=signature
                    )
                    total_sigs = len(container.get("signatures", []))
                    self.lbl_sign_status.configure(
                        text=f"✅ Офлайн-мультипідпис ({signer_name} — {role}, {algo_used}) додано!\n"
                             f"Всього підписів у контейнері: {total_sigs} | Файл: {os.path.basename(auto_ms_path)}",
                        text_color="#51cf66"
                    )

        except Exception as e:
            self.lbl_sign_status.configure(text=f"❌ Помилка підписання: {e}", text_color="#ff6b6b")

    # Вкладка 3: Локальна верифікація
    def setup_verify_tab(self):
        self.ver_doc_path = None
        self.ver_sig_path = None
        self.ver_key_path = None

        container = ctk.CTkFrame(self.tab_verify, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=20, pady=10)

        card_files = ctk.CTkFrame(container, corner_radius=10)
        card_files.pack(fill="x", pady=8, padx=5)

        ctk.CTkLabel(
            card_files,
            text="Локальна криптографічна перевірка цілісності та автентичності документа:",
            font=("Segoe UI", 14, "bold")
        ).pack(anchor="w", padx=15, pady=(12, 8))

        r1 = ctk.CTkFrame(card_files, fg_color="transparent")
        r1.pack(fill="x", padx=15, pady=4)
        ctk.CTkButton(r1, text="1. Обрати оригінальний документ", width=240, command=lambda: self.set_ver_path('doc')).pack(side="left")
        self.lbl_ver_doc = ctk.CTkLabel(r1, text="Не обрано", text_color="gray")
        self.lbl_ver_doc.pack(side="left", padx=15)

        r2 = ctk.CTkFrame(card_files, fg_color="transparent")
        r2.pack(fill="x", padx=15, pady=4)
        ctk.CTkButton(r2, text="2. Обрати файл підпису (.sig)", width=240, command=lambda: self.set_ver_path('sig')).pack(side="left")
        self.lbl_ver_sig = ctk.CTkLabel(r2, text="Не обрано", text_color="gray")
        self.lbl_ver_sig.pack(side="left", padx=15)

        r3 = ctk.CTkFrame(card_files, fg_color="transparent")
        r3.pack(fill="x", padx=15, pady=(4, 12))
        ctk.CTkButton(r3, text="3. Обрати відкритий ключ (.pem)", width=240, command=lambda: self.set_ver_path('key')).pack(side="left")
        self.lbl_ver_key = ctk.CTkLabel(r3, text="Не обрано", text_color="gray")
        self.lbl_ver_key.pack(side="left", padx=15)

        btn_verify = ctk.CTkButton(
            container,
            text="🔍 Перевірити справжність цифрового підпису",
            command=self.verify_document,
            height=45,
            font=("Segoe UI", 14, "bold"),
            fg_color="#1f538d"
        )
        btn_verify.pack(fill="x", padx=5, pady=10)

        self.txt_ver_result = ctk.CTkTextbox(container, height=160, font=("Consolas", 13), corner_radius=10)
        self.txt_ver_result.pack(fill="both", expand=True, padx=5, pady=5)
        self.txt_ver_result.insert("1.0", "Оберіть 3 файли вище та натисніть 'Перевірити' для запуску математичної верифікації...")

    def set_ver_path(self, target: str):
        path = filedialog.askopenfilename()
        if not path:
            return
        name = os.path.basename(path)
        if target == 'doc':
            self.ver_doc_path = path
            self.lbl_ver_doc.configure(text=f"✅ {name}", text_color="#51cf66")
        elif target == 'sig':
            self.ver_sig_path = path
            self.lbl_ver_sig.configure(text=f"✅ {name}", text_color="#51cf66")
        elif target == 'key':
            self.ver_key_path = path
            self.lbl_ver_key.configure(text=f"✅ {name}", text_color="#51cf66")

    def verify_document(self):
        if not (self.ver_doc_path and self.ver_sig_path and self.ver_key_path):
            self.txt_ver_result.delete("1.0", "end")
            self.txt_ver_result.insert("1.0", "❌ ПОМИЛКА: Необхідно обрати всі 3 файли (документ, підпис, відкритий ключ)!")
            return

        try:
            doc_bytes = FileUtils.read_file_bytes(self.ver_doc_path)
            sig_bytes = FileUtils.read_file_bytes(self.ver_sig_path)
            key_bytes = FileUtils.read_file_bytes(self.ver_key_path)

            algo = CryptoEngine.get_key_algorithm(key_bytes)
            is_valid = CryptoEngine.verify_signature(doc_bytes, sig_bytes, key_bytes)
            doc_hash = hashlib.sha256(doc_bytes).hexdigest()

            self.txt_ver_result.delete("1.0", "end")
            if is_valid:
                report = (
                    "============================================================\n"
                    "  ✅ РЕЗУЛЬТАТ ПЕРЕВІРКИ: ПІДПИС ДІЙСНИЙ (ВАЛІДНИЙ)\n"
                    "============================================================\n"
                    f"• Файл документа  : {os.path.basename(self.ver_doc_path)}\n"
                    f"• SHA-256 хеш     : {doc_hash}\n"
                    f"• Алгоритм ключа  : {algo}\n"
                    f"• Розмір підпису  : {len(sig_bytes)} байт\n"
                    "• Цілісність даних: Підтверджено (жоден байт не змінено)\n"
                )
            else:
                report = (
                    "============================================================\n"
                    "  ❌ РЕЗУЛЬТАТ ПЕРЕВІРКИ: ПІДПИС НЕДІЙСНИЙ!\n"
                    "============================================================\n"
                    f"• Файл документа  : {os.path.basename(self.ver_doc_path)}\n"
                    f"• Алгоритм ключа  : {algo}\n"
                    "• Причина відмови : Документ було змінено після підписання\n"
                    "                    або підпис накладено іншим закритим ключем!\n"
                )
            self.txt_ver_result.insert("1.0", report)
        except Exception as e:
            self.txt_ver_result.delete("1.0", "end")
            self.txt_ver_result.insert("1.0", f"❌ Помилка під час перевірки: {e}")

    # Вкладка 4: Сервер та TSA
    def setup_server_tab(self):
        container = ctk.CTkFrame(self.tab_server, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=20, pady=10)

        frame_auth = ctk.CTkFrame(container, corner_radius=10)
        frame_auth.pack(fill="x", pady=6, padx=5)

        ctk.CTkLabel(
            frame_auth,
            text="1. Автентифікація у серверному реєстрі СЕД (JWT + Автовипуск X.509):",
            font=("Segoe UI", 14, "bold")
        ).pack(anchor="w", padx=15, pady=(10, 5))

        inputs_row = ctk.CTkFrame(frame_auth, fg_color="transparent")
        inputs_row.pack(fill="x", padx=15, pady=5)

        self.entry_user = ctk.CTkEntry(inputs_row, placeholder_text="Логін користувача", width=220)
        self.entry_user.pack(side="left", padx=(0, 10))

        self.entry_pass = ctk.CTkEntry(inputs_row, placeholder_text="Пароль", show="•", width=220)
        self.entry_pass.pack(side="left", padx=(0, 10))

        ctk.CTkButton(inputs_row, text="🔑 Увійти", width=110, command=self.do_login).pack(side="left", padx=4)
        ctk.CTkButton(
            inputs_row,
            text="📝 Реєстрація (+X.509)",
            width=160,
            fg_color="#2b8a3e",
            hover_color="#1b5e20",
            command=self.do_register
        ).pack(side="left", padx=4)
        ctk.CTkButton(inputs_row, text="Вийти", width=80, fg_color="gray40", command=self.do_logout).pack(side="left", padx=4)

        self.lbl_server_auth = ctk.CTkLabel(
            frame_auth,
            text="Статус: Очікування входу в систему...",
            font=("Segoe UI", 12),
            text_color="orange"
        )
        self.lbl_server_auth.pack(anchor="w", padx=15, pady=(2, 10))

        frame_files = ctk.CTkFrame(container, corner_radius=10)
        frame_files.pack(fill="x", pady=6, padx=5)

        ctk.CTkLabel(
            frame_files,
            text="2. Реєстрація документа на сервері (TSA Штамп часу + Запис у Hash-Chain):",
            font=("Segoe UI", 14, "bold")
        ).pack(anchor="w", padx=15, pady=(10, 5))

        self.srv_doc_path = None
        self.srv_sig_path = None

        row_s1 = ctk.CTkFrame(frame_files, fg_color="transparent")
        row_s1.pack(fill="x", padx=15, pady=4)
        ctk.CTkButton(row_s1, text="1. Обрати Документ", width=220, command=lambda: self.set_srv_path('doc')).pack(side="left")
        self.lbl_srv_doc = ctk.CTkLabel(row_s1, text="Не обрано", text_color="gray")
        self.lbl_srv_doc.pack(side="left", padx=15)

        row_s2 = ctk.CTkFrame(frame_files, fg_color="transparent")
        row_s2.pack(fill="x", padx=15, pady=4)
        ctk.CTkButton(
            row_s2,
            text="2. Обрати .sig або .multisig.json",
            width=220,
            command=lambda: self.set_srv_path('sig')
        ).pack(side="left")
        self.lbl_srv_sig = ctk.CTkLabel(row_s2, text="Не обрано", text_color="gray")
        self.lbl_srv_sig.pack(side="left", padx=15)

        btn_row_srv = ctk.CTkFrame(frame_files, fg_color="transparent")
        btn_row_srv.pack(fill="x", padx=15, pady=10)

        ctk.CTkButton(
            btn_row_srv,
            text="🚀 Верифікувати .sig, отримати TSA та зберегти в БД",
            command=self.verify_on_server,
            height=40,
            fg_color="#2b8a3e",
            hover_color="#1b5e20",
            font=("Segoe UI", 13, "bold")
        ).pack(side="left", fill="x", expand=True, padx=(0, 5))

        ctk.CTkButton(
            btn_row_srv,
            text="🤝 Перевірити Мультипідпис (.multisig.json)",
            command=self.verify_multisig_on_server,
            height=40,
            fg_color="#1f538d",
            font=("Segoe UI", 13, "bold")
        ).pack(side="left", fill="x", expand=True, padx=(5, 0))

        self.txt_srv_output = ctk.CTkTextbox(container, height=150, font=("Consolas", 12), corner_radius=10)
        self.txt_srv_output.pack(fill="both", expand=True, padx=5, pady=5)
        self.txt_srv_output.insert("1.0", "Журнал відповідей сервера...")

    def do_login(self):
        user = self.entry_user.get().strip()
        pwd = self.entry_pass.get().strip()
        if not user or not pwd:
            self.lbl_server_auth.configure(text="❌ Введіть логін та пароль!", text_color="#ff6b6b")
            return

        success, msg = self.api.login(user, pwd)
        if success:
            self.lbl_server_auth.configure(text=f"✅ Авторизовано як: {user}", text_color="#51cf66")
            self._update_header_auth()
        else:
            self.lbl_server_auth.configure(text=f"❌ Помилка: {msg}", text_color="#ff6b6b")

    def do_logout(self):
        self.api.token = None
        self.api.username = None
        self.lbl_server_auth.configure(text="Статус: Ви вийшли з системи", text_color="orange")
        self._update_header_auth()

        if hasattr(self, 'history_frame'):
            for widget in self.history_frame.winfo_children():
                widget.destroy()

    def do_register(self):
        user = self.entry_user.get().strip()
        pwd = self.entry_pass.get().strip()
        if not user or not pwd:
            self.lbl_server_auth.configure(text="❌ Спочатку введіть бажаний логін та пароль у полях вище!", text_color="#ff6b6b")
            return

        pub_key_path = filedialog.askopenfilename(
            title="Оберіть ваш ВІДКРИТИЙ ключ (public_key.pem)",
            filetypes=[("PEM Files", "*.pem"), ("All Files", "*.*")]
        )
        if not pub_key_path:
            return

        try:
            pub_bytes = FileUtils.read_file_bytes(pub_key_path)
            pub_pem = pub_bytes.decode('utf-8')
            success, msg = self.api.register(user, pwd, pub_pem)
            if success:
                self.lbl_server_auth.configure(text=f"✅ {msg}", text_color="#51cf66")
            else:
                self.lbl_server_auth.configure(text=f"❌ Помилка: {msg}", text_color="#ff6b6b")
        except Exception as e:
            self.lbl_server_auth.configure(text=f"❌ Помилка читання ключа: {e}", text_color="#ff6b6b")

    def set_srv_path(self, target: str):
        path = filedialog.askopenfilename()
        if not path:
            return
        if target == 'doc':
            self.srv_doc_path = path
            self.lbl_srv_doc.configure(text=f"📄 {os.path.basename(path)}", text_color="#51cf66")
        elif target == 'sig':
            self.srv_sig_path = path
            self.lbl_srv_sig.configure(text=f"🔐 {os.path.basename(path)}", text_color="#51cf66")

    def verify_on_server(self):
        if not self.srv_doc_path or not self.srv_sig_path:
            self.txt_srv_output.delete("1.0", "end")
            self.txt_srv_output.insert("1.0", "❌ Оберіть документ та файл підпису (.sig)!")
            return

        self.txt_srv_output.delete("1.0", "end")
        self.txt_srv_output.insert("1.0", "⏳ Відправка пакета на сервер, перевірка X.509 та запит штампа часу TSA...")
        self.update()

        success, msg = self.api.verify_document(self.srv_doc_path, self.srv_sig_path)
        self.txt_srv_output.delete("1.0", "end")
        if success:
            self.txt_srv_output.insert("1.0", f"🎉 ВІДПОВІДЬ СЕРВЕРА:\n{msg}")
        else:
            self.txt_srv_output.insert("1.0", f"❌ ВІДМОВА СЕРВЕРА:\n{msg}")

    def verify_multisig_on_server(self):
        if not self.srv_doc_path:
            self.txt_srv_output.delete("1.0", "end")
            self.txt_srv_output.insert("1.0", "❌ Оберіть документ ('1. Обрати Документ')! Контейнер мультипідпису сервер автоматично підтягне з БД.")
            return

        self.txt_srv_output.delete("1.0", "end")
        self.txt_srv_output.insert("1.0", "⏳ Перевірка колективного мультипідпису в БД PostgreSQL (X.509 + CRL + TSA)...")
        self.update()

        success, data = self.api.verify_multisig(self.srv_doc_path, self.srv_sig_path)
        self.txt_srv_output.delete("1.0", "end")
        if success and isinstance(data, dict):
            lines = [
                "============================================================",
                f"  {data.get('summary', 'Результат мультипідпису')}",
                "============================================================"
            ]
            allowed_list = data.get("allowed_signers", [])
            if allowed_list:
                lines.append(f"👥 Маршрут погодження в БД (ACL): {', '.join(allowed_list)}")
                lines.append("------------------------------------------------------------")
            for r in data.get("reports", []):
                status_icon = "✅ ДІЙСНИЙ" if r.get("is_valid") else "❌ НЕДІЙСНИЙ"
                lines.append(
                    f"#{r.get('index')} Учасник: {r.get('signer_name')} [{r.get('role')}] -> {status_icon}\n"
                    f"   Алгоритм: {r.get('algorithm')} | Серія X.509: {r.get('serial_number')}\n"
                    f"   Деталі: {r.get('reason')}"
                )
            self.txt_srv_output.insert("1.0", "\n".join(lines))
        else:
            self.txt_srv_output.insert("1.0", f"❌ Помилка перевірки мультипідпису:\n{data}")

    # Вкладка 5: Сертифікати та аудит БД
    def setup_certs_tab(self):
        container = ctk.CTkFrame(self.tab_certs, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=20, pady=10)

        card_cert = ctk.CTkFrame(container, corner_radius=10)
        card_cert.pack(fill="x", pady=6, padx=5)

        ctk.CTkLabel(
            card_cert,
            text="1. Управління персональним сертифікатом X.509 (Центр сертифікації CA):",
            font=("Segoe UI", 14, "bold")
        ).pack(anchor="w", padx=15, pady=(10, 5))

        btn_row = ctk.CTkFrame(card_cert, fg_color="transparent")
        btn_row.pack(fill="x", padx=15, pady=6)

        ctk.CTkButton(btn_row, text="📥 Мій сертифікат X.509", width=210, command=self.load_my_cert).pack(side="left", padx=4)
        ctk.CTkButton(btn_row, text="💾 Зберегти мій .crt", width=190, command=self.save_my_cert_file).pack(side="left", padx=4)
        ctk.CTkButton(btn_row, text="🏛️ Завантажити Root CA", width=210, fg_color="gray40", command=self.download_root_ca_ui).pack(side="left", padx=4)

        rev_row = ctk.CTkFrame(card_cert, fg_color="transparent")
        rev_row.pack(fill="x", padx=15, pady=(4, 12))

        ctk.CTkLabel(rev_row, text="Причина відкликання (RFC 5280):").pack(side="left", padx=(4, 8))
        self.opt_revoke_reason = ctk.CTkOptionMenu(
            rev_row,
            values=["KeyCompromise", "Superseded", "CessationOfOperation", "AffiliationChanged"],
            width=200
        )
        self.opt_revoke_reason.pack(side="left", padx=4)

        ctk.CTkButton(
            rev_row,
            text="🚨 Анулювати / Відкликати сертифікат (CRL)",
            fg_color="#c92a2a",
            hover_color="#862e9c",
            width=280,
            command=self.revoke_my_cert_ui
        ).pack(side="left", padx=10)

        card_audit = ctk.CTkFrame(container, corner_radius=10)
        card_audit.pack(fill="x", pady=6, padx=5)

        ctk.CTkLabel(
            card_audit,
            text="2. Незмінний криптографічний журнал аудиту (Tamper-Evident Hash Chain):",
            font=("Segoe UI", 14, "bold")
        ).pack(anchor="w", padx=15, pady=(10, 5))

        ctk.CTkButton(
            card_audit,
            text="🛡️ Запустити повну математичну верифікацію цілісності геш-ланцюга БД",
            height=42,
            font=("Segoe UI", 13, "bold"),
            fg_color="#1f538d",
            command=self.run_audit_chain_ui
        ).pack(fill="x", padx=15, pady=(4, 12))

        self.txt_certs_audit = ctk.CTkTextbox(container, height=220, font=("Consolas", 12), corner_radius=10)
        self.txt_certs_audit.pack(fill="both", expand=True, padx=5, pady=5)
        self.txt_certs_audit.insert(
            "1.0",
            "Натисніть 'Мій сертифікат X.509' для перегляду цифрового паспорта ключа\n"
            "або запустіть перевірку цілісності геш-ланцюга бази даних..."
        )
        self._cached_cert_data = None

    def load_my_cert(self):
        ok, data = self.api.get_my_certificate()
        self.txt_certs_audit.delete("1.0", "end")
        if ok and isinstance(data, dict):
            self._cached_cert_data = data
            status_str = "🔴 ВІДКЛИКАНИЙ (АНУЛЬОВАНИЙ)" if data.get("is_revoked") else "🟢 АКТИВНИЙ (ДІЙСНИЙ)"
            info = (
                "============================================================\n"
                "  📜 ПЕРСОНАЛЬНИЙ СЕРТИФІКАТ X.509 (ВИДАНИЙ ROOT CA)\n"
                "============================================================\n"
                f"• Власник (Subject CN) : {data.get('username')}\n"
                f"• Серійний номер       : {data.get('serial_number')}\n"
                f"• Дійсний до           : {data.get('expires_at')}\n"
                f"• Статус у реєстрі CRL : {status_str}\n"
            )
            if data.get("revocation_reason"):
                info += f"• Причина блокування   : {data.get('revocation_reason')}\n"
            info += "\n" + data.get("certificate_pem", "")
            self.txt_certs_audit.insert("1.0", info)
        else:
            self.txt_certs_audit.insert("1.0", f"❌ {data}")

    def save_my_cert_file(self):
        if not self._cached_cert_data or not self._cached_cert_data.get("certificate_pem"):
            ok, data = self.api.get_my_certificate()
            if not ok:
                self.txt_certs_audit.delete("1.0", "end")
                self.txt_certs_audit.insert("1.0", f"❌ Не вдалося отримати сертифікат: {data}")
                return
            self._cached_cert_data = data

        save_path = filedialog.asksaveasfilename(
            title="Зберегти сертифікат X.509",
            initialfile=f"{self._cached_cert_data.get('username', 'user')}_x509.crt",
            defaultextension=".crt",
            filetypes=[("X.509 Certificate", "*.crt *.pem")]
        )
        if save_path:
            FileUtils.save_key_to_file(save_path, self._cached_cert_data["certificate_pem"])
            self.txt_certs_audit.delete("1.0", "end")
            self.txt_certs_audit.insert("1.0", f"✅ Сертифікат збережено у файл:\n{save_path}")

    def download_root_ca_ui(self):
        save_path = filedialog.asksaveasfilename(
            title="Зберегти кореневий сертифікат Root CA",
            initialfile="eds_root_ca.crt",
            defaultextension=".crt",
            filetypes=[("X.509 Root CA", "*.crt")]
        )
        if save_path:
            ok, msg = self.api.download_root_ca(save_path)
            self.txt_certs_audit.delete("1.0", "end")
            self.txt_certs_audit.insert("1.0", f"{'✅' if ok else '❌'} {msg}\nШлях: {save_path}")

    def revoke_my_cert_ui(self):
        ok, data = self.api.get_my_certificate()
        if not ok or not isinstance(data, dict):
            self.txt_certs_audit.delete("1.0", "end")
            self.txt_certs_audit.insert("1.0", f"❌ Спочатку авторизуйтесь: {data}")
            return

        serial = data.get("serial_number")
        reason = self.opt_revoke_reason.get()
        _, msg_rev = self.api.revoke_certificate(serial, reason=reason)
        self.txt_certs_audit.delete("1.0", "end")
        self.txt_certs_audit.insert("1.0", f"{msg_rev}\nОновіть дані сертифіката для перегляду статусу.")

    def run_audit_chain_ui(self):
        self.txt_certs_audit.delete("1.0", "end")
        self.txt_certs_audit.insert("1.0", "⏳ Перевірка криптографічного геш-ланцюжка всіх підписів у PostgreSQL...")
        self.update()

        ok, data = self.api.verify_audit_chain()
        self.txt_certs_audit.delete("1.0", "end")
        if ok and isinstance(data, dict):
            is_val = data.get("is_valid")
            msg = data.get("message")
            broken_id = data.get("broken_record_id")
            if is_val:
                report = (
                    "============================================================\n"
                    "  🛡️ АУДИТ БАЗИ ДАНИХ: ЦІЛІСНІСТЬ ПІДТВЕРДЖЕНО (100%)\n"
                    "============================================================\n"
                    f"• Висновок : {msg}\n"
                    "• Метод    : Tamper-Evident SHA-256 Hash Chain\n"
                    "• Статус   : Жоден запис у таблиці signatures не був модифікований\n"
                    "             або видалений заднім числом.\n"
                )
            else:
                report = (
                    "============================================================\n"
                    "  🚨 ТРИВОГА БЕЗПЕКИ: ВИЯВЛЕНО НЕСАНКЦІОНОВАНУ МОДИФІКАЦІЮ БД!\n"
                    "============================================================\n"
                    f"• Повідомлення    : {msg}\n"
                    f"• Пошкоджений блок: Запис ID = {broken_id}\n"
                    "• Рекомендація    : Ланцюжок гешів розірвано! Дані в базі підмінено.\n"
                )
            self.txt_certs_audit.insert("1.0", report)
        else:
            self.txt_certs_audit.insert("1.0", f"❌ Помилка запиту аудиту: {data}")

    # Вкладка 6: Мої документи
    def setup_history_tab(self):
        top_bar = ctk.CTkFrame(self.tab_history, fg_color="transparent")
        top_bar.pack(fill="x", padx=20, pady=10)

        btn_refresh = ctk.CTkButton(top_bar, text="🔄 Оновити реєстр документів", width=220, command=self.load_documents)
        btn_refresh.pack(side="left")

        self.lbl_history_status = ctk.CTkLabel(
            top_bar,
            text="Натисніть 'Оновити реєстр', щоб завантажити список документів.",
            font=("Segoe UI", 12)
        )
        self.lbl_history_status.pack(side="left", padx=15)

        self.history_frame = ctk.CTkScrollableFrame(self.tab_history, corner_radius=10)
        self.history_frame.pack(pady=5, padx=20, fill="both", expand=True)

    def load_documents(self):
        if not self.api.token:
            self.lbl_history_status.configure(
                text="❌ Спершу авторизуйтесь у вкладці '🌐 Сервер та TSA'!",
                text_color="#ff6b6b"
            )
            return

        self.lbl_history_status.configure(text="⏳ Завантаження...", text_color="yellow")
        self.update()

        success, data = self.api.get_my_documents()

        if success:
            for widget in self.history_frame.winfo_children():
                widget.destroy()

            if not data:
                self.lbl_history_status.configure(text="📭 У вас ще немає збережених документів.", text_color="white")
                return

            self.lbl_history_status.configure(text=f"✅ Знайдено документів у реєстрі: {len(data)}", text_color="#51cf66")

            for doc in data:
                doc_frame = ctk.CTkFrame(self.history_frame, corner_radius=8)
                doc_frame.pack(pady=5, padx=5, fill="x")

                btn_del = ctk.CTkButton(
                    doc_frame,
                    text="🗑 Видалити",
                    width=95,
                    fg_color="#8b0000",
                    hover_color="#5a0000",
                    command=lambda d=doc['id']: self.delete_doc_ui(d)
                )
                btn_del.pack(side="right", padx=10, pady=10)

                btn_open = ctk.CTkButton(
                    doc_frame,
                    text="👁 Відкрити",
                    width=95,
                    fg_color="#1f538d",
                    hover_color="#14375e",
                    command=lambda d=doc: self.open_doc_ui(d)
                )
                btn_open.pack(side="right", padx=5, pady=10)

                lbl_name = ctk.CTkLabel(doc_frame, text=f"📄 {doc['filename']} (ID: #{doc['id']})", font=("Segoe UI", 14, "bold"))
                lbl_name.pack(anchor="w", padx=12, pady=(6, 0))

                size_str = f" | Розмір: {doc['file_size']} байт" if doc.get("file_size") else ""
                lbl_info = ctk.CTkLabel(
                    doc_frame,
                    text=f"Завантажено: {doc['uploaded_at']}{size_str}  |  Статус: {doc['status']} (TSA + HashChain)",
                    text_color="gray70",
                    font=("Segoe UI", 11)
                )
                lbl_info.pack(anchor="w", padx=12, pady=(0, 6))
        else:
            self.lbl_history_status.configure(text=f"❌ Помилка: {data}", text_color="#ff6b6b")

    def delete_doc_ui(self, doc_id: int):
        success, msg = self.api.delete_document(doc_id)
        if success:
            self.load_documents()
        else:
            self.lbl_history_status.configure(text=f"❌ Помилка: {msg}", text_color="#ff6b6b")

    def open_doc_ui(self, doc: dict):
        doc_id = doc['id']
        filename = doc['filename']

        downloads_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "downloads")
        os.makedirs(downloads_dir, exist_ok=True)
        local_path = os.path.join(downloads_dir, filename)

        self.lbl_history_status.configure(text=f"⏳ Завантаження {filename}...", text_color="yellow")
        self.update()

        success, msg = self.api.download_document(doc_id, local_path)
        if success:
            self.lbl_history_status.configure(text=f"✅ Відкриття файлу {filename}...", text_color="#51cf66")
            try:
                os.startfile(local_path)
            except Exception as e:
                self.lbl_history_status.configure(text=f"❌ Не вдалося відкрити файл: {e}", text_color="#ff6b6b")
        else:
            self.lbl_history_status.configure(text=f"❌ Помилка: {msg}", text_color="#ff6b6b")

    # Вкладка 7: Налаштування
    def setup_settings_tab(self):
        card = ctk.CTkFrame(self.tab_settings, corner_radius=10)
        card.pack(padx=30, pady=20, fill="x")

        ctk.CTkLabel(card, text="Тема оформлення інтерфейсу:", font=("Segoe UI", 14, "bold")).pack(pady=(20, 5))

        self.theme_option = ctk.CTkOptionMenu(
            card,
            values=["Dark", "Light", "System"],
            command=self.change_theme,
            width=220
        )
        self.theme_option.pack(pady=5)
        self.theme_option.set(ctk.get_appearance_mode())

        ctk.CTkLabel(card, text="Адреса захищеного API сервера СЕД:", font=("Segoe UI", 14, "bold")).pack(pady=(20, 5))

        self.entry_server_url = ctk.CTkEntry(card, width=350)
        self.entry_server_url.pack(pady=5)
        self.entry_server_url.insert(0, self.api.base_url)

        ctk.CTkButton(card, text="💾 Зберегти адресу API", command=self.save_server_url, width=220).pack(pady=15)

        self.lbl_settings_status = ctk.CTkLabel(card, text="")
        self.lbl_settings_status.pack(pady=(0, 15))

    def change_theme(self, new_theme: str):
        ctk.set_appearance_mode(new_theme)
        self.lbl_settings_status.configure(text=f"✅ Тему змінено на: {new_theme}", text_color="#51cf66")

    def save_server_url(self):
        new_url = self.entry_server_url.get().strip()
        if new_url:
            self.api.base_url = new_url.rstrip("/")
            self.lbl_settings_status.configure(text=f"✅ Адресу API оновлено на: {self.api.base_url}", text_color="#51cf66")
        else:
            self.lbl_settings_status.configure(text="❌ Адреса не може бути порожньою!", text_color="#ff6b6b")
