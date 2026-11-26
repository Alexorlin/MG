import os
import requests
from typing import Tuple, Any, Optional


class ApiClient:
    """Мережевий клієнт для взаємодії з REST API сервера СЕД."""

    def __init__(self, base_url: str = "http://127.0.0.1:8000"):
        self.base_url = base_url.rstrip("/")
        self.token: Optional[str] = None
        self.username: Optional[str] = None

    def _auth_headers(self) -> dict:
        if not self.token:
            return {}
        return {"Authorization": f"Bearer {self.token}"}

    def register(self, username: str, password: str, public_key_pem: str) -> Tuple[bool, str]:
        url = f"{self.base_url}/auth/register"
        payload = {
            "username": username,
            "password": password,
            "public_key_pem": public_key_pem
        }
        try:
            response = requests.post(url, json=payload, timeout=10)
            response.raise_for_status()
            data = response.json()
            serial = data.get("cert_serial")
            algo = data.get("key_algorithm", "RSA-2048")
            msg = data.get("message", "Реєстрація успішна")
            if serial:
                msg += f" | Випущено X.509 сертифікат ({algo}, Serial: {serial[:12]}...)"
            return True, msg
        except requests.exceptions.HTTPError as e:
            try:
                error_detail = e.response.json().get("detail", "Помилка реєстрації")
            except Exception:
                error_detail = "Помилка реєстрації на сервері"
            return False, error_detail
        except requests.exceptions.ConnectionError:
            return False, "Помилка з'єднання. Переконайтеся, що сервер (FastAPI) запущено."
        except Exception as e:
            return False, f"Помилка: {e}"

    def login(self, username: str, password: str) -> Tuple[bool, str]:
        url = f"{self.base_url}/auth/login"
        payload = {
            "username": username,
            "password": password
        }
        try:
            response = requests.post(url, data=payload, timeout=10)
            response.raise_for_status()
            self.token = response.json().get("access_token")
            self.username = username
            return True, "Авторизація успішна"
        except requests.exceptions.HTTPError as e:
            try:
                error_detail = e.response.json().get("detail", "Невірний логін або пароль")
            except Exception:
                error_detail = "Невірний логін або пароль"
            return False, error_detail
        except requests.exceptions.ConnectionError:
            return False, "Помилка з'єднання із сервером."
        except Exception as e:
            return False, f"Помилка: {e}"

    def verify_document(self, doc_path: str, sig_path: str) -> Tuple[bool, str]:
        if not self.token:
            return False, "Ви не авторизовані. Будь ласка, увійдіть в систему."

        url = f"{self.base_url}/docs/verify-and-save"
        try:
            with open(doc_path, 'rb') as doc_file, open(sig_path, 'rb') as sig_file:
                files = {
                    'file': (os.path.basename(doc_path), doc_file, 'application/octet-stream'),
                    'signature_file': (os.path.basename(sig_path), sig_file, 'application/octet-stream')
                }
                response = requests.post(url, headers=self._auth_headers(), files=files, timeout=20)
                response.raise_for_status()
                data = response.json()

                msg = data.get("message", "Успішно перевірено")
                rec_hash = data.get("record_hash", "")
                tsa_time = data.get("tsa_timestamp", "")
                if rec_hash:
                    msg += f"\n🔗 Блок Hash-Chain: {rec_hash[:16]}..."
                if tsa_time:
                    msg += f"\n⏱️ Штамп TSA: {tsa_time[:19]} UTC"
                return True, msg
        except requests.exceptions.HTTPError as e:
            try:
                error_detail = e.response.json().get("detail", "Помилка перевірки на сервері")
            except Exception:
                error_detail = "Помилка перевірки на сервері"
            return False, error_detail
        except Exception as e:
            return False, f"Помилка при роботі з файлами: {str(e)}"

    def sign_multisig_on_server(
        self,
        doc_path: str,
        signature_b64: str,
        certificate_pem: str,
        role: str,
        allowed_signers: Optional[str] = None
    ) -> Tuple[bool, Any]:
        if not self.token:
            return False, "Ви не авторизовані. Увійдіть у свій акаунт у вкладці '🌐 Сервер та TSA'."

        url = f"{self.base_url}/docs/multisig/sign"
        try:
            with open(doc_path, 'rb') as doc_file:
                files = {
                    'file': (os.path.basename(doc_path), doc_file, 'application/octet-stream')
                }
                data = {
                    'signature_b64': signature_b64,
                    'certificate_pem': certificate_pem,
                    'role': role
                }
                if allowed_signers:
                    data['allowed_signers'] = allowed_signers

                response = requests.post(url, headers=self._auth_headers(), files=files, data=data, timeout=20)
                response.raise_for_status()
                return True, response.json()
        except requests.exceptions.HTTPError as e:
            try:
                error_detail = e.response.json().get("detail", "Помилка збереження мультипідпису в БД")
            except Exception:
                error_detail = "Помилка збереження мультипідпису в БД"
            return False, error_detail
        except Exception as e:
            return False, f"Помилка мережі: {e}"

    def verify_multisig(self, doc_path: str, multisig_path: Optional[str] = None) -> Tuple[bool, Any]:
        url = f"{self.base_url}/docs/verify-multisig"
        try:
            with open(doc_path, 'rb') as doc_file:
                files = {
                    'file': (os.path.basename(doc_path), doc_file, 'application/octet-stream')
                }
                if multisig_path and os.path.exists(multisig_path):
                    with open(multisig_path, 'rb') as ms_file:
                        files['multisig_file'] = (os.path.basename(multisig_path), ms_file.read(), 'application/json')
                response = requests.post(url, headers=self._auth_headers(), files=files, timeout=20)
                response.raise_for_status()
                return True, response.json()
        except requests.exceptions.HTTPError as e:
            try:
                error_detail = e.response.json().get("detail", "Помилка перевірки мультипідпису")
            except Exception:
                error_detail = "Помилка перевірки мультипідпису"
            return False, error_detail
        except Exception as e:
            return False, f"Помилка відправки мультипідпису: {e}"

    def get_my_documents(self) -> Tuple[bool, Any]:
        if not self.token:
            return False, "Ви не авторизовані."

        url = f"{self.base_url}/docs/my-documents"
        try:
            response = requests.get(url, headers=self._auth_headers(), timeout=10)
            response.raise_for_status()
            return True, response.json()
        except requests.exceptions.HTTPError:
            return False, "Помилка завантаження списку документів"
        except Exception as e:
            return False, f"Помилка мережі: {str(e)}"

    def delete_document(self, doc_id: int) -> Tuple[bool, str]:
        if not self.token:
            return False, "Ви не авторизовані."

        url = f"{self.base_url}/docs/{doc_id}"
        try:
            response = requests.delete(url, headers=self._auth_headers(), timeout=10)
            response.raise_for_status()
            return True, response.json().get("message", "Видалено")
        except requests.exceptions.HTTPError:
            return False, "Не вдалося видалити документ (немає прав)"
        except Exception as e:
            return False, f"Помилка мережі: {str(e)}"

    def download_document(self, doc_id: int, save_path: str) -> Tuple[bool, str]:
        if not self.token:
            return False, "Ви не авторизовані."

        url = f"{self.base_url}/docs/download/{doc_id}"
        try:
            response = requests.get(url, headers=self._auth_headers(), stream=True, timeout=20)
            response.raise_for_status()
            with open(save_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            return True, "Файл успішно завантажено"
        except requests.exceptions.HTTPError as e:
            try:
                detail = e.response.json().get("detail", "Не вдалося завантажити файл")
            except Exception:
                detail = "Не вдалося завантажити файл"
            return False, detail
        except Exception as e:
            return False, f"Помилка мережі: {str(e)}"

    def get_my_certificate(self) -> Tuple[bool, Any]:
        if not self.token:
            return False, "Ви не авторизовані."

        url = f"{self.base_url}/certs/my-certificate"
        try:
            response = requests.get(url, headers=self._auth_headers(), timeout=10)
            response.raise_for_status()
            return True, response.json()
        except requests.exceptions.HTTPError as e:
            try:
                detail = e.response.json().get("detail", "Сертифікат не знайдено")
            except Exception:
                detail = "Сертифікат не знайдено"
            return False, detail
        except Exception as e:
            return False, f"Помилка мережі: {e}"

    def issue_certificate(self) -> Tuple[bool, Any]:
        if not self.token:
            return False, "Ви не авторизовані."

        url = f"{self.base_url}/certs/issue"
        try:
            response = requests.post(url, headers=self._auth_headers(), timeout=10)
            response.raise_for_status()
            return True, response.json()
        except requests.exceptions.HTTPError as e:
            try:
                detail = e.response.json().get("detail", "Помилка випуску сертифіката")
            except Exception:
                detail = "Помилка випуску сертифіката"
            return False, detail
        except Exception as e:
            return False, f"Помилка мережі: {e}"

    def revoke_certificate(self, serial_number: str, reason: str = "KeyCompromise") -> Tuple[bool, str]:
        if not self.token:
            return False, "Ви не авторизовані."

        url = f"{self.base_url}/certs/revoke"
        payload = {
            "serial_number": serial_number,
            "reason": reason
        }
        try:
            response = requests.post(url, json=payload, headers=self._auth_headers(), timeout=10)
            response.raise_for_status()
            return True, response.json().get("message", "Сертифікат відкликано")
        except requests.exceptions.HTTPError as e:
            try:
                detail = e.response.json().get("detail", "Помилка відкликання сертифіката")
            except Exception:
                detail = "Помилка відкликання сертифіката"
            return False, detail
        except Exception as e:
            return False, f"Помилка мережі: {e}"

    def check_certificate_status(self, serial_number: str) -> Tuple[bool, Any]:
        url = f"{self.base_url}/certs/status/{serial_number}"
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            return True, response.json()
        except Exception as e:
            return False, f"Помилка перевірки статусу: {e}"

    def download_root_ca(self, save_path: str) -> Tuple[bool, str]:
        url = f"{self.base_url}/certs/ca.crt"
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            with open(save_path, 'wb') as f:
                f.write(response.content)
            return True, "Кореневий сертифікат Root CA успішно збережено."
        except Exception as e:
            return False, f"Помилка завантаження Root CA: {e}"

    def verify_audit_chain(self) -> Tuple[bool, Any]:
        url = f"{self.base_url}/docs/audit/verify-chain"
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            return True, response.json()
        except Exception as e:
            return False, f"Помилка перевірки геш-ланцюга: {e}"
