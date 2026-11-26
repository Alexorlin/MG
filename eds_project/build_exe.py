import os
import sys
import subprocess


def build():
    """Збирання клієнтського додатку у виконуваний файл dist/EDS_Project.exe."""
    project_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(project_dir)

    print("=" * 65)
    print("  ЗБІРКА ПРОГРАМИ: dist/EDS_Project.exe")
    print("=" * 65)

    try:
        import PyInstaller  # noqa: F401
        print("[1/2] PyInstaller знайдено.")
    except ImportError:
        print("[1/2] Встановлення PyInstaller...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])

    print("[2/2] Пакування програми у dist/EDS_Project.exe...")
    spec_path = os.path.join(project_dir, "main.spec")
    subprocess.check_call([
        sys.executable, "-m", "PyInstaller",
        "--clean",
        "--noconfirm",
        spec_path
    ])

    exe_path = os.path.join(project_dir, "dist", "EDS_Project.exe")
    print("\n" + "=" * 65)
    if os.path.exists(exe_path):
        size_mb = os.path.getsize(exe_path) / (1024 * 1024)
        print(f"Збірку завершено: {exe_path} ({size_mb:.1f} МБ)")
    else:
        print("Помилка: файл EDS_Project.exe не знайдено.")
    print("=" * 65)


if __name__ == "__main__":
    build()
