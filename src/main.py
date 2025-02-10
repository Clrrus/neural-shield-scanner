import subprocess
import time
import sys
import shutil

def get_python_command():
    if shutil.which('python3'):
        return 'python3'
    elif shutil.which('python'):
        return 'python'
    else:
        print("Python komutu bulunamadı!")
        sys.exit(1)

def main():
    python_cmd = get_python_command()
    while True:
        try:
            process = subprocess.run(
                [python_cmd, "port_scanner/port_scanner.py"],
                capture_output=True,
                text=True
            )
            
            if process.returncode != 0:
                print(f"Hata oluştu: {process.stderr}")
            
            time.sleep(3600)
            
        except KeyboardInterrupt:
            print("\nProgram sonlandırılıyor...")
            sys.exit(0)
        except Exception as e:
            print(f"Beklenmeyen hata: {str(e)}")
            time.sleep(5)
            continue

if __name__ == "__main__":
    main()