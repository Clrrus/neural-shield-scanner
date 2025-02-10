from port_scanner.port_scanner import run_scanner
import time

if __name__ == "__main__":
    while True:
        try:
            run_scanner()
            print("Scanning Completed Successfully. Next Scan will be occured in 1 hour")
            time.sleep(3600)
        except KeyboardInterrupt:
            print("Exiting program...")
            break
        except Exception as e:
            print(f"Error: {e}")
            time.sleep(5)
            continue