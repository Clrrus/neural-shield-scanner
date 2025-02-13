from port_scanner.port_scanner import run_scanner
from packet_sniffer.packet_sniffer import main as packet_sniffer_main
import time
import subprocess
from threading import Thread
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.events import EVENT_JOB_ERROR
import logging
from datetime import datetime

def run_packet_sniffer():
    try:
        packet_sniffer_main()
    except subprocess.CalledProcessError as e:
        print(f"Packet sniffer error: {e}")
    except KeyboardInterrupt:
        print("Packet sniffer stopping...")

def job_error_listener(event):
    logging.error(f"Scanner error: {event.exception}")
    logging.error(f"Job ID: {event.job_id}")

def run_port_scanner():
    try:
        logging.info(f"Port scanning started: {datetime.now()}")
        run_scanner()
        logging.info(f"Port scanning completed: {datetime.now()}")
    except Exception as e:
        logging.error(f"Port scanning error: {str(e)}")
        raise

if __name__ == "__main__":
    try:
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

        sniffer_thread = Thread(target=run_packet_sniffer)
        sniffer_thread.daemon = True
        sniffer_thread.start()
        
        scheduler = BackgroundScheduler()
        scheduler.add_listener(job_error_listener, EVENT_JOB_ERROR)
        
        scheduler.add_job(
            run_port_scanner,
            trigger=IntervalTrigger(hours=1),
            id='port_scanner',
            name='Hourly port scanning',
            max_instances=1,
            coalesce=True,
            misfire_grace_time=3600
        )
        
        scheduler.start()
        logging.info("Scheduler started")
        
        try:
            while True:
                time.sleep(1)
        except (KeyboardInterrupt, SystemExit):
            scheduler.shutdown()
            logging.info("Scheduler stopped")
            
    except KeyboardInterrupt:
        logging.info("Main program stopping...")