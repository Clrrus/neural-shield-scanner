import psutil
import time

def sistem_kaynaklarini_olc():
    # CPU kullanımı
    cpu_yuzde = psutil.cpu_percent(interval=1)
    
    # RAM kullanımı
    ram = psutil.virtual_memory()
    ram_kullanim = ram.percent
    
    # Disk kullanımı
    disk = psutil.disk_usage('/')
    disk_kullanim = disk.percent
    
    return {
        'CPU Kullanımı': f'%{cpu_yuzde}',
        'RAM Kullanımı': f'%{ram_kullanim}',
        'Disk Kullanımı': f'%{disk_kullanim}'
    }

# Test
print(sistem_kaynaklarini_olc())