# Network Scanner

Bu ağ tarama aracı, belirtilen IP adresleri veya IP aralıklarında port taraması ve paket yakalama yapmanıza olanak sağlar.

## ⚠️ Önemli Bilgilendirme

Bu proje, Project: Neural Shield için Clrrus tarafından oluşturulmuştur. İzinsiz kullanımı kesinlikle yasaktır.

## 🚀 Özellikler

- Tekli IP taraması
- CIDR notasyonuyla ağ taraması
- Çoklu thread desteği
- Özelleştirilebilir port aralığı
- Batch işleme özelliği
- Packet Sniffer
- Intrusion Detection System (Port taraması tespiti için)

## ⚙️ Kurulum
```
git clone https://github.com/Clrrus/neural-shield-scanner.git
cd neural-shield-scanner
pip install -r requirements.txt
```

## 🔧 Kullanım

1. `config.json` dosyasını düzenleyin
2. Programı çalıştırın: (**Packet Sniffer İçin Root Yetkisi İstenmektedir**)
```
sudo python src/main.py
```


## 📝 Yapılandırma

Tarama ayarlarını `config.json` dosyası üzerinden yapılandırabilirsiniz:
```
{
    "scanner": {
        "scan_type": "2",
        "port_range_type": "2",
        "target": "192.168.1.1",
        "target_range": "192.168.1.0/24",
        "thread_count": 150,
        "batch_size": 200
    },
    "ids" : {
        "syn_threshold" : 20,
        "scan_threshold" : 15,
        "time_window" : 5
    }
}
```

### Yapılandırma Parametreleri

- `scan_type`: Tarama türü (1: Tekli IP, 2: IP aralığı)
- `port_range_type`: Port tarama türü
- `target`: Tekli IP taraması için hedef adres
- `target_range`: CIDR formatında ağ aralığı
- `thread_count`: Eşzamanlı thread sayısı
- `batch_size`: İşlem başına batch boyutu
- `syn_threshold`: SYN paket sayısı eşiği (Değiştirilmesi önerilmez)
- `scan_threshold`: Tarama eşiği (Değiştirilmesi önerilmez)
- `time_window`: Zaman aralığı (Değiştirilmesi önerilmez)

#### Thread Count:
- `thread_count`: 50 -> 50 thread ile tarama yapılır. (Aynı anda 50 port taranır.) Dezavantajı ise ağınıza yük bindirir, sistem kaynaklarını daha fazla kullanır. (10-30 arası ideal)

#### Batch Size:
- `batch_size`: 200 -> Taramayı gruplara ayırır. Örneğin 200 port taranırken 1000 port taranırken 5 grup oluşturur. Her grup sırasıyla taranır. Bellek kullanımını optimize eder ama ağa yük bindirir. (100-500 arası ideal)

#### Port Aralıkları:
- `port_range_type`: 1 -> Daha fazla port tarandığı için daha yavaş çalışır.
```
1 ile 10000 arasındaki portlara ek olarak "10010, 32768, 32771, 49152, 49153, 49154, 49155, 49156, 49157, 50000,62078" portları.
```
- `port_range_type`: 2 -> Popüler portlar taranır bu yüzden daha hızlı çalışır.
```
POPULAR_PORTS = [
    1, 3, 7, 9, 13, 17, 19, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 82, 88, 100, 106, 110, 111, 113, 119, 135, 139, 143, 144, 179, 199, 
    254, 255, 280, 311, 389, 427, 443, 444, 445, 464, 465, 497, 513, 514, 515, 543, 544, 548, 554, 587, 593, 625, 631, 636, 646, 787, 
    808, 873, 902, 990, 993, 995, 1000, 1022, 1024, 1025, 1026, 1027, 1028, 1029, 1030, 1031, 1032, 1033, 1035, 1036, 1037, 1038, 
    1039, 1040, 1041, 1044, 1048, 1049, 1050, 1053, 1054, 1056, 1058, 1059, 1064, 1065, 1066, 1069, 1071, 1074, 1080, 1110, 1234, 
    1433, 1434, 1494, 1521, 1720, 1723, 1755, 1761, 1801, 1900, 1935, 1998, 2000, 2001, 2002, 2003, 2005, 2049, 2103, 2105, 2107, 
    2121, 2161, 2301, 2383, 2401, 2601, 2717, 2869, 2967, 3000, 3001, 3128, 3268, 3306, 3389, 3689, 3690, 3703, 3986, 4000, 4001, 
    4045, 4899, 5000, 5001, 5003, 5009, 5050, 5051, 5060, 5101, 5120, 5190, 5357, 5432, 5555, 5631, 5666, 5800, 5900, 5901, 6000, 
    6001, 6002, 6004, 6112, 6646, 6666, 7000, 7070, 7937, 7938, 8000, 8002, 8008, 8009, 8010, 8031, 8080, 8081, 8443, 8888, 9000, 
    9001, 9090, 9100, 9102, 9999, 10000, 10001, 10010, 32768, 32771, 49152, 49153, 49154, 49155, 49156, 49157, 50000
]
```

## ⚠️ Bilgilendirme

Bu sistem, sadece Linux sistemlerde çalışır. Windows veya MacOS desteği yoktur.