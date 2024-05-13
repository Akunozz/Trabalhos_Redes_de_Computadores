import pyshark
import matplotlib.pyplot as plt

# Caminho para o arquivo pcap
pcap_file = 'arp.pcap'

# Dicionário para mapear códigos OUI para marcas de placa de rede
oui_to_brand = {
    '00:0C:29': 'VMware',
    '00:50:56': 'VMware',
    '00:1C:14': 'Cisco',
    '9C:14:63': 'Zhejiang Dahua Technology Co., Ltd.',
    'E0:50:8B': 'Zhejiang Dahua Technology Co., Ltd.',
    '38:AF:29': 'Zhejiang Dahua Technology Co., Ltd.',
    '44:DF:65': 'Beijing Xiaomi Mobile Software Co., Ltd',
    '24:18:C6': 'HUNAN FN-LINK TECHNOLOGY LIMITED',
    '14:A7:8B': 'Zhejiang Dahua Technology Co., Ltd.',
    '80:19:34': 'Intel Corporate',
    '5C:D9:98': 'D-Link Corporation',
    '60:AB:67': 'Xiaomi Communications Co Ltd',
    '54:EF:44': 'Lumi United Technology Co., Ltd',
    'DA:A9:53': 'Technicolor CH USA Inc.',
}

# Função para obter a marca da placa de rede com base no endereço MAC
def get_mac_vendor(mac_address):
    # Obter os 6 primeiros caracteres do endereço MAC
    oui = mac_address[:8].upper()
    # Verificar se o OUI está mapeado em oui_to_brand, se não, retornar o próprio OUI
    return oui_to_brand.get(oui, oui)

# Dicionário para armazenar a contagem de endereços MAC por marca de placa de rede
mac_counts = {}

# Conjunto para armazenar marcas de placa de rede não mapeadas
unmapped_brands = set()

# Analisar o arquivo pcap
cap = pyshark.FileCapture(pcap_file)
for pkt in cap:
    if 'ARP' in pkt:
        mac_address = pkt.arp.src_hw_mac
        mac_vendor = get_mac_vendor(mac_address)
        if mac_vendor in mac_counts:
            mac_counts[mac_vendor] += 1
        else:
            mac_counts[mac_vendor] = 1
            if mac_vendor not in oui_to_brand.values():
                unmapped_brands.add(mac_vendor)

cap.close()

# Imprimir lista de códigos OUI e marcas de placa de rede
print("Códigos OUI e marcas de placa de rede:")
for oui, brand in oui_to_brand.items():
    print(f"{oui}: {brand}")

# Imprimir marcas de placa de rede não mapeadas
if unmapped_brands:
    print("\nMarcas de placa de rede não mapeadas:")
    for brand in unmapped_brands:
        print(brand)

# Plotar o gráfico
sorted_mac_counts = sorted(mac_counts.items(), key=lambda x: x[1], reverse=True)
top_brands = [brand for brand, count in sorted_mac_counts[:10]]
counts = [count for brand, count in sorted_mac_counts[:10]]

plt.barh(top_brands, counts)
plt.xlabel('Quantidade de Dispositivos')
plt.ylabel('Marca da Placa de Rede')
plt.title('Marcas de Placas de Rede Mais Usadas')
plt.show()