from collections import defaultdict
from pyecharts import options as opts
from pyecharts.charts import Line
from scapy.all import rdpcap

# Carrega o arquivo pcapng
pacotes = rdpcap("trabalho1.pcapng")

# Dicionário para armazenar o tráfego por IP ao longo do tempo
trafego_por_ip_e_tempo = defaultdict(lambda: defaultdict(int))

# Obtém o tempo inicial e final do tráfego
primeiro_tempo = pacotes[0].time
ultimo_tempo = pacotes[-1].time

# Itera sobre os pacotes e obtém informações de tráfego por IP ao longo do tempo
for pacote in pacotes:
    if 'IP' in pacote:
        ip_origem = pacote['IP'].src
        ip_destino = pacote['IP'].dst
        tempo = int(pacote.time - primeiro_tempo)  # Convertendo para segundos

        # Atualiza o dicionário de tráfego por IP ao longo do tempo
        trafego_por_ip_e_tempo[ip_origem][tempo] += 1
        trafego_por_ip_e_tempo[ip_destino][tempo] += 1

# Cria gráfico de linha usando Pyecharts
def create_line_chart(ip_trafego_tempo_dict, title):
    line = Line()
    line.set_global_opts(title_opts=opts.TitleOpts(title=title))
    for ip, tempo_trafego in ip_trafego_tempo_dict.items():
        tempo_list = list(tempo_trafego.keys())
        trafego_list = list(tempo_trafego.values())
        line.add_xaxis(tempo_list)
        line.add_yaxis(ip, trafego_list, is_smooth=True)
    return line

# Cria gráfico de linha para mostrar o tráfego por IP ao longo do tempo
line_chart = create_line_chart(trafego_por_ip_e_tempo, "Tráfego por IP ao longo do tempo")

# Renderiza o gráfico se ele existir
if line_chart:
    line_chart.render("trafego_por_ip_tempo.html")
