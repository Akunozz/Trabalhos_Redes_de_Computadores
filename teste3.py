from scapy.all import rdpcap
from datetime import datetime
from collections import defaultdict
from pyecharts import options as opts
from pyecharts.charts import Line

# Carrega o arquivo pcapng
pacotes = rdpcap("trabalho1.pcapng")

# Dicionário para armazenar o tráfego por endereço IP
trafego_por_ip = defaultdict(int)

# Define o intervalo de tempo (em segundos)
intervalo = 1

# Calcula o primeiro e o último tempo de captura
primeiro_tempo = pacotes[0].time
ultimo_tempo = pacotes[-1].time

# Define os intervalos de tempo
intervalos = range(int(primeiro_tempo), int(ultimo_tempo), intervalo)

# Itera sobre os pacotes e conta o tráfego por endereço IP
for pacote in pacotes:
    if "IP" in pacote:
        ip_origem = pacote["IP"].src
        trafego_por_ip[ip_origem] += 1

# Prepara os dados para o gráfico
dados_grafico = sorted(trafego_por_ip.items(), key=lambda x: x[1], reverse=True)

# Cria o gráfico usando ECharts
line = (
    Line()
    .add_xaxis([str(ip[0]) for ip in dados_grafico])
    .add_yaxis("Volume de Tráfego por IP", [volume[1] for volume in dados_grafico], symbol='circle', is_symbol_show=True)
    .set_series_opts(label_opts=opts.LabelOpts(is_show=False))
    .set_global_opts(
        xaxis_opts=opts.AxisOpts(name="Endereço IP"),
        yaxis_opts=opts.AxisOpts(name="Volume de Tráfego"),
        title_opts=opts.TitleOpts(title=f"Volume de Tráfego por Endereço IP"),
    )
)

# Renderiza o gráfico
line.render("grafico_volume_trafego_por_ip.html")
