from scapy.all import rdpcap
from datetime import datetime
from pyecharts import options as opts
from pyecharts.charts import Line

# Carrega o arquivo pcapng
pacotes = rdpcap("trabalho1.pcapng")

# Dicionário para armazenar o tráfego por intervalo de tempo
trafego_por_intervalo = {}

# Define o intervalo de tempo (em segundos)
intervalo = 1

# Calcula o primeiro e o último tempo de captura
primeiro_tempo = pacotes[0].time
ultimo_tempo = pacotes[-1].time

# Define os intervalos de tempo
intervalos = range(int(primeiro_tempo), int(ultimo_tempo), intervalo)

# Inicializa o dicionário com contadores zerados para cada intervalo
for intervalo_tempo in intervalos:
    trafego_por_intervalo[intervalo_tempo] = 0

# Itera sobre os pacotes e calcula o volume de dados por intervalo de tempo
for pacote in pacotes:
    tempo = pacote.time
    intervalo_tempo = int(tempo) // intervalo * intervalo
    if intervalo_tempo in trafego_por_intervalo:
        trafego_por_intervalo[intervalo_tempo] += len(pacote)

# Converte os tempos dos intervalos para objetos datetime
tempos_intervalos = [datetime.fromtimestamp(intervalo_tempo) for intervalo_tempo in trafego_por_intervalo.keys()]

# Prepara os dados para o gráfico
dados_grafico = [(str(tempo), trafego_por_intervalo[intervalo_tempo]) for tempo, intervalo_tempo in zip(tempos_intervalos, trafego_por_intervalo.keys())]

# Cria o gráfico usando ECharts
line = (
    Line()
    .add_xaxis([x[0] for x in dados_grafico])
    .add_yaxis("Volume de Dados Transmitidos (bytes)", [y[1] for y in dados_grafico], symbol='circle', is_symbol_show=True)
    .set_series_opts(label_opts=opts.LabelOpts(is_show=False))
    .set_global_opts(
        xaxis_opts=opts.AxisOpts(name="Tempo", axislabel_opts={"rotate": 45}),
        yaxis_opts=opts.AxisOpts(name="Volume de Dados Transmitidos (bytes)"),
        title_opts=opts.TitleOpts(title=f"Volume de dados transmitidos por intervalo de {intervalo} segundo(s)"),
    )
)

# Renderiza o gráfico
line.render("grafico_echarts_volume_dados.html")
