import json, os
from collections import Counter
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

def load_results(path):
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f).get('results', [])

core = load_results('out/core.json')
admin = load_results('out/admin.json')
soap = load_results('out/soap.json')
all_res = core + admin + soap

sev_map = {'ERROR': 'Alta', 'WARNING': 'Media', 'INFO': 'Baja'}
projects = {'Core bWAPP': core, 'admin': admin, 'soap (NuSOAP)': soap}

# Gráfica 1: Proyecto y Severidad
fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4.5))
names = list(projects.keys())
alta = [sum(1 for r in projects[p] if r['extra']['severity']=='ERROR') for p in names]
media = [sum(1 for r in projects[p] if r['extra']['severity']=='WARNING') for p in names]
baja = [sum(1 for r in projects[p] if r['extra']['severity']=='INFO') for p in names]

ax1.bar(names, alta, label='Alta', color='#c0392b')
ax1.bar(names, media, bottom=alta, label='Media', color='#e67e22')
ax1.bar(names, baja, bottom=[a+m for a,m in zip(alta,media)], label='Baja', color='#2980b9')
ax1.set_title('Hallazgos por Proyecto y Severidad')
ax1.set_ylabel('Cantidad de Hallazgos')
ax1.legend()

tot_sev = [sum(alta), sum(media), sum(baja)]
ax2.pie(tot_sev, labels=[f'Alta ({tot_sev[0]})', f'Media ({tot_sev[1]})', f'Baja ({tot_sev[2]})'],
        autopct='%1.0f%%', colors=['#c0392b', '#e67e22', '#2980b9'], startangle=90)
ax2.set_title('Distribución Total por Severidad')
plt.tight_layout()
plt.savefig('grafica1_severidad.png', dpi=150)
plt.close()

# Gráfica 2: OWASP Top 10
owasp_counts = Counter(r['extra']['metadata'].get('owasp', 'Otros') for r in all_res)
items = owasp_counts.most_common()
plt.figure(figsize=(9, 4.5))
plt.barh([i[0] for i in items][::-1], [i[1] for i in items][::-1], color='#2c3e50')
plt.title('Hallazgos por Categoría OWASP Top 10 (2021)')
plt.xlabel('Hallazgos')
plt.tight_layout()
plt.savefig('grafica2_owasp.png', dpi=150)
plt.close()

# Gráfica 3: Top 10 archivos en Core
file_counts = Counter(os.path.basename(r['path']) for r in core).most_common(10)
plt.figure(figsize=(9, 4.5))
plt.barh([i[0] for i in file_counts][::-1], [i[1] for i in file_counts][::-1], color='#8e44ad')
plt.title('Top 10 Archivos Más Afectados (Core bWAPP)')
plt.xlabel('Hallazgos')
plt.tight_layout()
plt.savefig('grafica3_archivos.png', dpi=150)
plt.close()

# Dashboard HTML (Tarea T8)
rows_html = ""
for r in all_res[:60]:
    sev = sev_map.get(r['extra']['severity'], 'Media')
    badge = '#c0392b' if sev=='Alta' else ('#e67e22' if sev=='Media' else '#2980b9')
    rows_html += f"<tr><td><span style='background:{badge};color:#fff;padding:2px 8px;border-radius:4px;font-size:12px'>{sev}</span></td><td>{os.path.basename(r['path'])}:{r['start']['line']}</td><td>{r['extra']['metadata'].get('owasp','')}</td><td>{r['extra']['metadata'].get('cwe','')}</td><td>{r['extra']['message']}</td></tr>"

html = f"""<!DOCTYPE html><html lang="es"><head><meta charset="UTF-8"><title>Dashboard SAST - Jose Donaldo Pacay Saenz</title>
<style>body{{font-family:Segoe UI,Arial,sans-serif;background:#0f172a;color:#f8fafc;margin:0;padding:24px}}
.header{{background:#1e293b;padding:20px;border-radius:10px;border-left:5px solid #38bdf8;margin-bottom:20px}}
.cards{{display:grid;grid-template-columns:repeat(4,1fr);gap:15px;margin-bottom:20px}}
.card{{background:#1e293b;padding:18px;border-radius:10px;text-align:center}}
.num{{font-size:32px;font-weight:bold;color:#38bdf8}}
.charts{{display:grid;grid-template-columns:repeat(3,1fr);gap:15px;margin-bottom:20px}}
.charts img{{width:100%;border-radius:8px;background:#fff;padding:5px}}
table{{width:100%;border-collapse:collapse;background:#1e293b;border-radius:10px;overflow:hidden}}
th,td{{padding:10px;text-align:left;border-bottom:1px solid #334155;font-size:13px}}
th{{background:#0284c7;color:#fff}}</style></head><body>
<div class="header"><h1>Evaluación SAST con Semgrep — Repositorio bWAPP</h1>
<p><strong>Universidad Mariano Gálvez de Guatemala</strong> | Maestría en Seguridad de Aplicaciones | Estudiante: <strong>Jose Donaldo Pacay Saenz</strong></p></div>
<div class="cards">
<div class="card"><div class="num">{len(all_res)}</div><div>Hallazgos Totales</div></div>
<div class="card"><div class="num" style="color:#ef4444">{sum(alta)}</div><div>Severidad Alta</div></div>
<div class="card"><div class="num" style="color:#f59e0b">{sum(media)}</div><div>Severidad Media</div></div>
<div class="card"><div class="num" style="color:#10b981">{sum(alta)*5 + sum(media)*3 + sum(baja)} pts</div><div>Índice de Riesgo</div></div>
</div>
<div class="charts"><img src="grafica1_severidad.png"><img src="grafica2_owasp.png"><img src="grafica3_archivos.png"></div>
<h2>Detalle de Hallazgos Detectados (Muestra Priorizada)</h2>
<table><thead><tr><th>Severidad</th><th>Archivo y Línea</th><th>OWASP Top 10</th><th>CWE</th><th>Descripción</th></tr></thead><tbody>{rows_html}</tbody></table>
</body></html>"""

with open('dashboard.html', 'w', encoding='utf-8') as f:
    f.write(html)
print("Listo: graficas PNG y dashboard.html creados correctamente.")
