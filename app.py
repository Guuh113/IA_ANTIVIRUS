import os
import math
import re
import joblib
import pefile
from urllib.parse import urlparse
from datetime import datetime
from flask import Flask, request, jsonify, render_template_string
from extractor import extrair_caracteristicas_memoria

app = Flask(__name__)

# Base de dados em memória para o histórico de varreduras
HISTORICO_VARREDURAS = []

def classificar_risco(prob):
    if prob > 70:
        return "Perigoso", "#ff0055"
    elif prob > 30:
        return "Possível Vírus", "#ffb700"
    else:
        return "Normal", "#00ff88"

def analisar_link_heuristica(url):
    risco = 10
    alertas = []
    
    parsed = urlparse(url)
    dominio = parsed.netloc or parsed.path
    
    # Verificação de endereço IP em vez de domínio
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', dominio):
        risco += 35
        alertas.append("Uso direto de IP no lugar de domínio legítimo")
        
    # Verificação de extensão executável direta na URL
    if any(url.lower().endswith(ext) for ext in ['.exe', '.dll', '.scr', '.bat', '.ps1']):
        risco += 40
        alertas.append("O link aponta diretamente para um ficheiro executável")
        
    # Palavras-chave associadas a Phishing ou Engenharia Social
    palavras_suspeitas = ['login', 'verify', 'account', 'banking', 'update', 'secure', 'free', 'bonus']
    encontradas = [p for p in palavras_suspeitas if p in url.lower()]
    if encontradas:
        risco += len(encontradas) * 15
        alertas.append(f"Termos sensíveis identificados: {', '.join(encontradas)}")
        
    # Comprimento excessivo do link
    if len(url) > 75:
        risco += 15
        alertas.append("Comprimento da URL anormalmente longo")

    prob = min(risco, 99.0)
    classificacao, cor = classificar_risco(prob)
    
    return {
        'tipo': 'LINK',
        'alvo': url,
        'probabilidade_malware': round(prob, 2),
        'classificacao': classificacao,
        'cor': cor,
        'alertas': alertas if alertas else ["Nenhum indicador malicioso de URL encontrado"],
        'data': datetime.now().strftime("%H:%M:%S")
    }

HTML_INTERFACE = """
<!DOCTYPE html>
<html lang="pt">
<head>
    <meta charset="UTF-8">
    <title>CyberShield AI - Security Center</title>
    <style>
        :root {
            --bg-dark: #0b0f19;
            --card-bg: #111827;
            --accent: #00f0ff;
            --border: #1e293b;
            --text: #e2e8f0;
        }
        body { background: var(--bg-dark); color: var(--text); font-family: 'Segoe UI', sans-serif; margin: 0; padding: 25px; }
        .container { max-width: 1050px; margin: 0 auto; }
        .header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 15px; margin-bottom: 25px; }
        .tabs { display: flex; gap: 10px; margin-bottom: 20px; }
        .tab-btn { background: #1e293b; color: #fff; border: none; padding: 10px 20px; border-radius: 6px; cursor: pointer; font-weight: bold; }
        .tab-btn.active { background: var(--accent); color: #000; }
        .card { background: var(--card-bg); border: 1px solid var(--border); border-radius: 10px; padding: 20px; margin-bottom: 20px; }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        input[type="text"] { width: 80%; padding: 10px; background: #0f172a; border: 1px solid var(--border); color: #fff; border-radius: 6px; }
        button.action-btn { background: var(--accent); border: none; padding: 10px 20px; color: #000; font-weight: bold; border-radius: 6px; cursor: pointer; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        th, td { border: 1px solid var(--border); padding: 10px; text-align: left; font-size: 13px; }
        th { background: #0f172a; color: var(--accent); }
        .badge { padding: 4px 10px; border-radius: 12px; font-weight: bold; font-size: 11px; display: inline-block; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h2 style="color:var(--accent); margin:0;">🛡️ CyberShield AI // Scanner Platform</h2>
            <span style="font-size:12px; color:#94a3b8;">SISTEMA OPERACIONAL</span>
        </div>

        <div class="tabs">
            <button class="tab-btn active" onclick="switchTab('ficheiro')">Ficheiro / Pasta</button>
            <button class="tab-btn" onclick="switchTab('link')">Analisar Link (URL)</button>
        </div>

        <!-- ABA 1: FICHEIRO OU PASTA -->
        <div id="tab-ficheiro" class="tab-content active">
            <div class="card">
                <h3>Análise Estática de Ficheiros ou Pastas (.exe, .dll)</h3>
                <p style="font-size:13px; color:#94a3b8;">Selecione um ficheiro único ou uma pasta completa para verificação paralela.</p>
                <input type="file" id="fileInput" multiple webkitdirectory directory>
                <button class="action-btn" onclick="analisarFicheiros()">Efetuar Varredura</button>
            </div>
        </div>

        <!-- ABA 2: ANALISAR LINK -->
        <div id="tab-link" class="tab-content">
            <div class="card">
                <h3>Análise de Segurança de URLs e Domains</h3>
                <p style="font-size:13px; color:#94a3b8;">Introduza o endereço web para verificar indicadores de risco ou phishing.</p>
                <input type="text" id="urlInput" placeholder="https://exemplo.com/download.exe">
                <button class="action-btn" onclick="analisarURL()">Analisar Link</button>
            </div>
        </div>

        <!-- HISTÓRICO DE VARREDURAS -->
        <div class="card">
            <h3>Histórico de Varreduras da Sessão</h3>
            <table>
                <thead>
                    <tr>
                        <th>Hora</th>
                        <th>Tipo</th>
                        <th>Alvo / Nome</th>
                        <th>Risco Calculado</th>
                        <th>Classificação</th>
                    </tr>
                </thead>
                <tbody id="historicoBody">
                    <tr><td colspan="5" style="text-align:center; color:#64748b;">Nenhuma varredura efetuada até ao momento.</td></tr>
                </tbody>
            </table>
        </div>
    </div>

    <script>
        function switchTab(tab) {
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            
            if(tab === 'ficheiro') {
                document.querySelectorAll('.tab-btn')[0].classList.add('active');
                document.getElementById('tab-ficheiro').classList.add('active');
            } else {
                document.querySelectorAll('.tab-btn')[1].classList.add('active');
                document.getElementById('tab-link').classList.add('active');
            }
        }

        async function atualizarHistorico() {
            const res = await fetch('/api/historico');
            const dados = await res.json();
            const body = document.getElementById('historicoBody');
            
            if(dados.length === 0) return;
            
            body.innerHTML = dados.map(item => `
                <tr>
                    <td>${item.data}</td>
                    <td><strong>${item.tipo}</strong></td>
                    <td>${item.alvo}</td>
                    <td>${item.probabilidade_malware}%</td>
                    <td><span class="badge" style="background:${item.cor}22; color:${item.cor}; border: 1px solid ${item.cor}">${item.classificacao}</span></td>
                </tr>
            `).join('');
        }

        async function analisarFicheiros() {
            const input = document.getElementById('fileInput');
            if (input.files.length === 0) { alert('Selecione ficheiros ou uma pasta primeiro.'); return; }

            for (let file of input.files) {
                if(!file.name.match(/\.(exe|dll|sys)$/i)) continue;
                
                const formData = new FormData();
                formData.append('file', file);
                await fetch('/api/analisar-ficheiro', { method: 'POST', body: formData });
            }
            atualizarHistorico();
        }

        async function analisarURL() {
            const url = document.getElementById('urlInput').value;
            if (!url) { alert('Insira uma URL válida.'); return; }

            await fetch('/api/analisar-url', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: url })
            });
            document.getElementById('urlInput').value = '';
            atualizarHistorico();
        }
    </script>
</body>
</html>
"""

@app.route('/')
def home():
    return render_template_string(HTML_INTERFACE)

@app.route('/api/historico', methods=['GET'])
def get_historico():
    return jsonify(HISTORICO_VARREDURAS)

@app.route('/api/analisar-ficheiro', methods=['POST'])
def api_analisar_ficheiro():
    if 'file' not in request.files:
        return jsonify({'erro': 'Nenhum ficheiro recebido'}), 400
    
    file = request.files['file']
    try:
        conteudo = file.read()
        vetor, detalhes = extrair_caracteristicas_memoria(conteudo)
        
        if vetor is None:
            return jsonify({'erro': 'Estrutura incompatível'}), 400
            
        modelo = joblib.load("modelo_malware.pkl")
        prob = modelo.predict_proba([vetor])[0][1] * 100
        classificacao, cor = classificar_risco(prob)
        
        registro = {
            'tipo': 'FICHEIRO',
            'alvo': file.filename,
            'probabilidade_malware': round(prob, 2),
            'classificacao': classificacao,
            'cor': cor,
            'data': datetime.now().strftime("%H:%M:%S")
        }
        
        HISTORICO_VARREDURAS.insert(0, registro)
        return jsonify(registro)
    except Exception as e:
        return jsonify({'erro': str(e)}), 500

@app.route('/api/analisar-url', methods=['POST'])
def api_analisar_url():
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({'erro': 'URL não fornecida'}), 400
        
    resultado = analisar_link_heuristica(data['url'])
    HISTORICO_VARREDURAS.insert(0, resultado)
    return jsonify(resultado)

if __name__ == '__main__':
    print("Servidor CyberShield ativo em http://127.0.0.1:5000")
    app.run(host='127.0.0.1', port=5000, debug=True)