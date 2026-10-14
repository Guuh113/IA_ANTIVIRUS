import joblib
from extractor import extrair_caracteristicas

def analisar_ficheiro(caminho_ficheiro):
    # 1. Carregar o modelo de IA treinado
    modelo = joblib.load("modelo_malware.pkl")
    
    # 2. Extrair as características estruturais do ficheiro
    caracteristicas = extrair_caracteristicas(caminho_ficheiro)
    
    if caracteristicas is None:
        print("Erro: Não foi possível processar o ficheiro indicado.")
        return
    
    # 3. Prever a probabilidade de ser malware (0 = Seguro, 1 = Malware)
    probabilidades = modelo.predict_proba([caracteristicas])[0]
    prob_malware = probabilidades[1] * 100
    
    # 4. Exibir o resultado final
    print("\n==========================================")
    print("      RELATÓRIO DE ANÁLISE DE SEGURANÇA   ")
    print("==========================================")
    print(f"Ficheiro: {caminho_ficheiro}")
    print(f"Probabilidade de Malware: {prob_malware:.2f}%")
    
    if prob_malware > 70:
        print("Classificação: [CRÍTICO] Ficheiro com alto risco de ameaça!")
    elif prob_malware > 30:
        print("Classificação: [SUSPEITO] Risco moderado detectado.")
    else:
        print("Classificação: [SEGURO] Nenhum padrão malicioso encontrado.")
    print("==========================================\n")

if __name__ == "__main__":
    # Teste de verificação com um ficheiro seguro do sistema
    ficheiro_teste = r"C:\Windows\System32\notepad.exe"
    analisar_ficheiro(ficheiro_teste)
