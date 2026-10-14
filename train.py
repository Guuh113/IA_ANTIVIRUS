import numpy as np
from sklearn.ensemble import RandomForestClassifier
import joblib

np.random.seed(42)

# Gerar dados calibrados para evitar falsos positivos em programas legítimos
# Amostras Benignas (Software Legítimo como calc.exe)
benignos = []
for _ in range(1200):
    num_secoes = np.random.randint(3, 6)
    entropia_media = np.random.uniform(3.5, 5.2)
    entropia_max = np.random.uniform(4.5, 6.6)
    num_dlls = np.random.randint(10, 80)
    num_funcoes = np.random.randint(100, 1500)
    tam_codigo = np.random.randint(20000, 500000)
    tam_dados = np.random.randint(10000, 300000)
    apis_susp = np.random.choice([0, 1], p=[0.92, 0.08])
    sec_anomalas = 0
    packer = 0
    benignos.append([num_secoes, entropia_media, entropia_max, num_dlls, num_funcoes, tam_codigo, tam_dados, apis_susp, sec_anomalas, packer])

# Amostras Maliciosas (Ransomware, Trojans, Packers)
malwares = []
for _ in range(1200):
    num_secoes = np.random.randint(2, 12)
    entropia_media = np.random.uniform(6.0, 7.8)
    entropia_max = np.random.uniform(7.1, 7.99)
    num_dlls = np.random.randint(1, 15)
    num_funcoes = np.random.randint(10, 150)
    tam_codigo = np.random.randint(5000, 2000000)
    tam_dados = np.random.randint(50000, 5000000)
    apis_susp = np.random.randint(2, 8)
    sec_anomalas = np.random.choice([0, 1, 2], p=[0.3, 0.5, 0.2])
    packer = 1
    malwares.append([num_secoes, entropia_media, entropia_max, num_dlls, num_funcoes, tam_codigo, tam_dados, apis_susp, sec_anomalas, packer])

X = np.array(benignos + malwares)
y = np.array([0] * 1200 + [1] * 1200)

modelo = RandomForestClassifier(n_estimators=150, max_depth=12, random_state=42)
modelo.fit(X, y)

joblib.dump(modelo, "modelo_malware.pkl")
print("Cérebro da IA re-treinado com sucesso e guardado em 'modelo_malware.pkl'!")