import math
import hashlib
import pefile

# APIs comummente exploradas por malwares para injeção e evasão
APIS_SUSPEITAS = {
    'virtualalloc', 'virtualalloc-ex', 'writeprocessmemory', 'createremotethread',
    'isdebuggerpresent', 'internetopenw', 'urldownloadtofilew', 'winexec', 'shellwait'
}

def calcular_entropia(dados):
    if not dados:
        return 0.0
    entropia = 0
    for x in range(256):
        p_x = dados.count(bytes([x])) / len(dados)
        if p_x > 0:
            entropia += - p_x * math.log2(p_x)
    return entropia

def extrair_caracteristicas_memoria(conteudo_bytes):
    try:
        pe = pefile.PE(data=conteudo_bytes)
        
        num_secoes = len(pe.sections)
        entropias = [calcular_entropia(sec.get_data()) for sec in pe.sections]
        entropia_media = sum(entropias) / len(entropias) if entropias else 0
        entropia_maxima = max(entropias) if entropias else 0
        
        num_dlls = 0
        num_funcoes = 0
        apis_suspeitas_encontradas = []
        
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            num_dlls = len(pe.DIRECTORY_ENTRY_IMPORT)
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    num_funcoes += 1
                    if imp.name:
                        nome_funcao = imp.name.decode('utf-8', errors='ignore').lower()
                        if nome_funcao in APIS_SUSPEITAS:
                            apis_suspeitas_encontradas.append(nome_funcao)
                            
        tamanho_codigo = pe.OPTIONAL_HEADER.SizeOfCode
        tamanho_dados = pe.OPTIONAL_HEADER.SizeOfInitializedData
        
        # Anomalias de permissão executável/escrita simultânea nas secções
        secoes_anomalas = 0
        for sec in pe.sections:
            if (sec.Characteristics & 0x20000000) and (sec.Characteristics & 0x80000000):
                secoes_anomalas += 1

        pe.close()
        
        md5 = hashlib.md5(conteudo_bytes).hexdigest()
        sha256 = hashlib.sha256(conteudo_bytes).hexdigest()

        vetor_caracteristicas = [
            num_secoes,
            entropia_media,
            entropia_maxima,
            num_dlls,
            num_funcoes,
            tamanho_codigo,
            tamanho_dados,
            len(apis_suspeitas_encontradas),
            secoes_anomalas,
            1 if entropia_maxima > 7.1 else 0  # Indicador de empacotador (packer/criptografia)
        ]

        detalhes = {
            'md5': md5,
            'sha256': sha256,
            'apis_suspeitas': list(set(apis_suspeitas_encontradas)),
            'secoes_anomalas': secoes_anomalas
        }

        return vetor_caracteristicas, detalhes
    except Exception as e:
        return None, None