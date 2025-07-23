# Zero-Day LLM Ensemble

Sistema di rilevamento zero-day basato su ensemble di LLM che classifica vulnerabilità CVE senza data leakage.

## 🎯 Caratteristiche Principali

- **5 Agenti LLM Specializzati**: Analisi multi-prospettiva delle vulnerabilità
- **Zero Data Leakage**: Classificazione basata esclusivamente sul contenuto CVE
- **Prompt Open-Ended**: I modelli ragionano liberamente senza pattern hardcoded
- **Visualizzazioni Automatiche**: 6 grafici di performance generati automaticamente
- **Monitoraggio Real-time**: Statistiche live durante l'esecuzione

## 📊 Performance

Su dataset bilanciato (50 CVE: 25 zero-day, 25 regular):

- **Accuracy**: ~70%
- **Precision**: ~80% (basso tasso di falsi positivi)
- **Recall**: ~45% (identifica quasi metà degli zero-day)
- **Zero falsi positivi** su CVE regular in molti test

## 🚀 Quick Start

### 1. Installazione

```bash
# Clone repository
git clone https://github.com/yourusername/zero-day-llm-ensemble.git
cd zero-day-llm-ensemble

# Installa dipendenze
pip install -r requirements.txt

# Configura API key OpenRouter
export OPENROUTER_API_KEY="your-api-key"
```

### 2. Esegui Test

```bash
# Test veloce (20 CVE, ~5 minuti)
python run_complete_test.py --zero-days 10 --regular 10 --parallel

# Test medio (50 CVE, ~15 minuti) 
python run_complete_test.py --zero-days 25 --regular 25 --parallel

# Test completo (100 CVE, ~30 minuti)
python run_complete_test.py --zero-days 50 --regular 50 --parallel
```

### 3. Output

I risultati vengono salvati in:
- `results/complete_test_TIMESTAMP.json` - Dati completi
- `results/analysis_plots_TIMESTAMP.png` - 6 grafici di analisi
- `results/report_TIMESTAMP.txt` - Report testuale

## 🤖 Agenti LLM

| Agente | Modello | Specializzazione |
|--------|---------|------------------|
| ForensicAnalyst | Mixtral-8x22B | Analisi forense e indicatori di exploitation |
| PatternDetector | Claude Opus 4 | Riconoscimento pattern linguistici e tecnici |
| TemporalAnalyst | Llama 3.3 70B | Analisi temporale e urgenza |
| AttributionExpert | DeepSeek R1 | Valutazione threat actor e targeting |
| MetaAnalyst | Gemini 2.5 Pro | Sintesi e decisione finale |

## 📈 Visualizzazioni Generate

1. **Confusion Matrix** - Mostra TP/FP/TN/FN
2. **Performance Metrics** - Barre con Accuracy, Precision, Recall, F1
3. **Score Distribution** - Istogramma delle probabilità per classe
4. **ROC Curve** - Trade-off tra TPR e FPR
5. **Prediction Timeline** - Andamento predizioni nel tempo
6. **Accuracy by Confidence** - Performance per livello di confidenza

## 🔧 Architettura

```
zero-day-llm-ensemble/
├── src/
│   ├── agents/          # Implementazione dei 5 agenti LLM
│   ├── data/            # Raccolta dati da CISA KEV e NVD
│   ├── ensemble/        # Sistema multi-agente e voting
│   └── utils/           # Logger e utilities
├── config/
│   ├── prompts.yaml     # Prompt open-ended per gli agenti
│   └── settings.py      # Configurazione modelli e API
├── run_complete_test.py # Script principale con visualizzazioni
├── run_balanced_test.py # Test con bilanciamento garantito
└── results/             # Output (gitignored)
```

## 💡 Come Funziona

1. **Raccolta Dati**: Fetch da CISA KEV (zero-day confermati) e NVD (CVE regular)
2. **Preprocessing**: Validazione e preparazione dati senza leakage
3. **Analisi Multi-Agente**: Ogni agente analizza la CVE dalla sua prospettiva
4. **Ensemble Voting**: Media pesata delle predizioni (pesi uguali)
5. **Classificazione**: Soglia 0.5 per distinguere zero-day da regular

## 🛠️ Personalizzazione

### Cambiare Modelli LLM

Modifica `config/settings.py`:

```python
MODEL_CONFIGS = {
    'ForensicAnalyst': 'mistralai/mixtral-8x22b-instruct',
    'PatternDetector': 'anthropic/claude-opus-4',
    # ... altri modelli
}
```

### Modificare Prompt

I prompt sono in `config/prompts.yaml`. Usa prompt open-ended che permettono ai modelli di ragionare liberamente.

## 📝 Esempio di Utilizzo

```python
from src.ensemble.multi_agent import MultiAgentSystem
from src.data.preprocessor import DataPreprocessor

# Inizializza
system = MultiAgentSystem(parallel_execution=True)
preprocessor = DataPreprocessor()

# Analizza una CVE
cve_data = {
    'cve_id': 'CVE-2024-1234',
    'vendor': 'Microsoft',
    'product': 'Windows',
    'description': 'Remote code execution vulnerability...',
    'year': 2024
}

# Preprocessa e analizza
processed = preprocessor.preprocess_entry(cve_data)
result = system.analyze_vulnerability(processed)

# Risultato
prediction = result['ensemble']['prediction']
print(f"Probabilità zero-day: {prediction:.1%}")
```

## ⚠️ Note Importanti

- **Nessun Data Leakage**: I prompt non menzionano mai la fonte dei dati
- **Ragionamento Libero**: I modelli non cercano pattern specifici hardcoded
- **API Key Richiesta**: Necessaria API key di OpenRouter
- **Cache Locale**: I dati vengono cachati per ridurre le chiamate API

## 🏆 Punti di Forza

1. **Alta Precisione**: Quando identifica uno zero-day, raramente sbaglia
2. **Zero Bias**: Nessun riferimento alla fonte nei prompt
3. **Scalabile**: Supporta esecuzione parallela degli agenti
4. **Trasparente**: Log dettagliati di ogni predizione

## 📄 License

MIT License

## 🤝 Contributing

1. Fork il repository
2. Crea un branch (`git checkout -b feature/AmazingFeature`)
3. Commit (`git commit -m 'Add AmazingFeature'`)
4. Push (`git push origin feature/AmazingFeature`)
5. Apri una Pull Request

## 🙏 Acknowledgments

- CISA per il catalogo Known Exploited Vulnerabilities
- NVD per il database delle vulnerabilità
- OpenRouter per l'accesso ai modelli LLM