# Guida Test CLI - Zero-Day Detection System

## Script Disponibili

### 1. `run_large_test.sh` (Bash Script)
Script bash semplice per eseguire il test completo con output filtrato.

### 2. `run_large_test.py` (Python Script) 
Script Python avanzato con progress bar e report dettagliati.

## Come Eseguire il Test (20 Zero-Day + 20 Regular CVE)

### Opzione 1: Usando lo Script Bash

```bash
# Con API key come parametro
./run_large_test.sh sk-or-v1-your-api-key-here

# O con API key come variabile d'ambiente
export OPENROUTER_API_KEY="sk-or-v1-your-api-key-here"
./run_large_test.sh
```

Output esempio:
```
🚀 Zero-Day Detection System - Large Scale Test
==============================================
Configuration:
  - Zero-days: 20
  - Regular CVEs: 20
  - Total samples: 40
  - Parallel execution: Enabled
  - Cache: Enabled

✓ Using API key from environment variable
✅ Connectivity test passed

🔍 Starting analysis of 40 CVEs...
This may take 10-15 minutes. Please be patient...

[1/40] CVE-2025-25257 (Zero-day)
[2/40] CVE-2025-54309 (Zero-day)
...
[40/40] CVE-2023-98765 (Regular)

📊 Summary of Results:
---------------------
  Accuracy:  75.0%
  Precision: 78.9%
  Recall:    75.0%
  F1 Score:  0.769

⏱️  Test completed in 12m 34s
✅ Test completed successfully!
```

### Opzione 2: Usando lo Script Python (Consigliato)

```bash
# Installare prima 'rich' per output migliore (opzionale)
pip install rich

# Eseguire il test
python run_large_test.py

# Con API key come parametro
python run_large_test.py --api-key sk-or-v1-your-api-key-here

# Salvare report dettagliato
python run_large_test.py --save-report test_report.txt

# Output minimale
python run_large_test.py --quiet
```

Output con Rich:
```
╭─────────────────────────────────────────────────────────╮
│ 🚀 Zero-Day Detection System - Large Scale Test         │
│ Testing 20 zero-days + 20 regular CVEs                  │
╰─────────────────────────────────────────────────────────╯

🔌 Checking API connectivity...
✅ API connected

🚀 Starting large scale test...
⏱️  Estimated time: 10-15 minutes

Analyzing CVE-2025-49706... ████████████████████░░░░░░ 75% 0:03:12

┏━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━┓
┃ Metric               ┃  Value ┃
┡━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━┩
│ Accuracy             │  75.0% │
│ Precision            │  78.9% │
│ Recall               │  75.0% │
│ F1 Score             │  0.769 │
│ Evidence Collection  │ 100.0% │
│ Uncertain Predictions│  42.5% │
└──────────────────────┴────────┘

✅ Excellent performance! Target accuracy achieved.

⏱️  Total time: 12m 34s
✅ Test completed successfully!
```

## Interpretazione dei Risultati

### Metriche Chiave

- **Accuracy**: Percentuale di predizioni corrette (target: 70-80%)
- **Precision**: Percentuale di zero-day predetti che sono realmente zero-day
- **Recall**: Percentuale di zero-day reali che sono stati identificati
- **F1 Score**: Media armonica di precision e recall
- **Evidence Collection**: Successo nella raccolta di evidenze web
- **Uncertain Predictions**: Percentuale di predizioni con alta incertezza

### Valutazione Performance

- **✅ Eccellente**: Accuracy ≥ 75%
- **✓ Buono**: Accuracy 70-75%
- **⚠️ Sotto target**: Accuracy < 70%

### File di Output

I risultati vengono salvati in:
- `logs/large_test_YYYYMMDD_HHMMSS.log` - Log completo
- `results/fixed_test_YYYYMMDD_HHMMSS.json` - Risultati JSON dettagliati

## Opzioni Avanzate

### Test Personalizzato

Per eseguire test con numeri diversi di CVE:
```bash
python run_test_fixed.py --zero-days 10 --regular 30 --parallel
```

### Debug e Troubleshooting

1. **Controllare connettività**:
   ```bash
   python test_api_connectivity.py
   ```

2. **Test veloce (2+2 CVE)**:
   ```bash
   python run_test_fixed.py --zero-days 2 --regular 2
   ```

3. **Logs dettagliati**:
   - Controllare `logs/` per output completo
   - Controllare `logs/api_calls_*.log` per debug API

## Requisiti

- Python 3.7+
- API Key OpenRouter valida
- Connessione internet per web scraping
- ~15 minuti per test completo (40 CVE)

## Note

- Il test usa esecuzione parallela per velocizzare
- Le evidenze vengono cachate per 7 giorni
- Alta incertezza (>70%) indica necessità di revisione umana
- I risultati possono variare leggermente tra esecuzioni