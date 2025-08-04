# Come Testare il Sistema

## Setup Iniziale
```bash
# 1. Verifica di avere l'API key
cat .env
# Deve mostrare: OPENROUTER_API_KEY=sk-or-v1-...

# 2. Installa dipendenze (se non l'hai già fatto)
pip install -r requirements.txt
```

## Test Principale - QUESTO È IL METODO DA USARE

```bash
# Scegli quante CVE testare
python test_system.py --zero-days 20 --regular 20
```

### Cosa fa:
1. **Controllo Cache**: Vede quali CVE sono già state testate
2. **Selezione Smart**: 
   - Usa prima le CVE già in cache
   - Scarica solo quelle mancanti
3. **Ground Truth Verificata**: Usa solo fonti pubbliche
4. **Risultati Chiari**: Mostra confusion matrix e metriche

### Esempi:

```bash
# Test piccolo (10+10)
python test_system.py --zero-days 10 --regular 10

# Test medio (20+20) 
python test_system.py --zero-days 20 --regular 20

# Test grande (30+30)
python test_system.py --zero-days 30 --regular 30

# Vedere quante CVE verificate abbiamo
python test_system.py --list-available
```

## Altri Comandi Utili

### Demo Veloce (senza API):
```bash
python quick_test.py
```
Mostra i risultati già calcolati su 30 CVE.

### Analisi Singola CVE:
```bash
python detect_zero_days.py CVE-2024-3400
```

## Note Importanti

- **Rate Limiting**: Massimo ~40 CVE/ora
- **Cache**: I risultati vengono salvati, non serve ri-testare
- **Ground Truth**: Basata SOLO su fonti pubbliche (CISA KEV, vendor)
- **Delay**: 3-5 secondi tra le chiamate API

## Risultati

I risultati vengono salvati in:
- `results/balanced_test_YYYYMMDD_HHMMSS.json`
- Cache aggiornata in `cache/detection_cache.json`

## Performance Attuale

Con 30 CVE testate:
- **Accuracy**: 80%
- **Recall**: 100% (trova tutti gli zero-day)
- **Precision**: 76% (alcuni falsi positivi)