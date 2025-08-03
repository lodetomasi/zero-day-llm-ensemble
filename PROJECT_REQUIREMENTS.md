# Project Requirements - Zero-Day LLM Ensemble

## 🎯 CORE OBJECTIVES (IMMUTABILI)

### 1. Sistema Multi-Agente per Zero-Day Detection
- **DEVE** usare 5 agenti LLM specializzati
- **DEVE** fare ensemble delle predizioni
- **DEVE** detectare zero-day vulnerabilities
- **NON CAMBIARE** l'architettura multi-agente

### 2. Risultati Accademicamente Validi
- **DEVE** essere generalizzabile (no hardcoding)
- **DEVE** essere riproducibile
- **DEVE** avere metriche oggettive
- **DEVE** funzionare su qualsiasi CVE

### 3. Nessuna Valutazione Umana
- **NON** richiedere security analysts
- **NON** fare user studies
- **TUTTO** deve essere automatico
- **USARE** metriche computabili

## ⚠️ VINCOLI FISSI

### Cosa NON Cambiare:
1. **Architettura**: 5 agenti (Forensic, Pattern, Temporal, Attribution, Meta)
2. **Obiettivo**: Detectare zero-day (non cambiare in "intelligence aggregation")
3. **Approccio**: Web scraping + LLM ensemble
4. **Valutazione**: Automatica basata su metriche oggettive

### Cosa È Modificabile:
1. **Implementazione** dei singoli componenti
2. **Feature engineering** (ma deve rimanere oggettiva)
3. **Metriche** (purché misurabili)
4. **Visualizzazioni** e report

## 📋 CHECKLIST SVILUPPO

Prima di proporre QUALSIASI modifica, verificare:

- [ ] Mantiene i 5 agenti?
- [ ] Mantiene focus su zero-day detection?
- [ ] È generalizzabile (no hardcoding)?
- [ ] È valutabile automaticamente?
- [ ] Non richiede valutazione umana?
- [ ] Non cambia l'obiettivo core?

Se anche solo uno è NO → NON PROPORRE LA MODIFICA

## 🔒 DECISIONI PERMANENTI

1. **Detection vs Intelligence**: Il sistema FA detection, anche se internamente aggrega intelligence
2. **Binary Output**: Alla fine DEVE dire zero-day SI/NO (anche se con confidence)
3. **Multi-Agent**: SEMPRE 5 agenti, non ridurre a single LLM
4. **Evaluation**: SOLO automatica, mai umana

## 📊 METRICHE RICHIESTE

### Primarie (OBBLIGATORIE):
- Accuracy (su ground truth verificabile)
- Precision/Recall/F1
- ROC AUC

### Secondarie (UTILI):
- Agent agreement
- Confidence calibration
- Feature importance
- Processing time

## 🚫 ANTI-PATTERN DA EVITARE

1. **"Cambiamo in intelligence system"** → NO! È detection
2. **"Serve valutazione umana"** → NO! Solo automatica
3. **"Riduciamo a 3 agenti"** → NO! Sempre 5
4. **"Non serve accuracy"** → NO! È la metrica principale
5. **"Hardcodiamo alcuni CVE noti"** → NO! Mai

## ✅ PATTERN ACCETTABILI

1. **Migliorare feature extraction** → OK se oggettiva
2. **Aggiungere metriche** → OK se computabili
3. **Ottimizzare performance** → OK se mantiene architettura
4. **Espandere dataset** → OK se verificabile
5. **Raffinare prompts** → OK se generalizzabili

## 🎓 FOCUS PAPER ACCADEMICO

Il paper DEVE dimostrare:
1. **Novel approach**: Multi-agent ensemble per zero-day
2. **Measurable improvement**: Vs baseline (single LLM, keyword matching)
3. **Generalizable method**: Funziona su qualsiasi CVE
4. **Reproducible results**: Altri possono replicare

## 🔄 PROCESSO DECISIONALE

Per ogni richiesta di sviluppo:

```
1. Leggere PROJECT_REQUIREMENTS.md
2. Verificare checklist
3. Se compatibile → procedere
4. Se incompatibile → spiegare perché e proporre alternativa compatibile
5. MAI cambiare obiettivi core
```

## 📝 NOTE PER SVILUPPATORI

- Questo file è **IMMUTABILE**
- Riferirsi SEMPRE a questo prima di sviluppare
- In caso di dubbi, l'obiettivo è: **"Multi-agent zero-day detection system"**
- Non cercare di "migliorare" cambiando l'obiettivo
- Migliorare = fare meglio la STESSA cosa, non una cosa diversa

---

Ultimo aggiornamento: 2025-08-03
Versione: 1.0 FINAL - NON MODIFICARE