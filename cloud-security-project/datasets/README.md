# datasets/

Place a real network intrusion dataset CSV file here to train the ML model.

Recommended public datasets:

- **CICIDS2017** — https://www.unb.ca/cic/datasets/ids-2017.html
- **CSE-CIC-IDS2018** — https://www.unb.ca/cic/datasets/ids-2018.html
- **NSL-KDD** — https://www.unb.ca/cic/datasets/nsl.html

The CSV must contain a `Label` or `label` column identifying the traffic
class (e.g. `BENIGN`, `DDoS`, `PortScan`, etc.).

Once a CSV is placed here, run:

```
py ml/train_model.py
```
