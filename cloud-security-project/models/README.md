# models/

This folder will contain the trained ML model file:

- `rf_model.pkl` — generated after running `py ml/train_model.py`

It is empty by default. The dashboard works fine without any file here —
`ml/predict.py` detects the missing model and falls back gracefully.
