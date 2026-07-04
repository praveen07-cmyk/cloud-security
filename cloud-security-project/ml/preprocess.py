"""
preprocess.py
------------------------------------------------
Helper functions used by train_model.py and
predict.py to clean and prepare network/threat
datasets (e.g. CICIDS2017, CSE-CIC-IDS2018, NSL-KDD)
before training a RandomForestClassifier.
------------------------------------------------
"""

import numpy as np
import pandas as pd


def clean_dataframe(df):
    """
    Clean a raw dataset:
      - Strip whitespace from column names.
      - Replace infinite values with NaN.
      - Drop rows with missing values.
      - Drop duplicate rows.

    Args:
        df (pd.DataFrame): raw dataframe.

    Returns:
        pd.DataFrame: cleaned dataframe.
    """
    df = df.copy()
    df.columns = [str(c).strip() for c in df.columns]

    # Replace inf/-inf with NaN, then drop
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)
    df.drop_duplicates(inplace=True)

    return df


def find_label_column(df):
    """
    Find the label column in a dataframe.
    Supports both 'Label' and 'label' column names
    (as required by the project spec).

    Returns:
        str or None: the actual column name found.
    """
    for candidate in ["Label", "label", "LABEL", "class", "Class"]:
        if candidate in df.columns:
            return candidate
    return None


def split_features_labels(df, label_column):
    """
    Split a dataframe into features (X) and labels (y).

    Args:
        df (pd.DataFrame): cleaned dataframe.
        label_column (str): name of the label column.

    Returns:
        (pd.DataFrame, pd.Series): X, y
    """
    y = df[label_column]
    X = df.drop(columns=[label_column])

    # Keep numeric columns only (RandomForest needs numeric input)
    X = X.select_dtypes(include=[np.number])

    return X, y
