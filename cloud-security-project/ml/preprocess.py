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
from sklearn.preprocessing import StandardScaler


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

    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    for column in df.columns:
        if pd.api.types.is_numeric_dtype(df[column]):
            df[column] = df[column].fillna(df[column].median())
        else:
            df[column] = df[column].fillna("Unknown")
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


def prepare_features_for_training(df, label_column):
    """Return numeric, encoded feature dataframe and label series."""
    y = df[label_column]
    X = df.drop(columns=[label_column])
    X = pd.get_dummies(X, drop_first=False)
    X = X.apply(pd.to_numeric, errors="coerce").fillna(0)
    return X, y


def scale_features(X_train, X_test):
    """Scale feature matrices and return scaled data plus fitted scaler."""
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    return X_train_scaled, X_test_scaled, scaler


def dataframe_to_feature_rows(df, feature_columns):
    """Convert uploaded CSV rows into model-ready dictionaries."""
    df = clean_dataframe(df)
    label_column = find_label_column(df)
    if label_column:
        df = df.drop(columns=[label_column])
    df = pd.get_dummies(df, drop_first=False)
    df = df.apply(pd.to_numeric, errors="coerce").fillna(0)
    return [{column: row.get(column, 0) for column in feature_columns} for row in df.to_dict(orient="records")]
