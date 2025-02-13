import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split

def load_and_preprocess_data(file_path):
    data = pd.read_csv(file_path)
    data = data.drop(columns=['Flow ID', 'Timestamp'], errors='ignore')
    data = data.replace([np.inf, -np.inf], np.nan).dropna()
    return data


def encode_labels(data, label_column='Label'):
    encoder = LabelEncoder()
    data['Encoded_Label'] = encoder.fit_transform(data[label_column])
    return data, encoder

def split_data(data, target_column='Encoded_Label', label_column='Label', test_size=0.2, random_state=42):
    X = data.drop([target_column, label_column], axis=1, errors='ignore')
    y = data[target_column]
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=test_size, random_state=random_state)
    return X_train, X_test, y_train, y_test, X, y
# def scale_features_data(data):
#     scaler = MinMaxScaler()
#     numerical_columns = data.select_dtypes(include=['float64', 'int64']).columns
#     data[numerical_columns] = scaler.fit_transform(data[numerical_columns])
#     return data
