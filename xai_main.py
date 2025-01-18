import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, AdaBoostClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.svm import SVC
from sklearn.neighbors import KNeighborsClassifier
import shap
from lime.lime_tabular import LimeTabularExplainer # This line should now work
import matplotlib.pyplot as plt
import time

import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder, MinMaxScaler
from scipy.io import arff  # For handling ARFF files

from sklearn.preprocessing import LabelEncoder, MinMaxScaler
from scipy.io import arff

# File path for NSL-KDD ARFF
nsl_kdd_path = "KDDTest+.arff"  # Update with the path to your ARFF file
output_nsl_kdd = "./cleaned/nsl_kdd_clean.csv"  # Output path for the cleaned CSV file

# Preprocessing function
def preprocess_dataset(df, target_column="class"):
    """
    Preprocess NSL-KDD dataset:
    - Drop missing values
    - Encode categorical features
    - Normalize numerical features
    - Convert labels to binary (normal=0, attack=1)
    """
    df = df.dropna()

    # Encode categorical features
    categorical_columns = df.select_dtypes(include=['object']).columns
    encoder = LabelEncoder()
    for col in categorical_columns:
        if col != target_column:  # Do not encode the target column yet
            df[col] = encoder.fit_transform(df[col])

    # Convert label column to binary: normal = 0, anomaly = 1
    if target_column in df.columns:
        df[target_column] = df[target_column].apply(lambda x: 0 if "normal" in str(x).lower() else 1)

    return df

# Load NSL-KDD Dataset (ARFF file)
print("Processing NSL-KDD dataset...")
data, meta = arff.loadarff(nsl_kdd_path)
nsl_kdd_df = pd.DataFrame(data)

# Convert byte strings to normal strings
nsl_kdd_df = nsl_kdd_df.applymap(lambda x: x.decode('utf-8') if isinstance(x, bytes) else x)

# Preprocess the dataset
nsl_kdd_df = preprocess_dataset(nsl_kdd_df)

# Save the cleaned dataset as CSV
nsl_kdd_df.to_csv(output_nsl_kdd, index=False)
print(f"NSL-KDD dataset saved to {output_nsl_kdd}.")

# import pandas as pd

# # File path for the dataset
# dos_path = "dos-03-15-2022-15-44-32.csv"  # Path to the 'dos-03-15-2022-15-44-32.csv' file
# output_dos = "./cleaned/dos2022_clean.csv"  # Path to save the cleaned CSV file

# # Preprocessing function
# def preprocess_dataset(df, target_column="ALERT"):
#     """
#     Preprocess the 'dos-03-15-2022-15-44-32' dataset:
#     - Convert the 'ALERT' column to binary labels (0 for normal, 1 for anomaly).
#     """
#     # Convert 'ALERT' column to binary: "Denial of Service" becomes 1 (anomaly)
#     df[target_column] = 1  # Only 'Denial of Service' is present, so set all to 1

#     return df

# # Process 'dos-03-15-2022-15-44-32' Dataset
# print("Processing 'dos-03-15-2022-15-44-32' dataset...")
# dos_df = pd.read_csv(dos_path)

# # Preprocess the dataset
# dos_df = preprocess_dataset(dos_df, target_column="ALERT")

# # Save the cleaned dataset as CSV
# dos_df.to_csv(output_dos, index=False)
# print(f"'dos-03-15-2022-15-44-32' dataset saved to {output_dos}.")

# import pandas as pd

# # File path for the dataset
# cicids_path = "/content/cleaned/nsl_kdd_clean.csv"  # Path to the 'Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv' file

# # Load the dataset
# cicids_df = pd.read_csv(cicids_path)

# # Display unique values for each column
# print("Unique values in each feature:")
# for column in cicids_df.columns:
#     unique_values = cicids_df[column].unique()
#     print(f"Column '{column}':")
#     print(unique_values)
#     print()

# File path for the dataset
cicids_path = "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"  # Path to the 'Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv' file
output_cicids = "./cleaned/cicids2017_clean.csv"  # Path to save the cleaned CSV file

# Preprocessing function
def preprocess_dataset(df, target_column=" Label"):
    """
    Preprocess the 'Friday-WorkingHours-Afternoon-DDos.pcap_ISCX' dataset:
    - Drop missing values
    - Encode categorical features
    - Normalize numerical features
    - Convert 'Label' column to binary (BENIGN=0, DDoS=1)
    """
    df = df.dropna()  # Drop rows with missing values


    # Convert 'Label' column to binary: BENIGN = 0, DDoS = 1
    if target_column in df.columns:
        df[target_column] = df[target_column].apply(lambda x: 0 if x == "BENIGN" else 1)
    # Encode categorical features (if applicable)
    categorical_columns = df.select_dtypes(include=['object']).columns
    if categorical_columns.any():
        encoder = LabelEncoder()
        for col in categorical_columns:
            df[col] = encoder.fit_transform(df[col])



    return df

# Process 'Friday-WorkingHours-Afternoon-DDos.pcap_ISCX' Dataset
print("Processing 'Friday-WorkingHours-Afternoon-DDos.pcap_ISCX' dataset...")
cicids_df = pd.read_csv(cicids_path)

unique_values = np.unique(cicids_df[' Label'])
print("Unique")
print(unique_values)

# Preprocess the dataset
cicids_df = preprocess_dataset(cicids_df, target_column=" Label")

unique_values = np.unique(cicids_df[' Label'])
print("Unique 2")
print(unique_values)


# Save the cleaned dataset as CSV
cicids_df.to_csv(output_cicids, index=False)
print(f"'Friday-WorkingHours-Afternoon-DDos.pcap_ISCX' dataset saved to {output_cicids}.")

import pandas as pd

# File paths for the cleaned datasets
nsl_kdd_path = "./cleaned/nsl_kdd_clean.csv"
cicids_path = "./cleaned/cicids2017_clean.csv"
# simargl_path = "./cleaned/simargl2022_clean.csv"

# Load datasets
nsl_kdd_df = pd.read_csv(nsl_kdd_path)
cicids_df = pd.read_csv(cicids_path)
# simargl_df = pd.read_csv(simargl_path)

# Display head of the datasets for verification
print("NSL-KDD Dataset:\n", nsl_kdd_df.head(), "\n")
print("CICIDS-2017 Dataset:\n", cicids_df.head(), "\n")
# print("Simargl2022 Dataset:\n", simargl_df.head(), "\n")


unique_values = np.unique(cicids_df[' Label'])
print("Unique")
print(unique_values)

# Replace infinite values with NaN
cicids_df.replace([np.inf, -np.inf], np.nan, inplace=True)

# Impute or remove NaN values if any
# Option 1: Impute with the mean
# X_cicids = X_cicids.fillna(X_cicids.mean())
# Option 2: Remove rows with NaN values
cicids_df.dropna(inplace=True)


# Encode categorical features in X_simargl
# for col in simargl_df.select_dtypes(include=['object']).columns:
#     encoder = LabelEncoder()
#     simargl_df[col] = encoder.fit_transform(simargl_df[col])

# Features and labels preparation
X_nsl_kdd = nsl_kdd_df.drop(columns=['class'])  # 'class' column is the label in NSL-KDD
y_nsl_kdd = nsl_kdd_df['class']

X_cicids = cicids_df.drop(columns=[' Label'])  # 'Label' column is the label in CICIDS-2017
y_cicids = cicids_df[' Label']

# X_simargl = simargl_df.drop(columns=['ALERT'])  # 'ALERT' column is the label in Simargl2022
# y_simargl = simargl_df['ALERT']

from sklearn.preprocessing import MinMaxScaler

scaler_nsl_kdd = MinMaxScaler()
scaler_cicids = MinMaxScaler()
scaler_simargl = MinMaxScaler()

X_nsl_kdd_scaled = scaler_nsl_kdd.fit_transform(X_nsl_kdd)

X_cicids_scaled = scaler_cicids.fit_transform(X_cicids)

# X_simargl_scaled = scaler_simargl.fit_transform(X_simargl)

X_train_nsl, X_test_nsl, y_train_nsl, y_test_nsl = train_test_split(X_nsl_kdd_scaled, y_nsl_kdd, test_size=0.3, random_state=42)
X_train_cicids, X_test_cicids, y_train_cicids, y_test_cicids = train_test_split(X_cicids_scaled, y_cicids, test_size=0.3, random_state=42)
# X_train_simargl, X_test_simargl, y_train_simargl, y_test_simargl = train_test_split(X_simargl_scaled, y_simargl, test_size=0.3, random_state=42)

unique_values = np.unique(y_train_cicids)
print(unique_values)

# # Prepare models
# models = {
#     'RandomForest': RandomForestClassifier(random_state=42),
#     'AdaBoost': AdaBoostClassifier(random_state=42),
#     'MLP': MLPClassifier(random_state=42),
#     'SVM': SVC(probability=True, random_state=42),
#     'KNN': KNeighborsClassifier()
# }

# # Prepare datasets
# datasets = {
#     'NSL-KDD': (X_train_nsl, X_test_nsl, y_train_nsl, y_test_nsl),
#     'CICIDS-2017': (X_train_cicids, X_test_cicids, y_train_cicids, y_test_cicids)
# }

# # # Train models and store them
# # trained_models = {
# #     dataset_name: {model_name: model.fit(X_train, y_train)
# #                    for model_name, model in models.items()}
# #     for dataset_name, (X_train, X_test, y_train, y_test) in datasets.items()
# # }

# def train_models(models, datasets):
#     """
#     Train multiple models on given datasets.
#     Returns:
#         trained_models: Dictionary containing trained models.
#     """
#     trained_models = {}
#     for dataset_name, (X_train, X_test, y_train, y_test) in datasets.items():
#         trained_models[dataset_name] = {}
#         for model_name, model in models.items():
#             print(f"Training {model_name} on {dataset_name}...")
#             trained_models[dataset_name][model_name] = model.fit(X_train, y_train)
#     return trained_models

#     # Train models
# trained_models = train_models(models, datasets)



# from sklearn.ensemble import RandomForestClassifier, AdaBoostClassifier
# from sklearn.neural_network import MLPClassifier
# from sklearn.svm import SVC
# from sklearn.neighbors import KNeighborsClassifier
# from sklearn.inspection import permutation_importance, plot_partial_dependence
# import matplotlib.pyplot as plt
# import numpy as np
# import seaborn as sns
# from sklearn.metrics import confusion_matrix, classification_report

# for name, model in models.items():
#     if name in ['RandomForest', 'AdaBoost']:
#         # Feature importances
#         importances = model.feature_importances_
#         indices = range(len(importances))

#         # Plot feature importances
#         plt.figure(figsize=(10, 6))
#         plt.title(f"Feature Importances for {name}")
#         plt.barh(indices, importances, align='center')
#         plt.yticks(indices, [f"Feature {i}" for i in indices])
#         plt.xlabel('Importance')
#         plt.ylabel('Feature')
#         plt.show()

#     elif name in ['MLP', 'SVM', 'KNN']:
#         # Permutation feature importance
#         result = permutation_importance(model, X_train, y_train, n_repeats=10, random_state=42)
#         importances = result.importances_mean

#         # Plot feature importances
#         plt.figure(figsize=(10, 6))
#         plt.title(f"Permutation Feature Importances for {name}")
#         plt.barh(range(len(importances)), importances, align='center')
#         plt.yticks(range(len(importances)), [f"Feature {i}" for i in range(len(importances))])
#         plt.xlabel('Importance')
#         plt.ylabel('Feature')
#         plt.show()

#         # Error Analysis - Confusion Matrix and Classification Report
#         y_pred = model.predict(X_test)
#         cm = confusion_matrix(y_test, y_pred)
#         cr = classification_report(y_test, y_pred, target_names=[f"Class {i}" for i in range(len(set(y_test)))])

#         # Plot confusion matrix
#         plt.figure(figsize=(10, 7))
#         sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", xticklabels=[f"Pred {i}" for i in range(len(cm))], yticklabels=[f"True {i}" for i in range(len(cm))])
#         plt.xlabel('Predicted')
#         plt.ylabel('True')
#         plt.title(f"Confusion Matrix for {name}")
#         plt.show()

#         # Print classification report
#         print(f"Classification Report for {name}:\n{cr}\n")

#     if name in ['RandomForest', 'AdaBoost']:
#         # Partial Dependence Plots for RandomForest and AdaBoost
#         fig, ax = plot_partial_dependence(model, X_train, features=[0, 1], ax=plt.gca(), grid_resolution=50)
#         plt.title(f"Partial Dependence Plot for {name}")
#         plt.show()

# Prepare models
models = {
    'RandomForest': RandomForestClassifier(random_state=42),
    'AdaBoost': AdaBoostClassifier(random_state=42),
    'MLP': MLPClassifier(random_state=42),
    'SVM': SVC(probability=True, random_state=42),
    'KNN': KNeighborsClassifier()
}

# Prepare datasets
datasets = {
    'NSL-KDD': (X_train_nsl, y_train_nsl),
    'CICIDS-2017': (X_train_cicids, y_train_cicids)
}

def train_models(models, datasets):
    """
    Train multiple models on given datasets.
    Returns:
        trained_models: Dictionary containing trained models.
    """
    trained_models = {}
    for dataset_name, (X_train, y_train) in datasets.items():
        trained_models[dataset_name] = {}
        for model_name, model in models.items():
            print(f"Training {model_name} on {dataset_name}...")
            trained_models[dataset_name][model_name] = model.fit(X_train, y_train)
    return trained_models

# Train models
trained_models = train_models(models, datasets)

from sklearn.ensemble import RandomForestClassifier, AdaBoostClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.svm import SVC
from sklearn.neighbors import KNeighborsClassifier
from sklearn.inspection import permutation_importance, plot_partial_dependence
import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns
from sklearn.metrics import confusion_matrix, classification_report

for dataset_name, models_dict in trained_models.items():
    for name, model in models_dict.items():
        # Predictions on the corresponding dataset
        y_pred = model.predict(datasets[dataset_name][0])  # Use train set for predictions
        
        if name in ['RandomForest', 'AdaBoost']:
            # Feature importances
            importances = model.feature_importances_
            indices = range(len(importances))

            # Plot feature importances
            plt.figure(figsize=(10, 6))
            plt.title(f"Feature Importances for {name} on {dataset_name}")
            plt.barh(indices, importances, align='center')
            plt.yticks(indices, [f"Feature {i}" for i in indices])
            plt.xlabel('Importance')
            plt.ylabel('Feature')
            plt.show()

        elif name in ['MLP', 'SVM', 'KNN']:
            # Permutation feature importance
            result = permutation_importance(model, datasets[dataset_name][0], datasets[dataset_name][1], n_repeats=10, random_state=42)
            importances = result.importances_mean

            # Plot feature importances
            plt.figure(figsize=(10, 6))
            plt.title(f"Permutation Feature Importances for {name} on {dataset_name}")
            plt.barh(range(len(importances)), importances, align='center')
            plt.yticks(range(len(importances)), [f"Feature {i}" for i in range(len(importances))])
            plt.xlabel('Importance')
            plt.ylabel('Feature')
            plt.show()

            # Error Analysis - Confusion Matrix and Classification Report
            cm = confusion_matrix(datasets[dataset_name][1], y_pred)
            cr = classification_report(datasets[dataset_name][1], y_pred, target_names=[f"Class {i}" for i in range(len(set(datasets[dataset_name][1])))])
            
            # Plot confusion matrix
            plt.figure(figsize=(10, 7))
            sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", xticklabels=[f"Pred {i}" for i in range(len(cm))], yticklabels=[f"True {i}" for i in range(len(cm))])
            plt.xlabel('Predicted')
            plt.ylabel('True')
            plt.title(f"Confusion Matrix for {name} on {dataset_name}")
            plt.show()

            # Print classification report
            print(f"Classification Report for {name} on {dataset_name}:\n{cr}\n")

        if name in ['RandomForest', 'AdaBoost']:
            # Partial Dependence Plots for RandomForest and AdaBoost
            fig, ax = plot_partial_dependence(model, datasets[dataset_name][0], features=[0, 1], ax=plt.gca(), grid_resolution=50)
            plt.title(f"Partial Dependence Plot for {name} on {dataset_name}")
            plt.show()
