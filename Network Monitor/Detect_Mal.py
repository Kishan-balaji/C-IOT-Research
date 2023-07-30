import pandas as pd
import pickle
import numpy as np
from sklearn.preprocessing import MinMaxScaler
from sklearn.impute import SimpleImputer

import paho.mqtt.client as mqtt

broker_address = "mqtt.eclipseprojects.io" 
broker_port = 1883 

client = mqtt.Client()

client.connect(broker_address, broker_port)

# Load the CBLOF model from the pickle file
with open('sample1.pkl', 'rb') as file:
    kmeans_model = pickle.load(file)

new_conn_df = pd.read_csv('new.csv')

df_conn_c = new_conn_df.drop(columns=['ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p',
                                      'service', 'local_orig', 'local_resp', 'history'])

df_conn_c = pd.get_dummies(df_conn_c, columns=['proto'])
df_conn_c = pd.get_dummies(df_conn_c, columns=['conn_state'])

cols = df_conn_c.select_dtypes(include=['object'])
for col in cols.columns.values:
    df_conn_c[col] = df_conn_c[col].fillna('0')

df_conn_c.fillna(0, inplace=True)
df_conn_c['duration'] = pd.to_datetime(df_conn_c['duration'], errors='coerce')
df_conn_c['duration'] = df_conn_c['duration'].fillna(pd.Timedelta(seconds=0))
df_conn_c['duration'] = df_conn_c['duration'] - df_conn_c['duration'].min()  # Calculate the duration as difference
df_conn_c['duration'] = df_conn_c['duration'].dt.total_seconds()

df_conn_c['orig_bytes'] = df_conn_c['orig_bytes'].apply(
    str).str.replace('-', '0')
df_conn_c['resp_bytes'] = df_conn_c['resp_bytes'].apply(
    str).str.replace('-', '0')

# Save the preprocessed data to a new CSV file
df_conn_c.to_csv('test_main.csv', index=False)

# Load the preprocessed data from the new CSV file
test_data = pd.read_csv('test_main.csv')

# Copy the DataFrame to avoid modifying the original
new_data = test_data.copy()

# Convert DataFrame to numpy array
X = new_data.to_numpy()

# Handle missing values
X[X == '-'] = np.nan
imputer = SimpleImputer(strategy='mean')
impute = imputer.fit_transform(X)

# Apply MinMaxScaler
scaler = MinMaxScaler()
scaler.fit(impute)
normalized_x = scaler.transform(impute)

# Pad the array if necessary
if normalized_x.shape[1] < 256:
    padding_width = 256 - normalized_x.shape[1]
    normalized_x = np.pad(
        normalized_x, [(0, 0), (0, padding_width)], mode='constant')

# Convert to float32
normalized_x = normalized_x.astype("float32")

# Predict 'Malicious_Binary' values
predicted_labels = kmeans_model.predict(normalized_x)


# Add the predicted 'Malicious_Binary' values as a new column to the DataFrame
new_data['Malicious_Binary'] = predicted_labels

client.publish("mytopic","1")

def map_binary_to_label(binary_value):
    if binary_value == 0:
        return 'Benign'
    else:
        return 'Malicious'

new_data['label'] = new_data['Malicious_Binary'].apply(map_binary_to_label)


# Save the DataFrame with predicted values as a new CSV file
new_data.to_csv('predicted_data.csv', index=False)

# Print the predicted 'Malicious_Binary' and cluster 'label' for each row
print("Predicted Values and Labels:")
for binary_value, label in zip(new_data['Malicious_Binary'], new_data['label']):
    print(f"Binary Value: {binary_value}, Label: {label}")