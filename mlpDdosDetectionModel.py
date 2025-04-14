import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import pickle

from sklearn.metrics import confusion_matrix, accuracy_score, mean_squared_error
from sklearn.model_selection import train_test_split
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler

# === Step 1: Load & Preprocess Data ===
df = pd.read_csv("merged_ddos_dataset.csv")  # Replace with your actual file
df.sort_values(by=['ip', 'timestamp'], inplace=True)

# === Step 2: Feature Engineering ===
df['time_diff'] = df.groupby('ip')['timestamp'].diff().fillna(0)
df['rolling_avg'] = df.groupby('ip')['time_diff'].rolling(5, min_periods=1).mean().reset_index(0, drop=True)

# === Step 3: Feature/Label Separation ===
X = df.drop(columns=['ip', 'timestamp', 'Tot Bwd Pkts', 'TotLen Bwd Pkts','Label'])
y = df['Label'].astype(int)

# === Step 4: Normalization ===
print(X.columns)

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# === Step 5: Train/Test Split ===
X_train, X_test, y_train, y_test = train_test_split(X_scaled, y.values, test_size=0.2, random_state=42)

# === Step 6: Define Parameters ===
hidden_size = 32
epochs = 100

# === Step 7: Train MLP with Tracking ===
model = MLPClassifier(
    hidden_layer_sizes=(hidden_size,),
    activation='logistic',
    solver='sgd',
    learning_rate_init=0.001,
    max_iter=1,
    warm_start=True,
    random_state=42
)

train_losses, train_accs, test_losses, test_accs = [], [], [], []

for epoch in range(epochs):
    model.fit(X_train, y_train)

    # Predictions
    y_train_pred = model.predict(X_train)
    y_test_pred = model.predict(X_test)

    # Metrics
    train_loss = mean_squared_error(y_train, y_train_pred)
    test_loss = mean_squared_error(y_test, y_test_pred)
    train_acc = accuracy_score(y_train, y_train_pred)
    test_acc = accuracy_score(y_test, y_test_pred)

    train_losses.append(train_loss)
    test_losses.append(test_loss)
    train_accs.append(train_acc)
    test_accs.append(test_acc)

    if epoch % 10 == 0:
        print(f"Epoch {epoch} | Train Loss: {train_loss:.4f} | Train Acc: {train_acc:.4f} | Test Loss: {test_loss:.4f} | Test Acc: {test_acc:.4f}")

# === Step 8: Plot Metrics ===
plt.figure(figsize=(5, 4))
plt.plot(train_losses, label="Train Loss")
plt.plot(test_losses, label="Test Loss")
plt.title("Loss Over Epochs")
plt.xlabel("Epoch")
plt.ylabel("Loss")
plt.legend()

plt.figure(figsize=(5, 4))
plt.plot(train_accs, label="Train Accuracy")
plt.plot(test_accs, label="Test Accuracy")
plt.title("Accuracy Over Epochs")
plt.xlabel("Epoch")
plt.ylabel("Accuracy")
plt.legend()

plt.tight_layout()
plt.show()

# === Step 9: Confusion Matrix ===
cm = confusion_matrix(y_test, y_test_pred)
plt.figure(figsize=(5, 4))
plt.imshow(cm, cmap='Blues')
plt.title("Confusion Matrix (Test)")
plt.xlabel("Predicted")
plt.ylabel("Actual")
for (i, j), val in np.ndenumerate(cm):
    plt.text(j, i, val, ha='center', va='center')
plt.tight_layout()
plt.show()

# === Step 10: Save Model and Scaler ===
with open("mlp_ddos_model.pkl", "wb") as f:
    pickle.dump(model, f)

with open("mlp_ddos_scaler.pkl", "wb") as f:
    pickle.dump(scaler, f)