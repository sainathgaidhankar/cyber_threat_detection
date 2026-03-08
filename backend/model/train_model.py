import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
import pickle
from pathlib import Path

# Load dataset (NSL-KDD has no header, so we read it without headers)
script_dir = Path(__file__).resolve().parent
train_data_path = script_dir.parent.parent / "data" / "NSL_KDD_Train.csv"
df = pd.read_csv(train_data_path, header=None)

# The last column (index -1 or column name by position) is the attack type label
# Drop the last column for features, keep it as target
X = df.iloc[:, :-1]  # All columns except the last one
y = df.iloc[:, -1]   # Last column only (the attack type)

# Split data first to prevent data leakage
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, stratify=y, random_state=42
)

# Encode categorical variables in X_train (fit only on training data)
# Find columns with non-numeric data and encode them
label_encoders = {}
for col in X_train.columns:
    if X_train[col].dtype == 'object':  # If column is string/object type
        le = LabelEncoder()
        # Fit on training data only
        X_train[col] = le.fit_transform(X_train[col].astype(str))
        # Transform test data, handling unseen categories
        X_test[col] = X_test[col].astype(str).map(
            lambda x: le.transform([x])[0] if x in le.classes_ else 0
        )
        label_encoders[col] = le

# Encode target variable y (fit only on training data)
le_y = LabelEncoder()
y_train = le_y.fit_transform(y_train)
# Transform test data, handling unseen categories
y_test = y_test.astype(str).map(
    lambda x: le_y.transform([x])[0] if x in le_y.classes_ else 0
)

# Train model with class weighting to handle imbalance
model = RandomForestClassifier(class_weight='balanced', random_state=42)
model.fit(X_train, y_train)

# Save model and encoders
with open(script_dir / "saved_model.pkl", "wb") as f:
    pickle.dump(model, f)
with open(script_dir / "label_encoder_y.pkl", "wb") as f:
    pickle.dump(le_y, f)
with open(script_dir / "label_encoders_X.pkl", "wb") as f:
    pickle.dump(label_encoders, f)

# Evaluate on test set
from sklearn.metrics import accuracy_score, classification_report
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f"\nTest Accuracy: {accuracy:.4f}")
print("\nClassification Report:")
print(classification_report(y_test, y_pred, labels=sorted(set(y_test) | set(y_pred))))
