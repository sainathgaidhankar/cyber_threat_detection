import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
import pickle

# Load dataset (NSL-KDD has no header, so we read it without headers)
df = pd.read_csv("../../data/NSL_KDD_Train.csv", header=None)

# Print column names to verify
print(df.columns)

# The last column (index -1 or column name by position) is the attack type label
# Drop the last column for features, keep it as target
X = df.iloc[:, :-1]  # All columns except the last one
y = df.iloc[:, -1]   # Last column only (the attack type)

# Encode categorical variables in X
# Find columns with non-numeric data and encode them
label_encoders = {}
for col in X.columns:
    if X[col].dtype == 'object':  # If column is string/object type
        le = LabelEncoder()
        X[col] = le.fit_transform(X[col])
        label_encoders[col] = le

# Encode target variable y
le_y = LabelEncoder()
y = le_y.fit_transform(y)

# Split data
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)

# Train model with class weighting to handle imbalance
model = RandomForestClassifier(class_weight='balanced', random_state=42)
model.fit(X_train, y_train)

# Save model and encoders
import os
script_dir = os.path.dirname(os.path.abspath(__file__))
pickle.dump(model, open(os.path.join(script_dir, "saved_model.pkl"), "wb"))
pickle.dump(le_y, open(os.path.join(script_dir, "label_encoder_y.pkl"), "wb"))
pickle.dump(label_encoders, open(os.path.join(script_dir, "label_encoders_X.pkl"), "wb"))

# Evaluate on test set
from sklearn.metrics import accuracy_score, classification_report
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f"\nTraining Accuracy: {accuracy:.4f}")
print("\nClassification Report:")
print(classification_report(y_test, y_pred, labels=sorted(set(y_test) | set(y_pred))))