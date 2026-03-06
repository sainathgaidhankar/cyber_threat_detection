"""
Threat Predictor Module
Handles loading and using the trained model for threat detection
"""
import pickle
import pandas as pd
import os
import numpy as np


class ThreatPredictor:
    """Encapsulates model loading and prediction logic"""
    
    def __init__(self, model_dir="../model"):
        """Initialize the predictor with model and encoders"""
        self.model_dir = os.path.abspath(model_dir)
        self.model = None
        self.le_y = None
        self.label_encoders = {}
        self.metrics = {}
        self.load_model()
    
    def load_model(self):
        """Load the trained model and encoders"""
        try:
            model = None
            le_y = None
            label_encoders = {}

            # Load model
            model_path = os.path.join(self.model_dir, "saved_model.pkl")
            with open(model_path, "rb") as f:
                model = pickle.load(f)
            
            # Load label encoder for target variable
            le_y_path = os.path.join(self.model_dir, "label_encoder_y.pkl")
            with open(le_y_path, "rb") as f:
                le_y = pickle.load(f)
            
            # Load label encoders for features
            label_encoders_X_path = os.path.join(self.model_dir, "label_encoders_X.pkl")
            with open(label_encoders_X_path, "rb") as f:
                label_encoders = pickle.load(f)

            # Only commit state after all artifacts load successfully
            self.model = model
            self.le_y = le_y
            self.label_encoders = label_encoders
            
            print("Model and encoders loaded successfully")
            return True
        except Exception as e:
            print(f"Error loading model: {e}")
            self.model = None
            self.le_y = None
            self.label_encoders = {}
            return False
    
    def encode_features(self, features_dict):
        """
        Encode categorical features for prediction
        
        Args:
            features_dict: Dictionary of feature names to values
        
        Returns:
            Encoded dataframe
        """
        # Ensure column names are strings to match saved encoders
        df = pd.DataFrame([features_dict])
        df.columns = df.columns.map(str)

        # Apply saved label encoders when available
        for enc_key, encoder in self.label_encoders.items():
            key = str(enc_key)
            if key in df.columns:
                try:
                    df[key] = encoder.transform(df[key])
                except Exception:
                    # Unknown label: fallback to first known class, encoded numerically
                    try:
                        fallback_label = encoder.classes_[0]
                        fallback_encoded = encoder.transform([fallback_label])[0]
                    except Exception:
                        fallback_encoded = 0
                    df[key] = fallback_encoded
        
        return df
    
    def predict(self, features_dict):
        """
        Make a prediction on network traffic features
        
        Args:
            features_dict: Dictionary of 41 network traffic features
        
        Returns:
            Dictionary with prediction and confidence
        """
        if self.model is None:
            return {"error": "Model not loaded"}
        
        try:
            # Encode features
            X = self.encode_features(features_dict)
            # Ensure numeric dtype where possible
            try:
                X = X.astype(float)
            except Exception:
                pass
            
            # Make prediction
            prediction_encoded = self.model.predict(X)[0]
            prediction_proba = self.model.predict_proba(X)[0]
            
            # Decode prediction to attack type name
            prediction_name = self.le_y.inverse_transform([prediction_encoded])[0]
            
            # Get confidence (probability of predicted class)
            confidence = float(np.max(prediction_proba))
            
            # Get all predictions with probabilities
            all_predictions = {}
            for class_id, prob in zip(self.model.classes_, prediction_proba):
                attack_type = class_id
                try:
                    class_index = int(class_id)
                    attack_type = self.le_y.inverse_transform([class_index])[0]
                except Exception:
                    # If classes are already labels, use class_id directly.
                    attack_type = class_id
                all_predictions[str(attack_type)] = float(prob)
            
            return {
                "prediction": prediction_name,
                "confidence": confidence,
                "all_predictions": all_predictions,
                "success": True
            }
        except Exception as e:
            return {
                "error": str(e),
                "success": False
            }
    
    def batch_predict(self, features_list):
        """
        Make predictions on multiple samples
        
        Args:
            features_list: List of feature dictionaries
        
        Returns:
            List of predictions
        """
        results = []
        for features in features_list:
            results.append(self.predict(features))
        return results
    
    def get_model_info(self):
        """Get information about the loaded model"""
        if self.model is None:
            return {"error": "Model not loaded"}
        
        return {
            "model_type": str(type(self.model).__name__),
            "n_features": self.model.n_features_in_,
            "n_classes": len(self.le_y.classes_),
            "attack_types": list(self.le_y.classes_),
            "categorical_features": list(self.label_encoders.keys())
        }


# Example usage
if __name__ == "__main__":
    predictor = ThreatPredictor()
    
    # Example: Get model info
    print("\nModel Info:")
    print(predictor.get_model_info())
    
    # Example prediction
    sample_features = {
        0: 0,
        1: 0,  # tcp
        2: 1,  # protocol
        3: 0,  # service
        4: 491,
        5: 0,
        6: 0,
        7: 0,
        8: 0,
        9: 0,
        10: 0,
        11: 0,
        12: 0,
        13: 0,
        14: 0,
        15: 0,
        16: 0,
        17: 0,
        18: 0,
        19: 0,
        20: 0,
        21: 0,
        22: 2,
        23: 2,
        24: 0,
        25: 0,
        26: 0,
        27: 0,
        28: 1,
        29: 0,
        30: 0,
        31: 150,
        32: 25,
        33: 0.17,
        34: 0.03,
        35: 0.17,
        36: 0,
        37: 0,
        38: 0,
        39: 0.05,
        40: 0
    }
    
    print("\n\nSample Prediction:")
    result = predictor.predict(sample_features)
    print(result)
