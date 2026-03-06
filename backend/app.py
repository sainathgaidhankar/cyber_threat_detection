from flask import Flask, request, jsonify, render_template
import os
import sys
import csv
import threading
from datetime import datetime

# Add utils to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'utils'))
from threat_predictor import ThreatPredictor

app = Flask(__name__, template_folder='../templates', static_folder='../static')

# Initialize threat predictor
predictor = ThreatPredictor(model_dir="./model")

# Store prediction history for metrics
prediction_history = []
MAX_HISTORY = 100
prediction_history_lock = threading.Lock()


def _prediction_failed(result):
    """Return True when predictor output indicates failure."""
    if not isinstance(result, dict):
        return True
    if result.get("success") is False:
        return True
    return "error" in result


def _prediction_error_status(result):
    """Map prediction errors to a reasonable HTTP status."""
    if not isinstance(result, dict):
        return 500

    error_text = str(result.get("error", "")).lower()
    if "not loaded" in error_text:
        return 503

    client_error_markers = (
        "invalid",
        "missing",
        "must",
        "expected",
        "could not convert",
        "cannot convert",
        "shape",
        "features",
    )
    if any(marker in error_text for marker in client_error_markers):
        return 400

    return 500

@app.route("/")
def home():
    return jsonify({
        "message": "Cyber Threat Detection System",
        "version": "1.0",
        "status": "running"
    })


@app.route("/api/predict", methods=["POST"])
def predict():
    """Predict threat type for a single network flow"""
    try:
        data = request.json
        
        if not data or "features" not in data:
            return jsonify({"error": "Missing 'features' in request"}), 400
        
        features = data["features"]
        
        # Convert string keys to integers if needed
        new_features = {}
        for k, v in features.items():
            if isinstance(k, str) and k.isdigit():
                new_features[int(k)] = v
            else:
                new_features[k] = v
        features = new_features
        
        # Make prediction
        result = predictor.predict(features)

        if _prediction_failed(result):
            if not isinstance(result, dict):
                result = {"error": "Prediction failed", "success": False}
            return jsonify(result), _prediction_error_status(result)

        # Store successful predictions in history only
        history_entry = {
            "timestamp": datetime.now().isoformat(),
            "prediction": result.get("prediction"),
            "confidence": result.get("confidence")
        }
        with prediction_history_lock:
            prediction_history.append(history_entry)
            if len(prediction_history) > MAX_HISTORY:
                prediction_history.pop(0)

        return jsonify(result)
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500



@app.route("/api/model-info", methods=["GET"])
def model_info():
    """Get information about the loaded model"""
    return jsonify(predictor.get_model_info())


@app.route("/api/metrics", methods=["GET"])
def metrics():
    """Get prediction metrics and statistics"""
    try:
        with prediction_history_lock:
            history_copy = list(prediction_history)

        if not history_copy:
            return jsonify({
                "total_predictions": 0,
                "message": "No predictions made yet"
            })
        
        predictions = [h.get("prediction") for h in history_copy if h.get("prediction")]
        confidences = [float(h.get("confidence") or 0.0) for h in history_copy]

        # Count by attack type
        attack_counts = {}
        for pred in predictions:
            attack_counts[pred] = attack_counts.get(pred, 0) + 1

        # Sort by count
        attack_counts = dict(sorted(attack_counts.items(), key=lambda x: x[1], reverse=True))

        return jsonify({
            "total_predictions": len(history_copy),
            "average_confidence": float(sum(confidences) / len(confidences)) if confidences else 0.0,
            "attack_distribution": attack_counts,
            "latest_predictions": history_copy[-5:]
        })
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/dashboard")
def dashboard():
    """Render interactive dashboard"""
    return render_template("dashboard.html")


@app.route('/api/submit-row', methods=['POST'])
def submit_row():
    """Accept a single CSV row or features JSON and return a prediction."""
    try:
        data = request.json or {}
        # If features provided directly
        if 'features' in data:
            features = data['features']
        elif 'row' in data:
            # parse CSV row string
            row_str = data['row']
            reader = csv.reader([row_str])
            row = next(reader, [])
            row = row[:41] + ['0'] * max(0, 41 - len(row))
            features = {str(i): row[i] for i in range(41)}
        else:
            return jsonify({'error': "Provide 'features' JSON or a CSV 'row' string."}), 400

        # normalize keys
        new_features = {}
        for k, v in features.items():
            if isinstance(k, str) and k.isdigit():
                new_features[int(k)] = v
            else:
                new_features[k] = v

        result = predictor.predict(new_features)

        if _prediction_failed(result):
            if not isinstance(result, dict):
                result = {"error": "Prediction failed", "success": False}
            return jsonify(result), _prediction_error_status(result)

        # Store successful predictions in history only
        history_entry = {
            'timestamp': datetime.now().isoformat(),
            'features': new_features,
            'prediction': result.get('prediction') if isinstance(result, dict) else str(result),
            'confidence': float(result.get('confidence') or 0.0) if isinstance(result, dict) else 0.0
        }
        with prediction_history_lock:
            prediction_history.append(history_entry)
            if len(prediction_history) > MAX_HISTORY:
                prediction_history.pop(0)

        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/samples', methods=['GET'])
def get_samples():
    """Get list of available sample CSV files for testing"""
    try:
        sample_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'sample_data'))
        if not os.path.exists(sample_dir):
            return jsonify({'samples': []})
        
        files = [f for f in os.listdir(sample_dir) if f.endswith('.csv')]
        samples = []
        
        for fname in sorted(files):
            fpath = os.path.join(sample_dir, fname)
            with open(fpath, 'r') as f:
                rows = list(csv.reader(f))
            
            # Parse first row as example
            if rows:
                first_row = rows[0]
                samples.append({
                    'name': fname.replace('.csv', ''),
                    'filename': fname,
                    'rows': len(rows),
                    'sample_data': first_row
                })
        
        return jsonify({'samples': samples})
    except Exception as e:
        return jsonify({'error': str(e)}), 500




@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Endpoint not found"}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({"error": "Internal server error"}), 500

if __name__ == "__main__":
    print("=" * 60)
    print("Cyber Threat Detection System")
    print("=" * 60)
    if predictor and getattr(predictor, "model", None) is not None:
        print("Model loaded successfully")
        if hasattr(predictor, "le_y") and predictor.le_y is not None and hasattr(predictor.le_y, "classes_"):
            print(f"Features: {len(predictor.le_y.classes_)} attack classes")
        else:
            print("Warning: predictor.le_y is unavailable; skipping class count output.")
    else:
        print("Warning: model was not loaded; prediction endpoints may return errors.")
    print("=" * 60)
    print("Dashboard: http://localhost:5000/dashboard")
    print("API: http://localhost:5000/api/model-info")
    print("=" * 60)
    
    app.run(debug=False, host="127.0.0.1", port=5000, use_reloader=False)
