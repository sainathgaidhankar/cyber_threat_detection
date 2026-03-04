from flask import Flask, request, jsonify
import pickle

app = Flask(__name__)

# Load trained model (we’ll create later)
try:
    model = pickle.load(open("model/saved_model.pkl", "rb"))
except:
    model = None

@app.route("/")
def home():
    return "Cyber Threat Detection API is running!"

@app.route("/detect", methods=["POST"])
def detect():
    data = request.json["features"]  # input features
    prediction = model.predict([data])
    return jsonify({"result": int(prediction[0])})

if __name__ == "__main__":
    app.run(debug=True)