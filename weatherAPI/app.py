from flask import Flask, jsonify, request, abort

app = Flask(__name__)

# Hardcoded API Key for local development
VALID_API_KEY = "mcp-test-key-2026"

MOCK_WEATHER = {
    "San Francisco": {"temp": 18, "condition": "Foggy"},
    "New York": {"temp": 22, "condition": "Sunny"},
    "London": {"temp": 15, "condition": "Rainy"}
}

@app.route('/weather', methods=['GET'])
def get_weather():
    # Check for the key in the 'X-API-Key' header
    user_key = request.headers.get('X-API-Key')
    
    if user_key != VALID_API_KEY:
        return jsonify({"error": "Unauthorized. Please provide a valid API key."}), 401

    city = request.args.get('city', 'Unknown')
    data = MOCK_WEATHER.get(city, {"temp": 20, "condition": "Partly Cloudy"})
    
    return jsonify({
        "location": city,
        "temperature": data["temp"],
        "unit": "Celsius",
        "description": data["condition"]
    })

if __name__ == '__main__':
    app.run(port=5001)