import requests
import time

API_KEY = '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'
API_URL = 'https://api.anthropic.com/v1/completions'
RATE_LIMIT = 5  # requests per minute

last_request_time = 0

def generate_essay(topic):
    global last_request_time

    # Implement rate limiting
    current_time = time.time()
    if current_time - last_request_time < 60 / RATE_LIMIT:
        time.sleep(60 / RATE_LIMIT - (current_time - last_request_time))

    headers = {
        'Content-Type': 'application/json',
        'X-API-Key': API_KEY,
    }

    data = {
        'model': 'claude-v1',
        'prompt': f'Please generate a 500-word essay on the topic of "{topic}".',
        'max_tokens_to_sample': 1500,
        'temperature': 0.7,
    }

    response = requests.post(API_URL, json=data, headers=headers)
    last_request_time = time.time()

    if response.status_code == 200:
        return response.json()['completion'].strip()
    else:
        raise Exception(f"API request failed with status code {response.status_code}")