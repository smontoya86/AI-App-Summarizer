import os
from dotenv import load_dotenv
import requests

load_dotenv()  # Load environment variables from .env file

CLAUDE_API_KEY = os.getenv('ANTHROPIC_API_KEY')

def summarize_text(text):
    url = "https://api.anthropic.com/v1/claude/summarize"  # Hypothetical API endpoint
    headers = {
        'Authorization': f'Bearer {CLAUDE_API_KEY}',
        'Content-Type': 'application/json'
    }
    payload = {
        'text': text,
        'summary_length': 'short'  # You can change this to 'medium' or 'long'
    }
    
    try:
        response = requests.post(url, json=payload, headers=headers)
        response.raise_for_status()
        data = response.json()
        return data['summary']
    except requests.exceptions.RequestException as e:
        return f"An error occurred: {e}"
