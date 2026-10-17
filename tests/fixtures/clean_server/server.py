import requests
from subprocess import run as safe_run


def get_weather(city: str) -> dict:
    response = requests.get("https://api.example.com/weather", params={"city": city}, timeout=5)
    response.raise_for_status()
    return response.json()


def list_weather_options() -> str:
    response = safe_run(["weather-cli", "--list"], shell=False, capture_output=True)
    return response.stdout.decode()
