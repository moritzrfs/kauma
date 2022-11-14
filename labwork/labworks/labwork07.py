
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
    # password = assignment["password"]
    for i in range(10):
        char = crack_char(user, alphabet)
        print(char, "Round: ", i)

    session.close()

def crack_char(user, alphabet):
    char_stats = []
    for char in alphabet:
        status, time = query_oracle(session, user, char+char)
        char_stats.append((char, time))
    # sort the list by time in descending order
    char_stats.sort(key=lambda x: x[1], reverse=True)
    return char_stats[0]




def query_oracle(session: requests.Session, user: str, password: str) -> str:
    payload = { "user": user, "password": password }
    result = session.post(api_endpoint + "/oracle/timing_sidechannel", headers = {
        "Content-Type": "application/json"}, data = json.dumps(payload))
    return result.json()['status'], result.json()['time']

handle_timing_sidechannel()