#!/usr/bin/python3
#
# License: CC-0

import sys
import json
import requests
import time
from labworks.labwork04 import *

from labworks.labwork01 import *
from labworks.labwork02 import *
from labworks.labwork03 import *

if len(sys.argv) != 4:
	print("syntax: %s [API endpoint URI] [client ID] [assignment_name]" % (sys.argv[0]))
	sys.exit(1)


api_endpoint = sys.argv[1]
client_id = sys.argv[2]
assignment_name = sys.argv[3]

session = requests.Session()
# Get the assignment
result = session.get(api_endpoint + "/assignment/" + client_id + "/" + assignment_name)
assert(result.status_code == 200)

# See if we can compute the answer
assignment = result.json()
known_assignment_count = 0
unknown_assignment_count = 0
pass_count = 0
start = time.time()
for testcase in assignment["testcases"]:
	if testcase["type"] == "strcat":
		known_assignment_count += 1
		response = handle_strcat(testcase["assignment"])
	elif testcase["type"] == "histogram":
		known_assignment_count += 1
		response = handle_histogram(testcase["assignment"])
	elif testcase["type"] == "caesar_cipher":
		known_assignment_count += 1
		response = handle_caesar(testcase["assignment"])
	elif testcase["type"] == "password_keyspace":
		known_assignment_count += 1
		response = handle_password_keyspace(testcase["assignment"])
	elif testcase["type"] == "mul_gf2_128":
		known_assignment_count +=1
		response = handle_mul_gf2_128(testcase["assignment"])
	elif testcase["type"] == "block_cipher":
		known_assignment_count +=1
		response = handle_block_cipher(testcase["assignment"])
	elif testcase["type"] == "pkcs7_padding":
		known_assignment_count +=1
		print(testcase["tcid"])
		response = handle_pkcs7_padding(testcase["assignment"])
	elif testcase["type"] == "cbc_key_equals_iv":
		known_assignment_count +=1
		response = handle_cbc_key_equals_iv(testcase["assignment"])
	elif testcase["type"] == "gcm_block_to_poly":
		known_assignment_count +=1
		response = handle_gcm_block_to_poly(testcase["assignment"])
	else:
		unknown_assignment_count += 1
		print("Do not know how to handle type: %s" % (testcase["type"]))
		continue

	# We think we have an answer for this one, try to submit it
	result = session.post(api_endpoint + "/submission/" + testcase["tcid"], headers = {
		"Content-Type": "application/json",
	}, data = json.dumps(response))
	assert(result.status_code == 200)
	submission_result = result.json()
	if submission_result["status"] == "pass":
		pass_count += 1
	else:
		print(submission_result)
end = time.time()
print("Total time passed: %f seconds" % (end - start))
print("%d known assignments, %d unknown." % (known_assignment_count, unknown_assignment_count))
print("Passed: %d. Failed: %d" % (pass_count, known_assignment_count - pass_count))