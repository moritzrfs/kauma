import itertools
import re
import time

testcases = {"testcases" :[
        {
            "tcid": "ae729d0c-17a7-498c-a0a4-01cb3f98bbf4",
            "passed_at_utc": "2022-10-11T11:13:44Z",
            "type": "password_keyspace",
            "assignment": {
                "alphabet": "abcdefABCDEF0123!$*",
                "length": 4,
                "restrictions": []
            },
            "expect_solution": {
                "count": 130321
            }
        },
        {
            "tcid": "69e4655d-04dc-429c-b7bd-dd44e1e99e33",
            "passed_at_utc": "2022-10-11T11:13:44Z",
            "type": "password_keyspace",
            "assignment": {
                "alphabet": "abcdefABCDEF0123!$*",
                "length": 4,
                "restrictions": [
                    "at_least_one_special_char"
                ]
            },
            "expect_solution": {
                "count": 64785
            }
        },
        {
            "tcid": "ade19d0c-2b12-498c-ad23-22b89a1ef6b7",
            "passed_at_utc": "2022-10-11T11:07:36Z",
            "type": "password_keyspace",
            "assignment": {
                "alphabet": "abcdefABCDEF0123!$*",
                "length": 4,
                "restrictions": [
                    "at_least_one_uppercase_char",
                    "at_least_one_digit"
                ]
            },
            "expect_solution": {
                "count": 57696
            }
        },
        {
            "tcid": "3ccadf07-1770-440f-9652-8f06e3facc3e",
            "passed_at_utc": "2022-10-11T11:13:44Z",
            "type": "password_keyspace",
            "assignment": {
                "alphabet": "abcdefABCDEF0123!$*",
                "length": 4,
                "restrictions": [
                    "at_least_one_lowercase_char"
                ]
            },
            "expect_solution": {
                "count": 101760
            }
        },
        {
            "tcid": "ca1964fc-0ac5-4fa7-93cd-e1f5b28a5753",
            "passed_at_utc": "2022-10-11T11:13:44Z",
            "type": "password_keyspace",
            "assignment": {
                "alphabet": "abcdefABCDEF0123!$*",
                "length": 4,
                "restrictions": [
                    "at_least_one_digit"
                ]
            },
            "expect_solution": {
                "count": 79696
            }
        },
        {
            "tcid": "d0ab95fc-7573-4f38-9446-51b94992bf19",
            "passed_at_utc": "2022-10-11T11:13:44Z",
            "type": "password_keyspace",
            "assignment": {
                "alphabet": "abcdefABCDEF0123!$*",
                "length": 4,
                "restrictions": [
                    "no_consecutive_same_char"
                ]
            },
            "expect_solution": {
                "count": 110808
            }
        },
        {
            "tcid": "bcdf06ab-7f72-4a65-a23f-9fa394a2b563",
            "passed_at_utc": "2022-10-11T11:13:45Z",
            "type": "password_keyspace",
            "assignment": {
                "alphabet": "abcdefABCDEF0123!$*",
                "length": 4,
                "restrictions": [
                    "special_char_not_last_place"
                ]
            },
            "expect_solution": {
                "count": 109744
            }
        },
        {
            "tcid": "8fcee7fa-1761-4bc8-b4be-09b19222844d",
            "passed_at_utc": "null",
            "type": "password_keyspace",
            "assignment": {
                "alphabet": "abcdefABCDEF0123!$*",
                "length": 4,
                "restrictions": [
                    "at_least_one_special_char",
                    "at_least_one_uppercase_char",
                    "at_least_one_lowercase_char",
                    "at_least_one_digit",
                    "no_consecutive_same_char",
                    "special_char_not_last_place"
                ]
            },
            "expect_solution": {
                "count": 7776
            }
        },
        {
            "tcid": "3df5a97c-41ae-498f-b0e1-321772da2b6f",
            "passed_at_utc": "2022-10-11T11:13:45Z",
            "type": "password_keyspace",
            "assignment": {
                "alphabet": "abcABCDEFG0123!$*%",
                "length": 5,
                "restrictions": []
            }
        },
        {
            "tcid": "10db139f-d309-4023-b67e-4a3d281d9d42",
            "passed_at_utc": "2022-10-11T11:07:36Z",
            "type": "password_keyspace",
            "assignment": {
                "alphabet": "abcABCDEFG0123!$*%",
                "length": 5,
                "restrictions": [
                    "at_least_one_uppercase_char",
                    "at_least_one_lowercase_char"
                ]
            }
        },
        {
            "tcid": "019407f9-6856-40ae-b0ba-874ca8b960a5",
            "passed_at_utc": "2022-10-11T11:07:36Z",
            "type": "password_keyspace",
            "assignment": {
                "alphabet": "abcABCDEFG0123!$*%",
                "length": 5,
                "restrictions": [
                    "at_least_one_digit",
                    "at_least_one_special_char"
                ]
            }
        },
        {
            "tcid": "48367169-008f-4824-8c49-aa498dc447a4",
            "passed_at_utc": "2022-10-11T11:13:45Z",
            "type": "password_keyspace",
            "assignment": {
                "alphabet": "abcABCDEFG0123!$*%",
                "length": 5,
                "restrictions": [
                    "no_consecutive_same_char"
                ]
            }
        },
        {
            "tcid": "c68053aa-760f-4b6c-b17b-36167543ff1f",
            "passed_at_utc": "2022-10-11T11:13:45Z",
            "type": "password_keyspace",
            "assignment": {
                "alphabet": "abcABCDEFG0123!$*%",
                "length": 5,
                "restrictions": [
                    "special_char_not_last_place"
                ]
            }
        },
        {
            "tcid": "fdc667de-db25-4458-9454-f8fa8de5065a",
            "passed_at_utc": "null",
            "type": "password_keyspace",
            "assignment": {
                "alphabet": "abcABCDEFG0123!$*%",
                "length": 5,
                "restrictions": [
                    "at_least_one_special_char",
                    "at_least_one_uppercase_char",
                    "at_least_one_lowercase_char",
                    "at_least_one_digit",
                    "no_consecutive_same_char",
                    "special_char_not_last_place"
                ]
            }
        }
    ]
}


res_pattern = {
    "at_least_one_uppercase_char" : "[A-Z]+",
    "at_least_one_lowercase_char" : "[a-z]+",
    "at_least_one_digit" : "[0-9]+",
    "at_least_one_special_char" : "[^A-Za-z0-9]+",
    "no_consecutive_same_char" : r"(.)\1",
    "special_char_not_last_place" : r"[!@#\\$%\\^\\&*\\)\\(+=._-]$"
}

def find_regex(pattern, alphabet):
    return bool(re.search(pattern, alphabet))

def handle_password_keyspace(assignment):
    totaltime = 0
    start = time.time()
    password_list= set(itertools.product(assignment['alphabet'], repeat=assignment['length']))
    end = time.time()
    print("Time to create password list: ", end - start)
    totaltime += (end - start)
    print('Anzahl: ', len(password_list))

    for restriction in assignment['restrictions']:    
        if restriction in res_pattern:
            start_res = time.time()
            for element in password_list.copy():
                lowercase = False
                for c in element:
                    lowercase= find_regex(res_pattern[restriction], c)
                    if lowercase == True:
                        break
                if lowercase == False:
                    password_list.remove(element)
            end_res = time.time()
            totaltime += (end_res - start_res)
            print("Time to remove ",res_pattern[restriction], ":", end_res - start_res)
        # if restriction == "no_consecutive_same_char":
        #     start_nsc = time.time()
        #     for element in password_list.copy():
        #         s = ''
        #         for c in element:
        #             if c == s:                        
        #                 password_list.remove(element)
        #                 break
        #             else:
        #                 s=c
        #     end_nsc = time.time()
        #     print("Time to remove no_consecutive_same_char:", end_nsc - start_nsc)
        #     totaltime += end_nsc - start_nsc
        # if restriction == "special_char_not_last_place":
        #     start_snlp = time.time()
        #     for element in password_list.copy():
        #         if find_regex("[^A-Za-z0-9]+", element[-1]):
        #             password_list.remove(element)
        #     end_snlp = time.time()
        #     print("Time to remove special_char_not_last_place:", end_snlp - start_snlp)
        #     totaltime += (end_snlp - start_snlp)
    #print(len(password_list))

    print("Totaltime: ", totaltime)
    return {"count": int(len(password_list))}

def handle_password_keyspace2(assignment):
    totaltime = 0
    start = time.time()
    password_list= set(itertools.product(assignment['alphabet'], repeat=assignment['length']))
    end = time.time()
    print("Time to create password list: ", end - start)
    totaltime += (end - start)
    print('Anzahl: ', len(password_list))

    endergebnis = []
    addition = []
    for restriction in assignment['restrictions']:    
        if restriction in res_pattern and restriction != "no_consecutive_same_char" and restriction !=  "special_char_not_last_place" :
            start_res = time.time()
            for element in password_list:
                if find_regex(res_pattern[restriction], ''.join(element)) == True:
                    addition.append(element)
            end_res = time.time()
            totaltime += (end_res - start_res)
            print("Time to remove ",res_pattern[restriction], ":", end_res - start_res)
            if endergebnis == []:              
                endergebnis = addition
            else:
                endergebnis = list(set(endergebnis) & set(addition))
            addition = []
        if restriction == "no_consecutive_same_char":
            start_res = time.time()
            for element in password_list:
                if find_regex(res_pattern[restriction], ''.join(element)) == False:
                    addition.append(element)
            end_res = time.time()
            totaltime += (end_res - start_res)
            print("Time to remove ",res_pattern[restriction], ":", end_res - start_res)
            if endergebnis == []:              
                endergebnis = addition
            else:
                endergebnis = list(set(endergebnis) & set(addition))
            addition = []
        if restriction == "special_char_not_last_place":
            start_res = time.time()
            for element in password_list:
                if find_regex(res_pattern[restriction], ''.join(element)) == False:
                    addition.append(element)
            end_res = time.time()
            totaltime += (end_res - start_res)
            print("Time to remove ",res_pattern[restriction], ":", end_res - start_res)
            if endergebnis == []:              
                endergebnis = addition
            else:
                endergebnis = list(set(endergebnis) & set(addition))
            addition = []
    #print(len(password_list))

    print("Totaltime: ", totaltime)
    print(len(endergebnis))
    return {"count": int(len(endergebnis))}
# for testcase in testcases["testcases"]:
#     if testcase["type"] == "password_keyspace":
#         print(testcase['tcid'])
#         handle_password_keyspace(testcase['assignment'])

# assignment1 = {
#                 "alphabet": "abcdefABCDEF0123!$*",
#                 "length": 4,
#                 "restrictions": [
#                     "at_least_one_special_char",
#                     "at_least_one_uppercase_char",
#                     "at_least_one_lowercase_char",
#                     "at_least_one_digit",
#                     "no_consecutive_same_char",
#                     "special_char_not_last_place"
#                 ]
#             }

#andle_password_keyspace(assignment1)

ass2 = {
                "alphabet": "abcdefABCDEF0123!$*",
                "length": 4,
                "restrictions": [
                    "at_least_one_special_char",
                    "at_least_one_uppercase_char",
                    "at_least_one_lowercase_char",
                    "at_least_one_digit",
                    "no_consecutive_same_char",
                    "special_char_not_last_place"
                ]
            }
# def handle_set(assignment):
#     diccc = dict()
#     password_list= set(itertools.product(assignment['alphabet'], repeat=assignment['length']))
#     print(len(password_list))
#     for p in password_list:
#         s_p=''.join(p)
#         diccc[p] = 0
#     return diccc

handle_password_keyspace2(ass2)

# element = ('A', 'B', '6', '!')

# print(''.join(element))

# print(find_regex("[^A-Za-z0-9]+", ''.join(element)))


# # pattern = r"[!@#\\$%\\^\\&*\\)\\(+=._-]$"

# print(find_regex((pattern), "abcdef1*a"))