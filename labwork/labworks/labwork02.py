import re
import itertools

def handle_password_keyspace(assignment):
    possible_passwords = len(assignment['alphabet'])**assignment['length']
    lowercase_letters = re.findall(r"[a-z]+", assignment['alphabet'])[0]
    uppercase_letters = re.findall(r"[A-Z]+", assignment['alphabet'])[0]
    numbers = re.findall(r"[0-9]+", assignment['alphabet'])[0]
    others = re.findall(r"[^A-Za-z0-9]+", assignment['alphabet'])[0]
    
    c_alphabet = len(assignment['alphabet'])
    c_lowercase_letters = len(lowercase_letters)
    c_uppercase_letters = len(uppercase_letters)
    c_numbers = len(numbers)
    c_others = len(others)

    print(c_alphabet)

    if 'at_least_one_lowercase_char' in assignment['restrictions']:
        no_lowercase_char = (c_alphabet-c_lowercase_letters)**assignment['length']
        possible_passwords = possible_passwords-no_lowercase_char
    if 'special_char_not_last_place' in assignment['restrictions']:
        possible_passwords = possible_passwords-(c_alphabet**(assignment['length']-1))*(c_others)
    if 'at_least_one_special_char' in assignment['restrictions']:
        possible_passwords = possible_passwords-((c_alphabet-c_others)**assignment['length'])
    if 'at_least_one_uppercase_char' in assignment['restrictions']:
        possible_passwords = possible_passwords-((c_alphabet-c_uppercase_letters)**assignment['length'])
    if 'at_least_one_digit' in assignment['restrictions']:
        possible_passwords = possible_passwords-((c_alphabet-c_numbers)**assignment['length'])
    if 'no_consecutive_same_char' in assignment['restrictions']:
        possible_passwords = c_alphabet*((c_alphabet-1)**(assignment['length']-1))

    
    '''
    if 'at_least_one_lowercase_char' and 'at_least_one_digit' in assignment['restrictions']:
        possible_passwords +=(c_alphabet-test) **4'''
    return possible_passwords
    
ass = {
                "alphabet": "abcdefABCDEF0123!$*",
                "length": 4,
                "restrictions": [
                    "no_consecutive_same_char"
                ]
            }

print(handle_password_keyspace(ass))

