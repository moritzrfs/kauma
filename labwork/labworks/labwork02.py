import itertools
import re

res_pattern = {
    "at_least_one_special_char" : "[^A-Za-z0-9]+",
    "at_least_one_uppercase_char" : "[A-Z]+",
    "at_least_one_lowercase_char" : "[a-z]+",
    "at_least_one_digit" : "[0-9]+"
}

def find_regex(pattern, alphabet):
    return bool(re.match(pattern, alphabet))

def handle_password_keyspace(assignment):
    password_list= set(itertools.product(assignment['alphabet'], repeat=assignment['length']))

    for restriction in assignment['restrictions']:
    
        if restriction in res_pattern:
            for element in password_list.copy():
                lowercase = False
                for c in element:
                    lowercase= find_regex(res_pattern[restriction], c)
                    if lowercase == True:
                        break
                if lowercase == False:
                    password_list.remove(element)
        if restriction == "no_consecutive_same_char":
            for element in password_list.copy():
                s = ''
                for c in element:
                    if c == s:                        
                        password_list.remove(element)
                        break
                    else:
                        s=c
        if restriction == "special_char_not_last_place":
            for element in password_list.copy():
                if find_regex("[^A-Za-z0-9]+", element[-1]):
                    password_list.remove(element)    
    return {"count": int(len(password_list))}