import string

def handle_strcat(assignment):
	return " ".join(assignment["parts"])

def handle_histogram(assignment):
	histogram = {}
	for c in set(assignment['text']):
		histogram[c] = assignment['text'].count(c)
	return histogram

def handle_caesar(assignment):
    action = assignment['action']
    shift = assignment['letter_shift']
    if action == 'encrypt':
        text = assignment['plaintext']
    elif action == 'decrypt':
        text = assignment['ciphertext']
        shift *= -1
    
    lowercase_letters = string.ascii_lowercase
    uppercase_letters = string.ascii_uppercase
    result = ''
    for c in text:
        if c in lowercase_letters:
            pos = lowercase_letters.index(c)
            pos += shift
            pos = pos % 26
            result += lowercase_letters[pos]
        elif c in uppercase_letters:
            pos = uppercase_letters.index(c)
            pos += shift
            pos = pos % 26
            result += uppercase_letters[pos]
        else:
            result += c
    return result