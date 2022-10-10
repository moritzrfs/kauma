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
    result = ''
    for c in text:
        if c in string.ascii_lowercase:
            pos = (string.ascii_lowercase.index(c) + shift) % 26
            result += string.ascii_lowercase[pos]
        elif c in string.ascii_uppercase:
            pos = (string.ascii_uppercase.index(c) + shift) % 26
            result += string.ascii_uppercase[pos]
        else:
            result += c
    return result