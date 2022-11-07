import base64

def handle_chi_square(assignment):
    data = base64.b64decode(assignment['data'])
    selectors = assignment['selectors']
    solution = []
    
    if assignment['action'] == "decimate":
        decimated = handle_decimate(data, selectors)[0]
        for dec in decimated:
            solution.append({'decimated_data': base64.b64encode(dec).decode('utf-8')})
    elif assignment['action'] == "histogram":
        histograms = handle_histogram(data, selectors, False)
        for hist in histograms:
            solution.append({'histogram': hist})
    elif assignment['action'] == "chi_square":
        chi_squares = compute_chi_square(data, selectors)
        solution = handle_verdict(chi_squares)
    return solution
        
def handle_decimate(data, selectors):
    solutions = []
    lengths = []
    if selectors: # if selectors not empty
        for selector in selectors:
            offset = selector['offset'] if 'offset' in selector else 0 
            stride = selector['stride'] if 'stride' in selector else 1 
            decimated = data[offset::stride] # get every nth byte from data starting from offset
            solutions.append(decimated)
            lengths.append(len(decimated))
    else:
        solutions.append(data)
    return solutions, lengths

def handle_histogram(data, selectors, chi_square=False):
    decimated = handle_decimate(data, selectors)[0]
    solutions = []
    for data in decimated:
        occurences = {}
        for byte in data:
            if byte in occurences:
                occurences[byte] += 1
            else:
                occurences[byte] = 1
        if not chi_square:
            solutions.append({str(byte): occurences[byte] for byte in occurences})
        else:  # add all missing numbers to occurences to work with chi_square
            for i in range(256):
                if i not in occurences:
                    occurences[i] = 0
            solutions.append({byte: occurences[byte] for byte in occurences})
    return solutions

def compute_chi_square(data, selectors):
    solutions = []
    histograms = handle_histogram(data, selectors, True)
    lengths = handle_decimate(data, selectors)[1]
    ctr = 0
    for histogram in histograms:
        n = lengths[ctr]
        chi_square = 0
        for byte in histogram:
            chi_square += (histogram[byte] - n/256)**2 * 256/n
        ctr+=1
        solutions.append(round(chi_square))
    return solutions

def handle_verdict(chi_squares):
    solution = []
    for chisq in chi_squares:
        if chisq >= 311:
            solution.append({"chi_square_statistic": chisq , 'verdict': 'non_uniform'})
        elif chisq <= 205:
            solution.append({"chi_square_statistic": chisq , 'verdict': 'uniform'})
        else:
            solution.append({"chi_square_statistic": chisq , 'verdict': 'no_result'})
    return solution
