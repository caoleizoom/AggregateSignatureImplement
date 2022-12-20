from fuzzy_extractor import FuzzyExtractor

def Rep(Pid,helper):
    extractor = FuzzyExtractor(16, 8)
    r_key = extractor.reproduce(Pid, helper)
    return r_key

