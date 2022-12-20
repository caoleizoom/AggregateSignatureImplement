from fuzzy_extractor import FuzzyExtractor

def Gen(Rid):
    extractor = FuzzyExtractor(16, 8)
    key, helper = extractor.generate(Rid)
    return key, helper



