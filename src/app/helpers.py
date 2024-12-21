import math
import string

allowed_chars = string.ascii_letters + string.digits + string.punctuation + ' \n\r'
username_allowed_chars = string.ascii_letters + string.digits + '._'


def count_entropy(password):
    pass_len = len(password)
    entropy = pass_len * math.log2(len(allowed_chars))

    return entropy


def is_input_valid(input_text, val=''):
    if val == 'username':
        return all(char in username_allowed_chars for char in input_text)
    elif val == 'code':
        return all(char in string.digits for char in input_text)

    return all(char in allowed_chars for char in input_text)
