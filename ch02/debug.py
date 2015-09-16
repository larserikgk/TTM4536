def sum(a,b):
    int_a = convert_integer(a)
    int_b = convert_integer(b)

    result = int_a + int_b
    return result

def convert_integer(number_string):
    integer = int(number_string)
    return integer


answer = sum(5,3)