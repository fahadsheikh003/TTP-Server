# euler threorem (a^phi(n)) mod n = 1 where a is our generator and phi(n) is order of cyclic group
# in case of prime number n, phi(n) is equals to n - 1
def generator_check(p: int, g: int) -> bool:
    if pow(g, p - 1, p) == 1:
        return True
    return False
