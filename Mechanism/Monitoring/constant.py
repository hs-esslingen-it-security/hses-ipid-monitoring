# monitoring of constant assignment behavior

DEBUG_FLAG = False
TEST_FLAG = False

def debug(string):
    if DEBUG_FLAG:
        print(string)


class Constant:
    def __init__(self, constant) -> None:
        self.initial = -1
        self.constant = constant

    def set_initial(self, initial) -> None:
        self.initial = initial

    def __str__(self):
        return f"Constant {self.constant}"

    # returns: True if expected, False else 
    def compare(self, counter: int) -> bool:
        debug(f"compare {counter} with constant {self.constant}")
        return int(counter) == int(self.constant)


if TEST_FLAG:
    c = Constant()
    c.compare(0)
    c.compare(5)
    c.set_initial(5)
    c.compare(0)
    c.compare(5)
