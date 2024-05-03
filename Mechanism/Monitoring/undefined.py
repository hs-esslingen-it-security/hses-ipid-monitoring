# 'monitoring' undefined assignment behavior
# all behavior is expected behavior

DEBUG_FLAG = False
TEST_FLAG = False

def debug(string):
    if DEBUG_FLAG:
        print(string)


class Undefined:
    def __init__(self) -> None:
        self.initial = -1

    def set_initial(self, initial) -> None:
        self.initial = initial

    def __str__(self):
        return "Undefined object"

    # returns: True if expected, False else 
    def compare(self, counter: int) -> bool:
        return True


if TEST_FLAG:
    u = Undefined()
    u.compare(17)
    u.compare(1)
