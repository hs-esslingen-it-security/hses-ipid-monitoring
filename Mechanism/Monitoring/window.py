# window class
# window based monitoring approach
# monitoring of global and per-stream assignment behavior

DEBUG_FLAG = False
TEST_FLAG = False

def debug(string):
    if DEBUG_FLAG:
        print(string)


class Window:
    def __init__(self, increment: int, wrap_around: int, length: int, initial=-1, history_factor=0.6) -> None:
        self.increment = increment
        self.wrap_around = wrap_around 
    
        self.sliding_window = []
        self.length = length
        self.min_value_in_queue = initial # min and max bounds of window
        self.max_value_in_queue = initial-increment 
        self.history_factor = history_factor # how much history is stored within the window
        self.initial = initial # initialized with first IP-ID received after monitoring start, prior: -1

        while len(self.sliding_window) < self.length: # fill window
            self.max_value_in_queue += self.increment
            self.sliding_window.append([False, False])

        if self.min_value_in_queue > self.wrap_around: # wrap-around?
                self.min_value_in_queue = self.min_value_in_queue % (self.wrap_around+1)
        if self.max_value_in_queue > self.wrap_around: # 
                self.max_value_in_queue = self.max_value_in_queue % (self.wrap_around+1)


    def set_initial(self, initial) -> None:
        self.initial = initial # initialize with first IP-ID received at monitoring start
        self.min_value_in_queue = initial
        self.max_value_in_queue = initial + (self.length-1)*self.increment

        for i in range(0, len(self.sliding_window)): # update window
            self.sliding_window[i] = [False, False] # (Marked?, Fragments?)

        if self.min_value_in_queue > self.wrap_around:
                self.min_value_in_queue = self.min_value_in_queue % (self.wrap_around+1)
        if self.max_value_in_queue > self.wrap_around:
                self.max_value_in_queue = self.max_value_in_queue % (self.wrap_around+1)

    def __str__(self):
        return f"Window of size {self.length}, shift factor {self.history_factor}; min = {self.min_value_in_queue} ; max = {self.max_value_in_queue}"



    # returns: True if expected (counter falls within window), False else 
    def compare(self, counter: int, flags=None) -> bool:
        debug("")
        debug(f"compare {counter} with sliding window {self.sliding_window}  --  min = {self.min_value_in_queue} ; max = {self.max_value_in_queue}")
        
        if counter > self.wrap_around:
            debug("    mismatch of sizes -> False")
            return False
        if counter < self.increment: # to still follow monitoring after wrap-around
            self.initial = counter

        if (self.min_value_in_queue > self.max_value_in_queue and counter < self.min_value_in_queue and counter > self.max_value_in_queue) \
                or (self.min_value_in_queue < self.max_value_in_queue and (counter < self.min_value_in_queue or counter > self.max_value_in_queue)):
            debug("    outside of window -> False")
            return False

        if self.min_value_in_queue < self.max_value_in_queue:
            # normal case
            # expected increment?
            if (counter - self.initial) % self.increment == 0:
                target_position = int((counter-self.min_value_in_queue) / self.increment)
            else:
                debug("    does not fit increment -> False")
                return False

        else:
            # max already wraped around
            if counter <= self.max_value_in_queue:
                # counter wrapped around
                if (counter - self.initial) % self.increment == 0:
                    target_position = int((self.max_value_in_queue-counter)+1)*(-1)
                else:
                    debug("    does not fit increment -> False")
                    return False
            else:
                # counter did not wrap
                if (counter - self.initial) % self.increment == 0:
                    target_position = int((counter-self.min_value_in_queue) / self.increment)
                else:
                    debug("    does not fit increment -> False")
                    return False

        # correct window position
        if target_position < 0:
            target_position = int(self.length + (target_position / self.increment))

        # handle fragments and possible duplicates
        if flags and flags == 'MF':
            # following fragments
            self.sliding_window[target_position][1] = True
            debug(f"    following fragments")
            
        if self.sliding_window[target_position][0] and not self.sliding_window[target_position][1]:
            # not part of fragmented stream
            debug(f"    duplicate not caused by fragmentation -> False")
            return False
        if self.sliding_window[target_position][0] and self.sliding_window[target_position][1]:
            # fragment
            debug(f"    fragment -> True")
            return True


        self.sliding_window[target_position][0] = True
        debug(f"    -> True  --  updated position {target_position}: {self.sliding_window} --  min = {self.min_value_in_queue} ; max = {self.max_value_in_queue}")


        shift_size = max(0, target_position - int(self.length*self.history_factor))

        if shift_size > 0: # shift
            for _ in range(0, shift_size):
                self.sliding_window.append([False, False])
                self.sliding_window.pop(0)
                self.min_value_in_queue += self.increment
                self.max_value_in_queue += self.increment

            if self.min_value_in_queue > self.wrap_around:
                self.min_value_in_queue = self.min_value_in_queue % (self.wrap_around+1)
            if self.max_value_in_queue > self.wrap_around:
                self.max_value_in_queue = self.max_value_in_queue % (self.wrap_around+1)

        debug(f"    shift window by {shift_size}, new sliding window: {self.sliding_window}  --  min = {self.min_value_in_queue} ; max = {self.max_value_in_queue}")
        return True




if TEST_FLAG:
    w = Window(increment=1, wrap_around=15, length=10, initial=0)
    w.compare(0)
    w.compare(8)
    w.compare(8)
    w.compare(10, flags='MF')
    w.compare(10)
    w.compare(10)
    w.compare(12)
    w.compare(14)
    w.compare(15)
    w.compare(0)
    w.compare(1)
    w.compare(2)
    w.compare(2)

    w_256 = Window(increment=256, wrap_around=2000, length=6, initial=400)
    w_256.compare(400)
    w_256.compare(405)
    w_256.compare(912)
    w_256.compare(1680)
    w_256.compare(191)

    w_256.set_initial(400)
    w_256.compare(400)
