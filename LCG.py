class LCG:
    def __init__(self, seed=1, a=1664525, c=1013904223, m=2**32):
        self.seed = seed
        self.a = a
        self.c = c
        self.m = m
    def next(self):
        self.seed = (self.a * self.seed + self.c) % self.m
        return self.seed
    def lcg(self,length=1):
        output = [self.next() % 256 for _ in range(length)]
        print(output)
        return output