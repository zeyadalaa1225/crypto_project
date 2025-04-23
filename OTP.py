from LCG import LCG
class OTP :
    def __init__(self,key) :
        self.key = key

    def encrypt(self,text:str) :
        length=len(text)
        gen = LCG(seed=self.key)
        key = gen.lcg(length=length)
        result= [key[i] ^ ord(text[i]) for i in range(length)]
        print(result)
        return result
    
    def decrypt(self,text) :
        length=len(text)
        gen = LCG(seed=self.key)
        key = gen.lcg(length=length)
        result= [key[i] ^ text[i] for i in range(length)]
        result ="".join([chr(i) for i in result])
        print(result)
        return result