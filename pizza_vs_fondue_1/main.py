#!/usr/bin/python3

import random
import os
import sys

from HCom import HCom

flag = os.getenv('FLAG', default='CTF{dummyflag}')

class Alice:
    def __init__(self):
        self.coin = random.choice([True, False])
        self.C = None
        self.bobs_coin = None

    def step0_greeting(self):
        print('Hi Bob, Alice speaking!')
        print('We still haven\'t decided on dinner yet. I want Pizza, you want Fondue.')
        print('I suggest, we both toss a coin and take the XOR.')
        print('False = Pizza')
        print('True = Fondue')
        print('')
        print('You go first! Send me the commitment to your bit.')

    def step1_recv(self):
        while True:
            C_str = input('[Commitment to "True" or "False" as hex-string]: ')
            if len(C_str) == 0:
                print('Hello? Did you say something?')
                continue

            try:
                C = bytes.fromhex(C_str)
            except ValueError:
                print('Sorry, I could not parse your input.')
                continue

            break

        self.C = C

    def step2_send(self):
        print(f'Okay, my coin is {self.coin}. Now tell me yours!')

    def step3_step5_recv(self):
        while True:
            inp = input('[msg and r, separated by a comma (,)]:')
            try:
                (msg, r_str) = inp.split(',')
            except ValueError:
                print('Sorry, I could not parse your input. Did you forget the comma?')
                continue

            try:
                r = int(r_str)
            except ValueError:
                print('Sorry, I could not parse r as integer.')
                continue

            break

        if not HCom.vrf(msg, r, self.C):
            print('I can tell that you\'re lying!')
            print('I start to question whether I want to have dinner with you at all!')
            sys.exit(1)

        try:
            self.bobs_coin = Alice._str_to_bool(msg)
        except ValueError:
            print('I didn\'t get what you were saying. I thing the connection is bad.')
            print('Why don\'t we just eat Pizza?')
            sys.exit(1)

    def step4_send(self):
        if self.coin ^ self.bobs_coin == False:
            print('Nice! We\'re gonna eat Pizza. Exactly what I wanted')
            sys.exit(1)

        print('Hmmmm, I don\'t like this result. Let me change my coin.')
        self.coin = not self.coin
        print(f'It now is {self.coin}.')
        print('Sorry, what did you say your coin was again?')

    # step5 = step3

    def step6_end(self):
        if self.coin ^ self.bobs_coin == False:
            print('Oh, good that I changed my coin.')
            print('Now we\'re gonna eat Pizza as I wanted')
            sys.exit(1)

        print('Lucky you! Apparently the coins were in your favor.')
        print('So we\'re going to eat Fondue, but I\'d much rather it this tasty flag:')
        print(flag)

    def run(self):
        self.step0_greeting()
        self.step1_recv()
        self.step2_send()
        self.step3_step5_recv()
        self.step4_send()
        self.step3_step5_recv()
        self.step6_end()


    def _str_to_bool(mystr:str):
        # For the user's convenience
        # we do case-insensitive matching
        # by comparing the lengths
        # len("True") = 4
        # len("False") = 5

        match len(mystr):
            case 4:
                return True
            case 5:
                return False
            case _:
                raise ValueError


if __name__ == '__main__':
    A = Alice()
    A.run()

