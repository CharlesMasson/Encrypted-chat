#!/usr/bin/env python3

from threading import Thread
import time

class Running(Thread):
    def __init__(self, msg):
        Thread.__init__(self)
        self.msg = msg
    def run(self):
        while True:
            print("\nmsg = {0}".format(self.msg))
            time.sleep(1)

r = Running("...")
r.start()

import readline # better input

while True:
    m = input("m> ")
    print("m={0}".format(m))

