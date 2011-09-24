import time
import talkers

def main():
    with talkers.Talker('master') as p:
        while 1:
            if p.poll(1):
                print p.recv()
            print "Doing something important now"

if __name__ == '__main__':
    main()
