# make a script that generates 1 gb of random ascii data
# english alphabet, numbers, and special characters

import random

def random_ascii_data():
    with open('randomdata2.txt', 'w') as f:
        for _ in range(1_000_000):
            f.write(chr(random.randint(33, 126)))

if __name__ == '__main__':
    random_ascii_data()