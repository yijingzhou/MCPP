import random
import primes

class Locksmith:
    """
    Generates keys for Diffie-Hellman. Vulnerable to man-in-the-middle attacks.

    Generates keys based on g and n. Can generate secret value or work with
    passed in value. g should be a primitive root of n
    In order to discourage key re-use (because the same session key will
    result each time) the intermediate values and keys can only be calculated
    once. You should create a new secret for each communication.

    Attributes:
      g (int) A primitive root of n
      n (int) A prime number
      randNum (int) The secret

    """

    def __init__(self, g, n, randNum):
        """
        Initializes the Locksmith. 

        Args:
            g(int): A primitive root of n 
            n(int): A prime number
            randNum(int): the secret 

        """
        if randNum == None:
            raise NotImplemented()

        self.randNum = randNum
        if not primes.isPrimitiveRoot(g, n):
            raise ValueError(str(g) + "is not a primitive root of " + str(n))
        self.g = g
        self.n = n
        self.intermValCalced = False
        self.keyCalced = False
        self.g = self.makeIntermediateVal()

    # CHECK THAT THIS WOULD BE A SECUIRITY PROBLEM FOR REPEAT..
    def makeIntermediateVal(self):
        """Makes the intermediate value/public key to send to other party

        To discourage session key re-use, may only be called once.

        Returns:
          The intermediate value to be given to other party
        """
        if self.intermValCalced:
            raise ValueError("Intermediate Value should only be calculated once.")
        self.intermValCalced = True
        return (self.g ** self.randNum) % self.n

    def update_g(self, g):
        return (g ** self.randNum) % self.n

    def makeKey(self, otherContribution):
        """Creates a session key using secret and contribution from other party.

        To discourage session key re-use, may only be called once.

        Args:
          otherContribution(int): The result of other party's 

        Returns:
          The session key.
        """
        if self.keyCalced:
            raise ValueError("Key should only be calculated once.")
        self.keyCalced = True
        return (otherContribution ** self.randNum) % self.n


def multi_parties(parties, g = None):
    """
    :param parties: a list of Locksmith objects
    :param g: public key
    :return: new public-private key
    """

    if len(parties) <= 1:
        g[1] +=1
        print("here", g)
        print(parties[0].makeKey(g[0]))
        return

    # Divide and conquer
    middle = len(parties) // 2
    left = parties[:middle]
    right = parties[middle:]

    if g == None:
        g_r = [left[0].g, 1]
        for i in range(1, len(left)):
            g_r[0] = left[i].update_g(g_r[0])
            g_r[1] +=1

        g_l = [right[0].g, 1]
        for i in range(1, len(right)):
            g_l[0] = right[i].update_g(g_l[0])
            g_l[1] +=1

    else:
        g_r = g[:]
        g_l = g[:]
        for m in left:
            g_r[0] = m.update_g(g_r[0])
            g_r[1] += 1
        for m in right:
            g_l[0] = m.update_g(g_l[0])
            g_l[1] += 1

    multi_parties(left, g_l)
    multi_parties(right, g_r)

g = 21
n = 997
parties = []
for i in range(30):
    parties.append(Locksmith(g, n, random.randint(1, n)))

multi_parties(parties)