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
        return pow(self.g, self.randNum, self.n)

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
        return pow(otherContribution, self.randNum, self.n)
