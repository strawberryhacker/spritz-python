class Context:
  def __init__ (self):
    self.N = 256
    self.i = 0
    self.j = 0
    self.k = 0
    self.z = 0
    self.a = 0
    self.w = 1
    self.s = [i for i in range(self.N)]

  def init (self):
    for i in range(self.N):
      self.s[i] = i

    self.i = 0
    self.j = 0
    self.k = 0
    self.z = 0
    self.a = 0
    self.w = 1

  def swap (self, i, j):
    a = self.s[i]
    b = self.s[j]
    self.s[i] = b
    self.s[j] = a

  def shuffle (self):
    self.whip()
    self.crush()
    self.whip()
    self.crush()
    self.whip()
    self.a = 0

  def absorb_nibble (self, nibble):
    if self.a == self.N // 2:
      self.shuffle()
    self.swap(self.a, (nibble + self.N // 2) & 0xFF)
    self.a += 1

  def absorb (self, byte):
    self.absorb_nibble(byte & 0xF)
    self.absorb_nibble((byte >> 4) & 0xF)

  def absorb_bytes (self, bytes):
    for byte in bytes:
      self.absorb(byte)

  def absorb_stop(self):
    if self.a == self.N // 2:
      self.shuffle()
    self.a = (self.a + 1) & 0xFF

  def whip (self):
    for _ in range(2 * self.N):
      self.i = (self.i + self.w) & 0xFF
      self.j = (self.k + self.s[(self.j + self.s[self.i]) & 0xFF]) & 0xFF
      self.k = (self.k + self.i + self.s[self.j]) & 0xFF
      self.swap(self.i, self.j)
    self.w = (self.w + 2) & 0xFF

  def crush (self):
    for i in range(self.N // 2):
      j = self.N - 1 - i
      if self.s[i] > self.s[j]:
        self.s[i], self.s[j] = self.s[j], self.s[i]

  def drip (self):
    if self.a > 0:
      self.shuffle()
    tmp = (self.z + self.k) & 0xFF
    tmp = (self.i + self.s[tmp]) & 0xFF
    tmp = (self.j + self.s[tmp]) & 0xFF
    self.z = tmp
    return tmp

  def crypt_init (self, key):
    self.init()
    self.absorb_bytes(key)
    if self.a:
      self.shuffle()

  def crypt (self, data):
    encrypted_data = bytearray()
    for byte in data:
      encrypted_data.append(byte ^ self.drip())
    return encrypted_data
