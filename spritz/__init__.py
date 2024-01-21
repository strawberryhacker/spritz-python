class Spritz:
  def __init__ (self):
    self.init()

  def init (self):
    self.N = 256
    self.i = 0
    self.j = 0
    self.k = 0
    self.z = 0
    self.a = 0
    self.w = 1
    self.s = [i for i in range(self.N)]

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
    self.a = (self.a + 1) & 0xff

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

  def crypt (self, data, key):
    self.init()
    self.absorb_bytes(key)

    if self.a:
      self.shuffle()
    
    return self.xor(data)

  def xor (self, data, start, stop):
    result = bytearray()

    for i in range(start, stop):
      result.append(data[i] ^ self.drip())
      
    return result

  def aead (self, nonce, key, header, data, mac_len):
    self.init()

    self.absorb_bytes(key)
    self.absorb_stop()

    self.absorb_bytes(nonce)
    self.absorb_stop()

    self.absorb_bytes(header)
    self.absorb_stop()

    data_size = len(data)
    block_size = self.N // 4
    block_count = data_size // block_size
    remaining_bytes = data_size % block_size
    start = 0

    result = bytearray()
    result.extend(header)

    for i in range(0, block_count):
      stop = start + block_size
      result.extend(self.xor(data[start:stop]))
      self.absorb_bytes(data[start:stop])
      start += block_size

    if remaining_bytes:
      stop = start + remaining_bytes
      result.extend(self.xor(data[start:stop]))
      self.absorb_bytes(data[start:stop])
    
    self.absorb_stop()
    self.absorb(mac_len)
    
    mac = bytearray([self.drip() for i in range(mac_len)])
    return mac, result