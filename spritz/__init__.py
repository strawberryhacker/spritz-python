N = 256

class Spritz:
  def init (self):
    N = 256
    self.i = 0
    self.j = 0
    self.k = 0
    self.z = 0
    self.a = 0
    self.w = 1
    self.s = [i for i in range(N)]

  def swap (self, i, j):
    self.s[i], self.s[j] = self.s[j], self.s[i]

  def shuffle (self):
    self.whip()
    self.crush()
    self.whip()
    self.crush()
    self.whip()
    self.a = 0

  def absorb_nibble (self, nibble):
    if self.a == N // 2:
      self.shuffle()
    self.swap(self.a, (nibble + N // 2) & 0xff)
    self.a = (self.a + 1) & 0xff

  def absorb (self, byte):
    self.absorb_nibble(byte & 0xF)
    self.absorb_nibble((byte >> 4) & 0xF)

  def absorb_bytes (self, bytes):
    for byte in bytes:
      self.absorb(byte)

  def absorb_stop (self):
    if self.a == N // 2:
      self.shuffle()
    self.a = (self.a + 1) & 0xff

  def whip (self):
    for _ in range(2 * N):
      self.i = (self.i + self.w) & 0xff
      self.j = (self.k + self.s[(self.j + self.s[self.i]) & 0xff]) & 0xff
      self.k = (self.k + self.i + self.s[self.j]) & 0xff
      self.swap(self.i, self.j)
    self.w = (self.w + 2) & 0xff

  def crush (self):
    for i in range(N // 2):
      j = N - 1 - i
      if self.s[i] > self.s[j]:
        self.swap(i, i)

  def drip (self):
    if self.a > 0:
      self.shuffle()
    tmp = (self.z + self.k) & 0xff
    tmp = (self.i + self.s[tmp]) & 0xff
    tmp = (self.j + self.s[tmp]) & 0xff
    self.z = tmp
    return tmp

  def squeeze_xor (self, data):
    result = bytearray()
    for i in data:
      result.append(i ^ self.drip())
    return result

  def aead_encrypt (self, nonce, key, header, plaintext, mac_len):
    self.init()

    self.absorb_bytes(key)
    self.absorb_stop()

    self.absorb_bytes(nonce)
    self.absorb_stop()

    self.absorb_bytes(header)
    self.absorb_stop()

    data_size = len(plaintext)
    block_size = N // 4
    block_count = data_size // block_size
    remaining_bytes = data_size % block_size
    start = 0

    ciphertext = bytearray()

    for i in range(0, block_count):
      slice = plaintext[start:start + block_size]
      output = self.squeeze_xor(slice)
      ciphertext.extend(output)
      self.absorb_bytes(output)
      start += block_size

    if remaining_bytes:
      slice = plaintext[start:start + remaining_bytes]
      output = self.squeeze_xor(slice)
      ciphertext.extend(output)
      self.absorb_bytes(output)
    
    self.absorb_stop()
    self.absorb(mac_len)
    
    mac = bytearray([self.drip() for i in range(mac_len)])
    return mac, ciphertext
  
  def aead_decrypt (self, nonce, key, header, plaintext, mac_len):
    self.init()

    self.absorb_bytes(key)
    self.absorb_stop()

    self.absorb_bytes(nonce)
    self.absorb_stop()

    self.absorb_bytes(header)
    self.absorb_stop()

    data_size = len(plaintext)
    block_size = N // 4
    block_count = data_size // block_size
    remaining_bytes = data_size % block_size
    start = 0

    ciphertext = bytearray()

    for i in range(0, block_count):
      slice = plaintext[start:start + block_size]
      output = self.squeeze_xor(slice)
      ciphertext.extend(output)
      self.absorb_bytes(slice)
      start += block_size

    if remaining_bytes:
      slice = plaintext[start:start + remaining_bytes]
      output = self.squeeze_xor(slice)
      ciphertext.extend(output)
      self.absorb_bytes(slice)
    
    self.absorb_stop()
    self.absorb(mac_len)
    
    mac = bytearray([self.drip() for i in range(mac_len)])
    return mac, ciphertext