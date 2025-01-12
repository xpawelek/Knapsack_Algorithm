from random import randint
from math import gcd


#generating super-increasing sequence
def generate_super_increasing_sequence(n: int) -> list:
    sequence = [randint(1, 100)]
    while len(sequence) < n:
        sequence.append(sum(sequence) + randint(1, 100))
    return sequence


def find_inverse_modular(m: int, w: int) -> int:
    x = [1, 0]
    y = [0, 1]
    r = [m, w]
    q = [None]
    counter = 1

    while r[len(r) - 1] != 1:
        q_val = r[counter - 1] // r[counter]
        q.insert(counter, q_val)
        r_val = r[counter - 1] % r[counter]
        r.insert(counter + 1, r_val)

        new_x = x[counter-1] - (q[counter] * x[counter])
        new_y = y[counter - 1] - (q[counter] * y[counter])
        x.append(new_x)
        y.append(new_y)

        counter += 1
    return y[counter]


#generating public key - formula: ei = w * seq[i] (mod m)
def generate_public_key(seq: list, m: int, w:int) -> list:
    return [w * elem % m for elem in seq]


# function to ecrypt message using public key
def encrypt_message(binary_message: str, public_key: list, n: int) -> list:
    binary_message = binary_message.strip().replace(" ", "")
    binary_message = (n - len(binary_message) % n) * '0' + binary_message #adding 0's if len(mes) % n != 0, equal groups
    groups = []

    splitter = 0
    #splitting into groups
    while splitter <= len(binary_message) - n:
        groups.append(binary_message[splitter:splitter + n])
        splitter += n

    encrypted_message = []
    #encrypting each group
    for group in groups:
        i = -1
        encrypted_message.append(sum([int(elem) * public_key[(i := i + 1)] for elem in group]))

    return encrypted_message


#function to decrypt message using private_key
def decrypt_message(encrypted_message: list, private_key: dict) -> str:
    #finding seq_prim using forumla: Ci` = Ci * w (mod m), w - modular inverse
    seq_prim = [elem * private_key["modular_inverse"] % private_key["m"] for elem in encrypted_message]

    #backtracking to decrypt each element
    decrypted_message = []
    seq_size = len(private_key["seq"])

    for elem in seq_prim:
        decrypted_part = ""
        if elem == 0:
            decrypted_part = "0" * seq_size
            decrypted_message.append(decrypted_part)
            continue

        i = len(private_key["seq"]) - 1
        j = 1
        sum = 0
        while sum != elem:
            if elem >= sum + private_key["seq"][i]:
                decrypted_part = "1" + decrypted_part
                sum += private_key["seq"][i]
            else:
                decrypted_part = "0" + decrypted_part

            if elem == sum:
                break

            if i == 1 and elem != sum + private_key["seq"][0]:
                i = seq_size - 1 - j
                decrypted_part = "0" * j

            i -= 1

        prepend_zeros = seq_size - (len(decrypted_part) % seq_size)
        decrypted_part = "0" * (prepend_zeros % seq_size) + decrypted_part
        decrypted_message.append(decrypted_part)

    decrypted_message = remove_leading_zero_bytes("".join(decrypted_message))

    prepend_zeros = 8 - len(decrypted_message) % 8
    decrypted_message = prepend_zeros * "0" + decrypted_message

    first_byte_zero = False
    for bit in decrypted_message[0:8]:
        if bit == 1:
            first_byte_zero = True

    if first_byte_zero:
        decrypted_message = on_convert(decrypted_message, encoding='utf-8')
    else:
        decrypted_message = on_convert(decrypted_message[8:], encoding='utf-8')

    return decrypted_message


#converting binary to unicode text
def on_convert(binary_input: str, encoding='utf-8') -> str:
    binary_clean = ''.join(filter(lambda x: x in '01', binary_input))

    if len(binary_clean) % 8 != 0:
        raise ValueError("Binary sequence length should be divisible by 8.")

    #dividing into bytes
    byte_chunks = [binary_clean[i:i + 8] for i in range(0, len(binary_clean), 8)]

    byte_array = bytearray(int(byte, 2) for byte in byte_chunks)

    #bytes decoding
    try:
        text = byte_array.decode(encoding)
    except UnicodeDecodeError as e:
        raise ValueError(f"Decoding error: {e}")

    return text


#converting text to binary
def on_encode(text_input: str, encoding='utf-8', separator=' ') -> str:
    try:
        byte_array = text_input.encode(encoding)
    except UnicodeEncodeError as e:
        raise ValueError(f"Encoding error: {e}")

    # each byte to 8 bit seq
    binary_chunks = [format(byte, '08b') for byte in byte_array]

    binary_string = separator.join(binary_chunks)

    return binary_string


def remove_leading_zero_bytes(binary_str: str) -> str:
    byte_chunks = [binary_str[i:i + 8] for i in range(0, len(binary_str), 8)]

    while byte_chunks and byte_chunks[0] == '00000000':
        byte_chunks.pop(0)

    return ''.join(byte_chunks)


if __name__ == "__main__":
    try:
        size = randint(10, 100) #size of super increasing seq
        sequence = generate_super_increasing_sequence(size)
        m = sum(sequence) + randint(1, 10) #num greater than sum of super increasing seq

        #calculating w, which is num less than m and gives gcd(w,m) equal 1
        w = None
        attempts = 0
        while True:
            w_candidate = randint(2, m - 1)
            if gcd(m, w_candidate) == 1:
                w = w_candidate
                break
            attempts += 1
            if attempts > 1000:
                raise Exception("Generating w, which is num less than m and gives gcd(w,m) equal 1 has failed after 1000 attempts.")

        #print(f"m = {m}\n w = {w}\n gcd(m,w) = {gcd(m,w)}")

        #finding modular inverse using extended Eucleadian algorithm
        modular_inverse = find_inverse_modular(m, w)

        public_key = generate_public_key(sequence,  m, w)
        private_key = {
            "seq": sequence,
            "m": m,
            "modular_inverse": modular_inverse
        }
        while 1:
            message = input("Enter message to encrypt:")
            message = on_encode(message, separator=" ")
            encrypted_message = encrypt_message(message, public_key, size)
            print(f"Encrypted message: {encrypted_message}\n")
            message = decrypt_message(encrypted_message, private_key)
            print(f"Decrypted message: {message}\n")
    except Exception as error:
        print(f"An error has occured: {error}")

'''
1. super rosnacy ciag
2. liczba calkowita wieksza od sumy wyrazow super rosnacego ciagu
3. mniejsza od powyzszej ale gwd = 1
4. odwrortnosc liczby modularnej - rozszerzony algorytm euklidesa
5. klucz publiczny , prywatny - szyfrowanie i deszyfrowanie
'''