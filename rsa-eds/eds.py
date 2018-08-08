def generate_table():
    from eds import making_code
    with open("coded_table.bin", 'ab') as output_table:
        count = 1
        for i in range(ord('a'), ord('z') + 1):
            cnt = str(count)
            if len(cnt) == 1:
                cnt = '0' + cnt
            mas = [chr(i), cnt]
            code = making_code(mas, len(mas))
            output_table.write(bytes(code))
            count += 1
        for i in range(ord('!'), ord('A') - 1):
            cnt = str(count)
            mas = [chr(i), cnt]
            code = making_code(mas, len(mas))
            output_table.write(bytes(code))
            count += 1
        mas = [' ', '00']
        code = making_code(mas, len(mas))
        output_table.write(bytes(code))


def is_prime(x):
    i = 2
    while i * i <= x:
        if x % i == 0:
            return False
        i += 1
    return True


def inverse_num(e, n):
    t = 0
    new_t = 1
    r = n
    new_r = e
    while new_r != 0:
        quotient = r // new_r
        (t, new_t) = (new_t, t - quotient * new_t)
        (r, new_r) = (new_r, r - quotient * new_r)
    if t < 0:
        t = t + n
    return t


def get_keys():
    from random import randint
    p = randint(1e6, 1e9)
    while not is_prime(p):
        p = randint(1e6, 1e9)
    q = randint(1e6, 1e9)
    while not is_prime(q) or p == q:
        q = randint(1e6, 1e9)
    n = p * q
    phi_n = (p - 1) * (q - 1)
    from math import gcd
    e = randint(2, 1000)
    while not is_prime(e) and gcd(phi_n, e) != 1:
        e = randint(2, 1000)
    d = inverse_num(e, phi_n)
    pubkey = (e, n)
    privkey = (d, n)
    return pubkey, privkey


def fast_computing_power(x, power):
    bin_deg = "{0:b}".format(power[0])
    res = x
    for i in range(1, len(bin_deg)):
        res = ((res ** 2) * (x ** int(bin_deg[i]))) % power[1]
    return res


def rsa_encrypt(m, user):
    with open("base_of_users.bin", 'rb') as input_keys:
        for line in input_keys:
            data = line.decode().split('\t')
            if data[0] == user:
                if data[5][len(data[5]) - 1] != '\n':
                    code = data[5]
                else:
                    code = data[5][0:(len(data[5]) - 1)]
                privkey = (int(data[4]), int(code))
                break
    c = fast_computing_power(m, privkey)
    return c


def rsa_decrypt(c, user):
    with open("base_of_public_keys.bin", 'rb') as input_users:
        for line in input_users:
            data = line.decode().split('\t')
            if data[0] == user:
                if data[2][len(data[2]) - 1] != '\n':
                    code = data[2]
                else:
                    code = data[2][0:(len(data[2]) - 1)]
                pubkey = (int(data[1]), int(code))
                break
    decrypted_eds = fast_computing_power(c, pubkey)
    return decrypted_eds


def coding_message(message):
    table_coded = {}
    table_decoded = {}
    with open("coded_table.bin", 'rb') as input_table:
        for line in input_table:
            data = line.decode().split('\t')
            if data[1][len(data[1]) - 1] != '\n':
                code = data[1]
            else:
                code = data[1][0:(len(data[1]) - 1)]
            table_coded[data[0]] = code
            table_decoded[code] = data[0]
    count = len(table_coded)
    coded_message = ''
    for symbol in message.lower():
        if not symbol.isalpha() and symbol != ' ' and symbol not in table_coded:
            cnt = str(count)
            table_coded[symbol] = cnt
            table_decoded[cnt] = symbol
            count += 1
        coded_message = coded_message + table_coded[symbol]
    return coded_message


def encrypt_eds(coded_message, user):
    with open("base_of_users.bin", 'rb') as input_keys:
        for line in input_keys:
            data = line.decode().split('\t')
            if data[0] == user:
                if data[5][len(data[5]) - 1] != '\n':
                    code = data[5]
                else:
                    code = data[5][0:(len(data[5]) - 1)]
                break
    length = len(str(code))
    if len(coded_message) + 2 >= length:
        encrypted_eds = ''
        i = 0
        flag = True
        while i < len(coded_message):
            if i + length - 5 < len(coded_message):
                block = coded_message[i:(i + length - 4)]
                i += length - 4
            else:
                block = coded_message[i:len(coded_message)]
                i = len(coded_message)
                flag = False
            cryptogramm = rsa_encrypt(int('10' + block), user)
            encrypted_eds = encrypted_eds + str(cryptogramm)
            if flag:
                encrypted_eds += ':'
    else:
        encrypted_eds = str(rsa_encrypt(int('10' + coded_message), user))
    return encrypted_eds


def decrypt_eds(encrypted_eds, user):
    encrypted_eds = encrypted_eds.split(':')
    decrypted_eds = ''
    for message in encrypted_eds:
        rsa_decrypted = str(rsa_decrypt(int(message), user))
        decrypted_eds = decrypted_eds + rsa_decrypted[2:]
    return decrypted_eds


def decoding_eds(decrypted_eds):
    table_coded = {}
    table_decoded = {}
    with open("coded_table.bin", 'rb') as input_table:
        for line in input_table:
            data = line.decode().split('\t')
            if data[1][len(data[1]) - 1] != '\n':
                code = data[1]
            else:
                code = data[1][0:(len(data[1]) - 1)]
            table_coded[data[0]] = code
            table_decoded[code] = data[0]
    message = ''
    for i in range(0, len(str(decrypted_eds)), 2):
        code = (str(decrypted_eds))[i:(i+2)]
        message = message + table_decoded[str(code)]
    return message


def receive_eds(encrypted_eds, user):
    try:
        decrypted_eds = decrypt_eds(encrypted_eds, user)
        message = decoding_eds(decrypted_eds)
    except:
        return 'Incorrect message, error'
    return message


def send_eds(message, user):
    coded_message = coding_message(message)
    encrypted_eds = encrypt_eds(coded_message, user)
    return encrypted_eds




