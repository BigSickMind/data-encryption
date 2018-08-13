def add_code(code, elements):
    for symbol in elements:
        code.append(int("{0:b}".format(ord(symbol)), 2))


def making_code(mas, lim):
    code = []
    counter = 0
    for elements in mas:
        counter += 1
        if counter < lim:
            elements += '\t'
        else:
            elements += '\n'
        add_code(code, elements)
    return code


def previously_list(data):
    print("Message-ID: {} From: {} To: {} Date: {} Time {}".format(data[0], data[1], data[2], data[4], data[5]))


def prepared_list(data):
    msg_eds = data[3].split("c:::")
    msg = msg_eds[0]
    encrypted_eds = msg_eds[1]
    from .eds import receive_eds
    eds = receive_eds(encrypted_eds, data[1])
    if msg != eds:
        print("\nCorrupted message with Message-ID {}, some packages were lost\n".format(data[0]))
    else:
        print("\nMessage-ID: {}".format(data[0]))
        print("From: {}".format(data[1]))
        print("To: {}".format(data[2]))
        print("Message: {}".format(msg))
        print("Date: {} Time: {}\n".format(data[4], data[5]))


def read_msg_id():
    with open("counter.bin", 'rb') as input_counter:
        res = ""
        for line in input_counter:
            data = line.decode().split('\n')
            res += data[0]
        counter = int(res)
        return counter


def write_msg_id(msg_id):
    with open("counter.bin", 'ab') as output_counter:
        output_counter.seek(0)
        output_counter.truncate()
        s = str(msg_id)
        code = []
        add_code(code, s)
        code.append(int("{0:b}".format(ord('\n')), 2))
        output_counter.write(bytes(code))


def print_commands():
    print("Write message\n")
    print("Delete messages\n")
    print("Check new messages\n")
    print("View history of messages\n")


def print_users(user):
    have_users = False
    with open("base_of_users.bin", 'rb') as input_users:
        for line in input_users:
            data = line.decode().split('\t')
            if data[0] != user:
                have_users = True
                print(data[0])
    return have_users


def print_groups():
    have_groups = False
    with open("base_of_groups.bin", 'rb') as input_groups:
        for line in input_groups:
            data = line.decode().split('\n')
            have_groups = True
            print(data[0])
    return have_groups


def check_users(user):
    with open("base_of_users.bin", 'rb') as input_users:
        for line in input_users:
            data = line.decode().split('\t')
            if data[0] == user:
                return False
        return True


def check_groups(group):
    with open("base_of_groups.bin", 'rb') as input_groups:
        for line in input_groups:
            data = line.decode().split('\n')
            if data[0] == group:
                return False
        return True


def check_users_auth(username, password):
    with open("base_of_users.bin", 'rb') as input_users:
        for line in input_users:
            data = line.decode().split('\t')
            if data[0] == username and data[1] == password:
                return True, data[2]
    return False, 'n'


def check_users_groups(s, type_of_user):
    check_user = check_users(s)
    check_group = True
    if type_of_user == 'a':
        check_group = check_groups(s)
    return not check_user or not check_group


def add_user(user, passwd, type_of_user_add, group, privkey):
    mas = [user, passwd, type_of_user_add, group, str(privkey[0]), str(privkey[1])]
    code = making_code(mas, len(mas))
    with open("base_of_users.bin", 'ab') as output_users:
        output_users.write(bytes(code))
    if type_of_user_add != 'a':
        print("{} was added successfully\n".format(user))


def add_public_key(user, pubkey):
    mas = [user, str(pubkey[0]), str(pubkey[1])]
    code = making_code(mas, len(mas))
    with open("base_of_public_keys.bin", 'ab') as output_keys:
        output_keys.write(bytes(code))


def update_user_group(group, list_of_users):
    rewrite = []
    with open("base_of_users.bin", 'rb+') as input_users:
        for line in input_users:
            data = line.decode().split('\t')
            if data[0] in list_of_users:
                mas = [data[0], data[1], data[2], group]
                code = making_code(mas, len(mas))
                rewrite.append(code)
            else:
                rewrite.append(line)
        input_users.seek(0)
        input_users.truncate()
    with open("base_of_users.bin", 'ab') as output_users:
        for data in rewrite:
            output_users.write(bytes(data))


def add_group(group, list_of_users):
    code = []
    add_code(code, group)
    code.append(int("{0:b}".format(ord('\n')), 2))
    with open("base_of_groups.bin", 'ab') as output_users:
        output_users.write(bytes(code))
    update_user_group(group, list_of_users)
    print("{} was created successfully\n".format(group))


def add_user_to_group(user, group):
    group_user = ""
    found_user = False
    with open("base_of_users.bin", 'rb') as input_users:
        for line in input_users:
            data = line.decode().split('\t')
            if data[0] == user:
                group_user = data[3]
                found_user = True
                break
    found_group = False
    with open("base_of_groups.bin", 'rb') as input_groups:
        for line in input_groups:
            data = line.decode().split('\n')
            if data[0] == group:
                found_group = True
    if found_user and found_group and group_user.lower() == "none":
        update_user_group(group, [user])
        print("{} was successfully added to group {}\n".format(user, group))
    else:
        if not found_user:
            print("There now such user in user's database\n")
        elif not found_group:
            print("There now such group in group's database\n")
        elif group_user != 'None':
            print("{} composed in group {}\n".format(user, group))


def write_msg_to_user(from_msg, to_msg, msg, date, time):
    from .eds import send_eds
    encrypted_eds = send_eds(msg, from_msg)
    msg_id = read_msg_id()
    msg += "c:::"
    msg += str(encrypted_eds)
    mas = [str(msg_id), from_msg, to_msg, msg, date, time, '0']
    code = making_code(mas, len(mas))
    with open("base_of_messages.bin", 'ab') as output_messages:
        output_messages.write(bytes(code))
    msg_id += 1
    write_msg_id(msg_id)


def write_msg_to_group(from_msg, group_msg, msg, date, time):
    with open("base_of_users.bin", 'rb') as input_users:
        for line in input_users:
            data = line.decode().split('\t')
            group = data[3]
            if group_msg == group:
                write_msg_to_user(from_msg, data[0], msg, date, time)


def rewrite_file(rewrite):
    new_code = []
    for mas in rewrite:
        code = making_code(mas, len(mas))
        new_code.append(code)
    with open("base_of_messages.bin", 'ab') as output_messages:
        for data in new_code:
            output_messages.write(bytes(data))


def list_of_senders(user):
    have_msg = False
    with open("base_of_messages.bin", 'rb') as input_messages:
        for line in input_messages:
            data = line.decode().split('\t')
            length = len(data[6])
            if data[6][length - 1] != '\n':
                checked = data[6]
            else:
                checked = data[6][0:(length - 1)]
            if data[2] == user and checked == '0':
                have_msg = True
                msg_crc = data[3].split("c:::")
                msg_recv = msg_crc[0]
                previously_list(data)
    return have_msg


def new_messages(user, id_msg):
    rewrite = []
    have_msg = False
    with open("base_of_messages.bin", 'rb+') as input_messages:
        for line in input_messages:
            data = line.decode().split('\t')
            length = len(data[6])
            if data[6][length - 1] != '\n':
                checked = data[6]
            else:
                checked = data[6][0:(length - 1)]
            mas = [data[i] for i in range(len(data) - 1)]
            if data[0] == id_msg and data[2] == user and checked == '0':
                have_msg = True
                prepared_list(data)
                mas.append('1')
            else:
                mas.append(checked)
            rewrite.append(mas)
        if have_msg:
            input_messages.seek(0)
            input_messages.truncate()
    if have_msg:
        rewrite_file(rewrite)
    else:
        print("No message with Message-ID {}, maybe it was read before".format(id_msg))


def list_of_messages(user, to):
    have_msg = False
    with open("base_of_messages.bin", 'rb+') as input_messages:
        for line in input_messages:
            data = line.decode().split('\t')
            length = len(data[6])
            if data[6][length - 1] != '\n':
                checked = data[6]
            else:
                checked = data[6][0:(length - 1)]
            if ((data[1] == user and data[2] == to) or (data[1] == to and data[2] == user)) and checked == '1':
                have_msg = True
                previously_list(data)
    return have_msg


def history_messages(user, to, id_msg):
    have_msg = False
    with open("base_of_messages.bin", 'rb+') as input_messages:
        for line in input_messages:
            data = line.decode().split('\t')
            length = len(data[6])
            if data[6][length - 1] != '\n':
                checked = data[6]
            else:
                checked = data[6][0:(length - 1)]
            if ((data[1] == user and data[2] == to) or (data[1] == to and data[2] == user)) and data[0] == id_msg and checked == '1':
                have_msg = True
                prepared_list(data)
                break
    if not have_msg:
        print("\nNo message with Message-ID {}\n".format(id_msg))


def list_of_messages_deleted(user):
    have_msg = False
    with open("base_of_messages.bin", 'rb+') as input_messages:
        for line in input_messages:
            data = line.decode().split('\t')
            if data[1] == user:
                have_msg = True
                previously_list(data)
    return have_msg


def delete_messages(user, msg_id):
    rewrite = []
    deleted = False
    found = False
    with open("base_of_messages.bin", 'rb+') as input_messages:
        for line in input_messages:
            data = line.decode().split('\t')
            length = len(data[6])
            if data[6][length - 1] != '\n':
                checked = data[6]
            else:
                checked = data[6][0:(length - 1)]
            if data[0] == msg_id and data[1] == user:
                found = True
                if checked == '0':
                    deleted = True
                    print("Message with ID {} was successfully deleted\n".format(msg_id))
                else:
                    mas = [data[i] for i in range(len(data) - 1)]
                    mas.insert(len(mas), checked)
                    rewrite.append(mas)
            else:
                mas = [data[i] for i in range(len(data) - 1)]
                mas.insert(len(mas), checked)
                rewrite.append(mas)
        if deleted:
            input_messages.seek(0)
            input_messages.truncate()
    if deleted:
        rewrite_file(rewrite)
    elif found:
        print("Sorry, but message with Message-ID {} can't be deleted, because it was already viewed\n".format(msg_id))
    else:
        print("Sorry, but there is no message with Message-ID {}\n".format(msg_id))


def auth():
    while True:
        print("Please, enter your username and password.")
        print("Username: ", end="")
        username = input()
        print("Password: ", end="")
        password = input()
        result_of_auth, type_of_user = check_users_auth(username, password)
        if result_of_auth:
            print("\nWelcome, {}. \n".format(username))
            while True:
                print("Please, choose one of the functions:\n")
                print_commands()
                if type_of_user == 'a':
                    print("Add new user\n")
                    print("Create new group\n")
                    print("Add user to group\n")
                print("Exit\n")

                command = input()

                if command.lower() == "exit":
                    print('Close session for {}\n'.format(username))
                    break
                elif (command.lower() == "add new user" or command.lower() == "add") and type_of_user == 'a':
                    print("New username: ", end="")
                    user = input()
                    print("New password: ", end="")
                    passwd = input()
                    space = ' '
                    if space in user:
                        print("Incorrect username, please, try again\n")
                        continue
                    if space in passwd:
                        print("Incorrect password, please, try again\n")
                        continue
                    if check_users(user):
                        from .eds import get_keys
                        pubkey, privkey = get_keys()
                        add_user(user, passwd, 'u', 'None', privkey)
                        add_public_key(user, pubkey)
                    else:
                        print("Sorry, but user with username {} already exists in the user's database".format(user))
                elif (command.lower() == "create new group" or command.lower() == "create") and type_of_user == 'a':
                    print("Name of group: ", end="")
                    name_of_group = input()
                    space = ' '
                    if space in name_of_group:
                        print("Incorrect name of group, please, try again")
                        continue
                    print("Type users that you want add to group {}: ".format(name_of_group), end="")
                    list_of_users = list(input().split())
                    if check_groups(name_of_group):
                        add_group(name_of_group, list_of_users)
                    else:
                        print("Sorry, but group with group_name {} already exists in the group's database".format(name_of_group))
                elif (command.lower() == "add user to group" or command.lower() == "add to group") and type_of_user == 'a':
                    while True:
                        print()
                        if print_users(username):
                            print()
                            print("Choose user: ", end="")
                            user_add = input()
                            print()
                            if print_groups():
                                print()
                                print("Choose group: ", end="")
                                print()
                                group_add = input()
                                add_user_to_group(user_add, group_add)
                                print("Do you want choose another user?\n")
                                answer = input()
                                if answer.lower() == "no":
                                    print()
                                    break
                            else:
                                print("There is no another groups\n")
                                break
                        else:
                            print("There is no another users\n")
                            break
                elif command.lower() == "write message" or command.lower() == "view history of messages" or command.lower() == "write" or command.lower() == "view":
                    print()
                    if not print_users(username):
                        print("There is no another users and groups\n")
                        continue
                    if type_of_user == 'a':
                        print_groups()
                    print()
                    if type_of_user == 'a':
                        print("Choose user or group of users: ", end="")
                    else:
                        print("Choose user: ", end="")
                    to = input()
                    if check_users_groups(to, type_of_user):
                        if command.lower() == "write message" or command.lower() == "write":
                            if not check_users(to):
                                type_of_message = 'u'
                            else:
                                type_of_message = 'g'
                            while True:
                                print("Type new message: ", end="")
                                message = input()
                                print()
                                from time import strftime
                                date = strftime("%d.%m.%Y")
                                time = strftime("%X")
                                if type_of_message == 'u':
                                    write_msg_to_user(username, to, message, date, time)
                                else:
                                    write_msg_to_group(username, to, message, date, time)
                                print("The message was successfully sent\n")
                                print("Do you want write another message?\n")
                                answer = input()
                                if answer.lower() == "no":
                                    print()
                                    break
                                else:
                                    print()
                                    if not print_users(username):
                                        print("There is no another users and groups\n")
                                        continue
                                    if type_of_user == 'a':
                                        print_groups()
                                    print()
                                    if type_of_user == 'a':
                                        print("Choose user or group of users: ", end="")
                                    else:
                                        print("Choose user: ", end="")
                                    to = input()
                        else:
                            while True:
                                while True:
                                    if list_of_messages(username, to):
                                        print("\nChoose Message-ID to view: ", end="")
                                        id_msg = input()
                                        history_messages(username, to, id_msg)
                                        print("Do you want to choose another message?\n")
                                        answer = input()
                                        if answer.lower() == "no":
                                            print()
                                            break
                                    else:
                                        print("\nNo messages with {}\n".format(to))
                                        break
                                print("Do you want to choose another user?\n")
                                answer = input()
                                if answer.lower() == "no":
                                    print()
                                    break
                                else:
                                    print()
                                    if not print_users(username):
                                        print("There is no another users and groups\n")
                                        continue
                                    if type_of_user == 'a':
                                        print_groups()
                                    print()
                                    if type_of_user == 'a':
                                        print("Choose user or group of users: ", end="")
                                    else:
                                        print("Choose user: ", end="")
                                    to = input()

                    else:
                        print("There is now such user or group\n")
                elif command.lower() == "check new messages" or command.lower() == "check":
                    while True:
                        if list_of_senders(username):
                            print("Choose Message-ID to read: ", end="")
                            id_msg = input()
                            new_messages(username, id_msg)
                            print("Do you want choose another Message-ID?\n")
                            answer = input()
                            if answer.lower() == "no":
                                print()
                                break
                        else:
                            print("\nNo new messages for {}\n".format(username))
                            break
                elif command.lower() == "delete messages" or command.lower() == "delete":
                    while True:
                        if list_of_messages_deleted(username):
                            print("Message-ID for deleting: ", end="")
                            msg_id = input()
                            delete_messages(username, msg_id)
                            print("Do you want to choose another message?\n")
                            answer = input()
                            if answer.lower() == "no":
                                print()
                                break
                        else:
                            print("No messages were sent by {}".format(username))
                            break
        else:
            print("Wrong username or password, please, enter again\n")


if __name__ == "__main__":
    check = check_users("admin")
    if check:
        from .eds import get_keys, generate_table
        generate_table()
        pubkey, privkey = get_keys()
        add_user("admin", "admin", 'a', 'admin', privkey)
        add_public_key("admin", pubkey)
        write_msg_id(1)
    print("Welcome to Messenger!\n")
    auth()