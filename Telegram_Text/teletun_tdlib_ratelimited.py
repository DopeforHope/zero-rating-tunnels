#!/usr/bin/env python3
from pytun import TunTapDevice
import base64
from telegram.client import Telegram
import sys
import logging
import time
import threading
import datetime

# CONFIGURATION VARIABLES
SECRET_CHAT = True
CLIENT_ID = 1241064075
SERVER_ID = 1178350582
DEBUG = True


def setup_logging(level=logging.INFO):
    root = logging.getLogger()
    root.setLevel(level)
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(name)s: %(message)s')
    ch.setFormatter(formatter)
    root.addHandler(ch)


#--- Setup Phase ---#
setup_logging(level=logging.INFO)
print('Logger configured')


# Login depending on being server or client
if '--server' in sys.argv:
    RECEIVER_ID = SERVER_ID

    ### TODO: insert your API credentials here and change the DB encryption key
    tg = Telegram(
        api_id=1234567,
        api_hash='cafebabe',
        phone='+491567891011',
        database_encryption_key='ChangeMe',
        # TODO: Adjust the path to the libtdjson file
        library_path="./libtdjson.so.1.5.4",
        # TODO: Adjust to your preference
        use_secret_chats=True
    )
else:
    RECEIVER_ID = CLIENT_ID
    ### TODO: insert your API credentials here and change the DB encryption key
    tg = Telegram(
        api_id=1234567,
        api_hash='cafebabe',
        phone='+491567891011',
        database_encryption_key='ChangeMe',
        # TODO: Adjust the path to the libtdjson file
        library_path="./libtdjson.so.1.5.4",
        # TODO: Adjust to your preference
        use_secret_chats=True
    )

tg.login()


result = tg.call_method("getContacts")
result.wait()
print(result.update)

print("Getting chats...")
result = tg.call_method("getChats", params={'offset_order': 2 ** 63 - 1,
                                            'offset_chat_id': 0, 'limit': 100})
result.wait()
if result.update is None:
    raise Exception("Result is None")
if DEBUG: print(result.update)

# if we are the server we set the online status
if '--server' in sys.argv:
    # Set online status
    data = {
        '@type': 'setOption',
        'name': 'online',
        'value': {
            '@type': 'optionValueBoolean',
            'value': True,
        },
    }

    tg._send_data(data)


# if we are the client we have to establish the secret chat
if not ('--server' in sys.argv):
    if SECRET_CHAT:
        waiting_for_secret_chat = threading.Event()
        waiting_for_secret_chat_id = threading.Event()

        # this function will be called for every secret chat message
        def update_handler(update):
            print('New Secret Chat message!')
            print(update)

            # wait for the main function to get the secret chat id the first time
            global waiting_for_secret_chat_id
            if not waiting_for_secret_chat_id.is_set():
                waiting_for_secret_chat_id.wait()

            global secret_chat_id

            # check if the secret chat is the wanted one
            if update['secret_chat']['user_id'] == RECEIVER_ID and update['secret_chat']['id'] == secret_chat_id:
                if update['secret_chat']['state']['@type'] == 'secretChatStatePending':
                    print("Secret Chat Pending...")
                if update['secret_chat']['state']['@type'] == 'secretChatStateReady':
                    print("Secret Chat Ready!")
                    global waiting_for_secret_chat
                    waiting_for_secret_chat.set()

        # add handler
        tg.add_update_handler("updateSecretChat", update_handler)

        result = tg.call_method("createNewSecretChat", params={"user_id": RECEIVER_ID})
        result.wait()
        print(result.update)

        waiting_for_secret_chat_id.set()

        secret_chat_id = result.update['type']['secret_chat_id']
        print(secret_chat_id)
        chat_id = result.update['id']

        # wait until the secret chat is established
        waiting_for_secret_chat.wait()

        print("Secret Chat establishing Phase finished")
    else:
        chat_id = RECEIVER_ID
else:
    chat_id = "unknown"

# Create TUN device for network capture and injections
tun = TunTapDevice(name='teletun-device')

print(tun.name + ' has been created, information follows:')


# Set IP address based on --server flag
if '--server' in sys.argv:
    tun.addr = '10.8.0.1'
    tun.dstaddr = '10.8.0.2'
else:
    tun.addr = '10.8.0.2'
    tun.dstaddr = '10.8.0.1'

tun.netmask = '255.255.255.0'
tun.mtu = 1500

print('Address: ' + tun.addr)
print('Dest.-Address: ' + tun.dstaddr)
print('Netmask: ' + tun.netmask)
print('MTU: ' + str(tun.mtu))


# Start TUN device
tun.up()
up = True


# Init stats
sent = 0
received = 0


# this function will be called
# for each received message
def message_handler(update):
    if update['message']['date'] < handler_start_time:
        print('Discarding old message')
    elif update['message']['is_outgoing']:
        print("Discarding own message")
    elif update['message']['sender_user_id'] != RECEIVER_ID:
        print('Discarding message from unknown sender')
    else:
        print('New message!')
        print(update)

        # update chat ID if not known or new - the case when you receive the first msg of a new chat as a server
        current_chat_id = update['message']['chat_id']
        global chat_id
        if chat_id != current_chat_id:
            if chat_id == 'unknown':
                chat_id = current_chat_id
                wait_for_chat_id.set()
            else:
                chat_id = update['message']['sender_user_id']

        # check if its' normal text:
        if update['message']['content']['@type'] == 'messageText':
            text = update['message']['content']['text']['text']
            print("Receiver message with the following text: {}".format(text))
            # Decode data and write it to the tunnel
            recv_data = base64.b64decode(text)
            tun.write(recv_data)


if '--server' in sys.argv:
    wait_for_chat_id = threading.Event()

# start the message handler
handler_start_time = time.time()
tg.add_message_handler(message_handler)

# wait until first msg comes in otherwise the server doesnt know where to reply
if '--server' in sys.argv:
    print('Waiting for chat...')
    if not wait_for_chat_id.is_set():
        wait_for_chat_id.wait()
    print('Chat established')



#--- start the sending of data with a rate limiter ---#

maximum_per_interval = 49
interval_in_seconds = 15
maximum_per_hour = 2100

nr_of_msg_per_hour = 0
nr_of_msg = 0
start_time = datetime.datetime.now()
hour_start_time = datetime.datetime.now()
hour_threshold_reached = False

unblocker = False
while True:
    interval_start_time = datetime.datetime.now()

    if (datetime.datetime.now()-interval_start_time).seconds >= 60:
        minute_start_time = datetime.datetime.now()

    under_maximum = False
    print("Interval start time ", interval_start_time)
    for i in range(maximum_per_interval):
        if nr_of_msg_per_hour == maximum_per_hour:
            hour_threshold_reached = True
            break
        print("Execution nr. ", i)
        time_difference = datetime.datetime.now() - interval_start_time

        # if we haven't reached the maximum reset the timer
        if time_difference.seconds-1 >= interval_in_seconds:
            print("Slower than the interval -> reset timer")
            under_maximum = True
            break
        buf = tun.read(tun.mtu)
        send_data = base64.b64encode(buf)
        result = tg.send_message(chat_id, send_data.decode('utf-8'))
        result.wait()
        if DEBUG:
            print(result.update)
        if result is None:
            raise Exception("Result of senden message was None")

        nr_of_msg += 1
        nr_of_msg_per_hour += 1


    if hour_threshold_reached:
        print("Maximum messages per Hour reached")
        hour_time_difference = datetime.datetime.now() - hour_start_time

        #one hour has 3600 seconds
        hour_sleep_seconds = 3600 - hour_time_difference.seconds
        print("Sleeping for {} Minutes and {} Seconds ...".format(
            hour_sleep_seconds/60, hour_sleep_seconds % 60))
        time.sleep(hour_sleep_seconds)
        hour_start_time = datetime.datetime.now()
        hour_threshold_reached = False
        nr_of_msg_per_hour = 0
        continue
    if not under_maximum:
        print("\tMaximum executions reached")
        interval_sleep_time = max(0, (interval_in_seconds - (datetime.datetime.now() - interval_start_time).seconds))
        print("\tSleep time for interval reset: ", interval_sleep_time)
        time.sleep(interval_sleep_time)
    else:
        under_maximum = False
    #TODO: check when unblocked again
    #if unblocker:
    #    break
