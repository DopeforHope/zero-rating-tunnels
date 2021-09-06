import os.path
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.http import MediaIoBaseDownload, MediaIoBaseUpload
import logging
import threading
import time
import io
from multiprocessing import Queue, Lock
from flask import Flask
from flask import request
from flask import Response
import pickle

# The poller starts with a sleep time of CHANGE_POLLER_SLOW_INTERVAL between each poll request.
# If the poller gets' a succesfull change poll it's switches the sleep time to CHANGE_POLLER_FAST_INTERVAL.
# After CHANGE_POLLER_THROTTLE_CYCLE number of unseccessfull change polls it switches back to
# CHANGE_POLLER_SLOW_INTERVAL sleep time.
# Therefore it the poller polls fast for CHANGE_POLLER_FAST_INTERVAL*CHANGE_POLLER_THROTTLE_CYCLE seconds and is
# doing 1/CHANGE_POLLER_FAST_INTERVAL number of requests per seconds during this time.
#
# The change poller can be started and stopped with the event:
#     change_poller_stop_event
#     change_poller_run_event
#
# If the change poller is stopped and then restarted the counter for the CHANGE_POLLER_THROTTLE_CYCLE resets

# The client usually needs no slow polling
CHANGE_POLLER_FAST_INTERVAL = 0.125
CHANGE_POLLER_SLOW_INTERVAL = 0.125
CHANGE_POLLER_THROTTLE_CYCLE = 10

INCOMING_FOLDER = 'HTTP_Response'
OUTGOING_FOLDER = 'HTTP_Request'

# If the not run in parralel mode, the server just processes one request at a time.
# PARALLEL NOT TESTED/SUPPORTED.
PARALLEL = False

# let static files serve from the web and set local static files into nothing
app = Flask('__main__', static_url_path='/ofefqewrwqethewqoihfroiwqhronbwqonbfonhqonbfc')

sender_queue = Queue()
receiver_queue = Queue()
downloader_queue = Queue()
proxy_lock = Lock()


#TODO: payload
def build_text_request(method, url, http_version, request_headers, use_https=False):
    if use_https:
        text_request = "HTTPS_Tunnel\n"
    else:
        text_request = "HTTP_Tunnel\n"

    text_request += "{method} {url} {http_version}\n".format(
        method=method,
        url=url,
        http_version=http_version
    )
    print(request_headers)
    for header_name, header_value in request_headers:
        if use_https:
            if header_name == "Ssl-Terminated" or header_name == "Oldhost":
                continue
            #restore old host
            if header_name == "Host":
                header_value = request_headers['Oldhost']
        text_request += "{header_name}: {header_value}\n".format(
            header_name=header_name,
            header_value=header_value
        )

    return text_request


"""
GET Request
Input to tg: If we receive the GET Request we want to post the whole request as text message.
Therefore we print in the first line the normal Request Line and afterwards the simply the Header. Pretty straight forward
"""
@app.route('/', defaults={'foo': ''})
@app.route('/<path:foo>', methods=['GET', 'PUT', 'POST', 'DELETE', 'CONNECT'])
def proxy(foo):
    if request.method == 'CONNECT':
        return Response("Success")

    print("[Proxy] Incoming Request\n{}".format(request))
    if 'Ssl-Terminated' in request.headers and request.headers['Ssl-Terminated'] == 'True':
        use_https = True

        #rebuild url
        url = request.url.replace("127.0.0.1", request.headers['Oldhost'])

    else:
        use_https = False
        url = request.url


    gdrive_request = build_text_request(request.method, url,
                                        request.environ.get('SERVER_PROTOCOL'), request.headers, use_https=use_https)
    print("[Proxy] GDrive Request:\n{}".format(gdrive_request))

    if request.method == 'GET':

        print("[Proxy] Time: {}".format(time.time()))
        if not PARALLEL: proxy_lock.acquire()
        answer, content = send_and_get_answer(gdrive_request)
        if not PARALLEL: proxy_lock.release()
        print("[Proxy] Got answer")
        print("[Proxy] Time: {}".format(time.time()))


        if answer is None:
            return Response("Error", status=500)

        resp = Response(content, status=answer['status_code'])

        # TODO: blacklist header workaround
        for header_field in answer['header']:
            resp.headers[header_field] = answer['header'][header_field]
        print("[Proxy] Sending answer...")
        print("[Proxy] Time: {}".format(time.time()))

        return resp

    elif request.method == 'PUT':
        pass
    elif request.method == 'POST':
        pass
    elif request.method == 'DELETE':
        pass


    return "Success"


def send_and_get_answer(message):
    print("[Send and get answer] Putting message into queue")
    sender_queue.put(message)

    meta, content = receiver_queue.get()
    print("[Send and get answer] Returning:\nMeta:\n{}\nContent:\n{}".format(meta, content))
    print("[Send and get answer] Time: {}".format(time.time()))
    return meta, content


def sender():
    # see thread safety, each thread needs their own service
    gdrive_service = authenticate_and_build_service()
    while True:
        # TODO: adjust for desired behaviour
        print("[Sender] Sender waiting for queue input")
        http_request = sender_queue.get()

        if not PARALLEL:
            print("[Sender] NOT PARRALEL: Starting change poller...")
            change_poller_run_event.set()

        file_metadata = {'name': 'request' + str(int(time.time())), 'parents': [outgoing_folder_id]}

        fh_upload = io.BytesIO()
        fh_upload.write(http_request.encode('utf-8'))

        # just use 'application/octet-stream' as the mime type. Google doesn't need to know the mime type...
        media = MediaIoBaseUpload(fh_upload, 'application/octet-stream')

        print("[Sender] Starting upload file...")
        print("[Sender] Time: {}".format(time.time()))

        uploadfile = gdrive_service.files().create(body=file_metadata, media_body=media).execute()

        print("[Sender] Upload file response:".format(uploadfile))
        print("[Sender] Time: {}".format(time.time()))

        fh_upload.close()

def change_poller():
    # see thread safety, each thread needs their own service
    gdrive_service = authenticate_and_build_service()
    # TODO: test or change to APScheduler for python?
    global change_poller_run_event
    global change_poller_stop_event

    throttled = True

    if change_poller_stop_event.is_set():
        change_poller_stop_event.clear()

        print("[Change Poller] Stopped before first start...")

        change_poller_run_event.wait()
        change_poller_run_event.clear()

        print("[Change Poller] Started first time...")

    print("[Change Poller] Getting Start Page Token for changes")
    response = gdrive_service.changes().getStartPageToken().execute()
    print("[Change Poller] Start Page token response: {}".format(response))

    saved_start_page_token = response.get('startPageToken')

    fast_cycles = 0

    while True:
        change_poller_run_event.clear()

        page_token= saved_start_page_token
        while page_token is not None:
            print("[Change Poller] Polling for changes...")
            # start_time = time.time()
            response = gdrive_service.changes().list(pageToken=page_token,
                                                     pageSize=1000,
                                                     spaces='drive').execute()
            # print("Execution time for change request: {}".format(start_time-time.time()))
            print("[Change Poller] Change list response:\n{}".format(response))
            for change in response.get('changes'):
                # Process change
                file_id = change.get('fileId')

                if change['file']['name'].startswith('response'):
                    print('[Change Poller] Change found for file {} -> putting into downloade queue'.format(file_id))
                    print("[Change Poller] Time: {}".format(time.time()))
                    downloader_queue.put(file_id)

                    # if the change poller is throttled, unthrottle it
                    fast_cycles = 0
                    if throttled:
                        print('[Change Polller] Unthrottling due to found change')
                        throttled = False
                else:
                    print('[Change Polller] Ignoring unrelevant file {}'.format(change['file']['name']))

            if 'newStartPageToken' in response:
                # Last page, save this token for the next polling interval
                print("[Change Poller] No changes left -> adjusting start page token")
                saved_start_page_token = response.get('newStartPageToken')
            page_token = response.get('nextPageToken')

        if throttled:
            sleep_time = CHANGE_POLLER_SLOW_INTERVAL
        else:
            sleep_time = CHANGE_POLLER_FAST_INTERVAL
        print("[Change Poller] Sleeping for {} seconds...".format(sleep_time))
        time.sleep(sleep_time)

        if not throttled:
            fast_cycles += 1
            # if the maximum number of fast cycles is reached throttle the poller
            if fast_cycles == CHANGE_POLLER_THROTTLE_CYCLE:
                throttled = True

                print("[Change Poller] Throttling!")

        if change_poller_stop_event.is_set():
            change_poller_stop_event.clear()

            print("[Change Poller] Stopped...")

            change_poller_run_event.wait()
            change_poller_run_event.clear()
            throttled = False

            print("[Change Poller] Restarted...")


def downloader():
    # see thread safety, each thread needs their own service
    gdrive_service = authenticate_and_build_service()
    while True:
        print("[Downloader] Downloader waiting for queue input")
        downloadfile_id = downloader_queue.get()
        print("[Downloader] Received queue input")
        print("[Downloader] Time: {}".format(time.time()))

        if not PARALLEL:
            print("[Downloader] NOT PARRALEL: Stopping change poller...")
            change_poller_stop_event.set()

        print("[Download] Download file with the ID: {}".format(downloadfile_id))
        # TODO: abuse check only when the file is flagged as potential abuse, nevertheless unlikely
        request = gdrive_service.files().get_media(fileId=downloadfile_id)
        fh = io.BytesIO()
        # TODO: download type
        print("[Downloader] Time: {}".format(time.time()))
        media_downloader = MediaIoBaseDownload(fh, request)
        done = False
        while done is False:
            status, done = media_downloader.next_chunk()
            print("Download {}".format(int(status.progress() * 100)))

        print("[Downloader] Time: {}".format(time.time()))
        print("[Downloader] Downloaded data with the length of {} bytes".format(fh.getbuffer().nbytes))

        """
        FORMAT of the response:
        First line is a number which indicates how many of the following lines are a part of the HTTP answer header
        Then the specified amount of header lines follows
        After the a last line break occurs and then the payload follows

        Example:
        3
        HTTP/1.1 OK
        Content-Length: ...
        X-Powered-By: PHP/5.3.1
        [Payload]
        """

        print("[Downloader] Parsing response...")
        print("[Downloader] Time: {}".format(time.time()))

        # Set the stream position back to the beginning for reading
        fh.seek(0)

        # parse the first number as the number of header lines to be read
        nr_of_headerlines = int(fh.readline().strip())

        answer = {}
        header = {}
        for i in range(nr_of_headerlines):
            #first line is the HTTP response line
            cur_line = fh.readline().strip().decode('UTF-8')
            if i == 0:
                answer['status_code'] = cur_line.split(" ")[1]
                answer['status_message'] = cur_line.split(" ")[2]
            else:
                if cur_line != "":
                    header_name, header_value = cur_line.split(": ", 1)
                    header[header_name] = header_value

        answer['header'] = header
        # TODO: cookies

        content = fh.read()

        print("[Downloader] Time: {}".format(time.time()))
        #print("[Downloader] Putting response with the following values into queue:\nAnswer:\n{}\nContent:\n{}".format(answer, content))

        print("[Downloader] Time: {}".format(time.time()))
        receiver_queue.put((answer, content))
        fh.close()

def authenticate_and_build_service():
    # If modifying these scopes, delete the file server_token.pickle.
    scopes = ['https://www.googleapis.com/auth/drive']

    creds = None
    # The file server_token.pickle stores the user's access and refresh tokens, and is
    # created automatically when the authorization flow completes for the first
    # time.
    if os.path.exists('server_token.pickle'):
        with open('server_token.pickle', 'rb') as token:
            creds = pickle.load(token)
    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'server_credentials.json', scopes)
            creds = flow.run_local_server(port=0)
        # Save the credentials for the next run
        with open('server_token.pickle', 'wb') as token:
            pickle.dump(creds, token)

    return build('drive', 'v3', credentials=creds)


if __name__ == '__main__':

    print("[Main] Starting authentication")
    service = authenticate_and_build_service()
    print("[Main] Authenticated")

    """
    Get folder ids
    """
    print("[Main] Gettings the 100 first root files and folders")
    results = service.files().list(
        pageSize=1000, fields="nextPageToken, files(id, name)").execute()
    items = results.get('files', [])

    print("[Main] Retrieved Files:\n{}".format(items))

    print("[Main]  Searching for outgoing folder({}) and incoming folder({})".format(OUTGOING_FOLDER, INCOMING_FOLDER))

    outgoing_folder_id = None
    incoming_folder_id = None

    for cur_item in items:
        if cur_item['name'] == OUTGOING_FOLDER:
            outgoing_folder_id = cur_item['id']
        elif cur_item['name'] == INCOMING_FOLDER:
            incoming_folder_id = cur_item['id']
        if (outgoing_folder_id is not None) and (incoming_folder_id is not None):
            break

    if outgoing_folder_id is None:
        raise Exception("[Main] Outgoing folder not found")
    if incoming_folder_id is None:
        raise Exception("[Main] Incoming folder not found")

    print("[Main] Ids found:\nOutgoing folder: {}\nIncoming folder: {}".format(outgoing_folder_id, incoming_folder_id))

    change_poller_stop_event = threading.Event()
    change_poller_run_event = threading.Event()

    change_poll_worker = threading.Thread(target=change_poller, args=())
    change_poll_worker.setDaemon(True)
    # dont let the poller automatically start
    change_poller_stop_event.set()
    change_poll_worker.start()

    change_poll_worker = threading.Thread(target=downloader, args=())
    change_poll_worker.setDaemon(True)
    change_poll_worker.start()

    change_poll_worker = threading.Thread(target=sender, args=())
    change_poll_worker.setDaemon(True)
    change_poll_worker.start()


    app.run(port=42069, debug=True, use_reloader=False)
