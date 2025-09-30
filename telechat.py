"""
Streamlit version of NEURON chat + Telegram bridge
- Single-file Streamlit app that starts a TCP chat server (based on the original neuron_server)
  and a Telegram bot that bridges messages between a configured Telegram chat and the TCP clients.

Run:
streamlit run neuron_streamlit.py

"""

import streamlit as st
import threading
import socket
import select
import base64
import hashlib
import time
import queue
from Crypto.Cipher import AES

try:
    from telegram import Bot, Update
    from telegram.ext import Updater, MessageHandler, Filters, CallbackContext
    TELEGRAM_AVAILABLE = True
except Exception:
    TELEGRAM_AVAILABLE = False

BLOCK_SIZE = 32
PADDING = '{'

def pad(s: str) -> str:
    return s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING

def hasher(key: str) -> str:
    h = hashlib.sha512(key.encode('utf-8')).hexdigest()
    return hashlib.md5(h.encode('utf-8')).hexdigest()

def encrypt(secret: str, data: str) -> str:
    cipher = AES.new(secret.encode('utf-8'))
    encoded = base64.b64encode(cipher.encrypt(pad(data).encode('utf-8'))).decode('utf-8')
    return encoded

def decrypt(secret: str, data: str) -> str:
    cipher = AES.new(secret.encode('utf-8'))
    decoded = cipher.decrypt(base64.b64decode(data)).decode('utf-8').rstrip(PADDING)
    return decoded

class NeuronServer(threading.Thread):
    def __init__(self, host, port, password, view, log_queue, stop_event):
        super(NeuronServer, self).__init__(daemon=True)
        self.host = host
        self.port = port
        self.password = password
        self.view = view
        self.logq = log_queue
        self.stop_event = stop_event
        self.socket_list = []
        self.recv_buffer = 4096
        self.key = hasher(password)
        self.telegram_send_hook = None

    def log(self, msg):
        self.logq.put(msg)

    def broadcast(self, server_socket, sock, message_plain):
        enc = encrypt(self.key, message_plain)
        for s in list(self.socket_list):
            if s != server_socket and s != sock:
                try:
                    s.send(enc.encode('utf-8'))
                except Exception:
                    try:
                        s.close()
                    except:
                        pass
                    if s in self.socket_list:
                        self.socket_list.remove(s)

    def run(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server_socket.bind((self.host, self.port))
            server_socket.listen(10)
        except Exception as e:
            self.log(f"[error] Failed to bind/listen: {e}")
            return

        self.socket_list.append(server_socket)
        self.log(f"[info] neuron server started on {self.host}:{self.port}")

        while not self.stop_event.is_set():
            try:
                ready_to_read, _, _ = select.select(self.socket_list, [], [], 0.5)
            except Exception:
                break

            for sock in ready_to_read:
                if sock == server_socket:
                    try:
                        sockfd, addr = server_socket.accept()
                        self.socket_list.append(sockfd)
                        self.log(f"[conn] user {addr} connected")
                        self.broadcast(server_socket, sockfd, f"[{addr[0]}:{addr[1]}] entered our chatting room\n")
                    except Exception as e:
                        self.log(f"[error] accept: {e}")
                else:
                    try:
                        data = sock.recv(self.recv_buffer)
                        if not data:
                            if sock in self.socket_list:
                                self.socket_list.remove(sock)
                            self.log(f"[conn] client disconnected")
                            continue

                        try:
                            plaintext = decrypt(self.key, data.decode('utf-8'))
                        except Exception as e:
                            self.log(f"[error] decrypt failed: {e}")
                            continue

                        self.broadcast(server_socket, sock, '\r' + plaintext)
                        if self.view == '1':
                            self.log(plaintext)

                        if self.telegram_send_hook:
                            try:
                                self.telegram_send_hook(plaintext)
                            except Exception as e:
                                self.log(f"[tg] telegram hook failed: {e}")

                    except Exception as e:
                        self.log(f"[error] socket read: {e}")
                        try:
                            if sock in self.socket_list:
                                self.socket_list.remove(sock)
                        except:
                            pass

        for s in self.socket_list:
            try:
                s.close()
            except:
                pass
        self.socket_list = []
        server_socket.close()
        self.log("[info] server stopped")

class TelegramBridge(threading.Thread):
    def __init__(self, token, chat_id, send_to_server_fn, log_queue, stop_event):
        super(TelegramBridge, self).__init__(daemon=True)
        self.token = token
        self.chat_id = chat_id
        self.send_to_server = send_to_server_fn
        self.logq = log_queue
        self.stop_event = stop_event
        self.updater = None

    def log(self, msg):
        self.logq.put(msg)

    def start_bot(self):
        if not TELEGRAM_AVAILABLE:
            self.log('[tg] python-telegram-bot not installed. Telegram bridge disabled.')
            return

        try:
            self.updater = Updater(self.token, use_context=True)

            def handler(update: Update, context: CallbackContext):
                text = update.message.text or ''
                user = update.effective_user
                display = f"[TG:{user.username or user.id}] {text}"
                self.log(f"[tg] received: {display}")
                if self.send_to_server:
                    try:
                        self.send_to_server(display)
                    except Exception as e:
                        self.log(f"[tg] failed sending to server: {e}")

            self.updater.dispatcher.add_handler(MessageHandler(Filters.text & ~Filters.command, handler))
            self.updater.start_polling()
            self.log('[tg] bot started (polling)')
        except Exception as e:
            self.log(f"[tg] bot start failed: {e}")

    def stop_bot(self):
        try:
            if self.updater:
                self.updater.stop()
                self.log('[tg] bot stopped')
        except Exception as e:
            self.log(f"[tg] stop error: {e}")

    def run(self):
        self.start_bot()
        while not self.stop_event.is_set():
            time.sleep(0.5)
        self.stop_bot()

st.set_page_config(page_title="NEURON Streamlit Bridge", layout="wide")
st.title("NEURON Chat — Streamlit + Telegram bridge")

st.sidebar.header("Server configuration")
HOST = st.sidebar.text_input('HOST', value='0.0.0.0')
PORT = st.sidebar.number_input('PORT', value=9999, min_value=1, max_value=65535)
PASSWORD = st.sidebar.text_input('PASSWORD', type='password', value='secret')
VIEW = st.sidebar.selectbox('VIEW (log incoming plaintext?)', ['0', '1'])

st.sidebar.header("Telegram bridge")
TELEGRAM_TOKEN = "8204477990:AAE2icqYhk4dQVqNMl33f-A4giPkV2nMZyQ"
TELEGRAM_CHAT_ID = "7617373689"

col1, col2 = st.columns([1,3])

if 'server_thread' not in st.session_state:
    st.session_state.server_thread = None
if 'tg_thread' not in st.session_state:
    st.session_state.tg_thread = None
if 'server_stop' not in st.session_state:
    st.session_state.server_stop = threading.Event()
if 'tg_stop' not in st.session_state:
    st.session_state.tg_stop = threading.Event()
if 'log_queue' not in st.session_state:
    st.session_state.log_queue = queue.Queue()

log_placeholder = st.empty()

def append_log_from_queue():
    logs = []
    while not st.session_state.log_queue.empty():
        logs.append(st.session_state.log_queue.get_nowait())
    if logs:
        prev = st.session_state.get('log_text', '')
        new = prev + '\n'.join(logs) + '\n'
        st.session_state['log_text'] = new
        log_placeholder.code(new)

with col1:
    st.header('Controls')
    start_server = st.button('Start Server')
    stop_server = st.button('Stop Server')
    start_tg = st.button('Start Telegram Bridge')
    stop_tg = st.button('Stop Telegram Bridge')

    append_log_from_queue()

    if start_server:
        if st.session_state.server_thread and st.session_state.server_thread.is_alive():
            st.session_state.log_queue.put('[info] server already running')
        else:
            st.session_state.server_stop.clear()
            srv = NeuronServer(HOST, int(PORT), PASSWORD, VIEW, st.session_state.log_queue, st.session_state.server_stop)

            def send_to_clients(msg_plain):
                srv.broadcast(None, None, msg_plain)
            srv.telegram_send_hook = None

            srv.start()
            st.session_state.server_thread = srv
            st.session_state.log_queue.put(f'[info] server thread started on {HOST}:{PORT}')

    if stop_server:
        if st.session_state.server_thread:
            st.session_state.server_stop.set()
            st.session_state.server_thread = None
            st.session_state.log_queue.put('[info] server stop signaled')
        else:
            st.session_state.log_queue.put('[info] server not running')

    if start_tg:
        if not TELEGRAM_TOKEN:
            st.session_state.log_queue.put('[tg] no token provided, cannot start')
        elif not TELEGRAM_AVAILABLE:
            st.session_state.log_queue.put('[tg] python-telegram-bot not available in environment')
        else:
            st.session_state.tg_stop.clear()
            def send_to_server_fn(msg):
                if st.session_state.server_thread:
                    st.session_state.server_thread.broadcast(None, None, msg)
                else:
                    st.session_state.log_queue.put('[tg] server not running, cannot forward to clients')

            tg = TelegramBridge(TELEGRAM_TOKEN, TELEGRAM_CHAT_ID, send_to_server_fn, st.session_state.log_queue, st.session_state.tg_stop)

            def server_to_telegram(plaintext):
                try:
                    bot = Bot(token=TELEGRAM_TOKEN)
                    bot.send_message(chat_id=int(TELEGRAM_CHAT_ID), text=plaintext)
                    st.session_state.log_queue.put('[tg] forwarded message from server to telegram')
                except Exception as e:
                    st.session_state.log_queue.put(f'[tg] forward failed: {e}')

            if st.session_state.server_thread:
                st.session_state.server_thread.telegram_send_hook = server_to_telegram

            tg.start()
            st.session_state.tg_thread = tg
            st.session_state.log_queue.put('[tg] telegram bridge started')

    if stop_tg:
        if st.session_state.tg_thread:
            st.session_state.tg_stop.set()
            st.session_state.tg_thread = None
            st.session_state.log_queue.put('[tg] telegram stop signaled')
        else:
            st.session_state.log_queue.put('[tg] telegram bridge not running')

with col2:
    st.header('Quick send (to connected TCP clients and/or Telegram)')
    quick_msg = st.text_area('Message', height=120)
    if st.button('Send message'):
        if quick_msg.strip() == '':
            st.warning('Message is empty')
        else:
            if st.session_state.server_thread:
                st.session_state.server_thread.broadcast(None, None, f"[ServerAdmin] {quick_msg}")
                st.session_state.log_queue.put('[info] message broadcasted to TCP clients')
            else:
                st.session_state.log_queue.put('[info] server not running — not broadcasted')

            if TELEGRAM_TOKEN and TELEGRAM_CHAT_ID:
                if TELEGRAM_AVAILABLE:
                    try:
                        bot = Bot(token=TELEGRAM_TOKEN)
                        bot.send_message(chat_id=int(TELEGRAM_CHAT_ID), text=quick_msg)
                        st.session_state.log_queue.put('[tg] message sent to telegram chat')
                    except Exception as e:
                        st.session_state.log_queue.put(f'[tg] failed to send message: {e}')
                else:
                    st.session_state.log_queue.put('[tg] python-telegram-bot not available')

    append_log_from_queue()

if st.button('Refresh logs'):
    append_log_from_queue()

st.markdown('---')
st.caption('This app bridges TCP clients and Telegram chat. TCP clients use neuron_client to connect to HOST:PORT with the same password. Telegram messages will be relayed both ways.')

append_log_from_queue()
