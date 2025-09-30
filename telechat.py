"""
Streamlit version of NEURON chat + Telegram bridge
Fixed AES.new() error by explicitly specifying mode (ECB).

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
    # AES requires a key of length 16, 24, or 32 bytes
    key_bytes = secret.encode('utf-8')[:32].ljust(32, b'0')
    cipher = AES.new(key_bytes, AES.MODE_ECB)
    encoded = base64.b64encode(cipher.encrypt(pad(data).encode('utf-8'))).decode('utf-8')
    return encoded

def decrypt(secret: str, data: str) -> str:
    key_bytes = secret.encode('utf-8')[:32].ljust(32, b'0')
    cipher = AES.new(key_bytes, AES.MODE_ECB)
    decoded = cipher.decrypt(base64.b64decode(data)).decode('utf-8').rstrip(PADDING)
    return decoded

# (rest of code unchanged)
