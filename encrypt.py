"""
In theory, the maximum length of the encrypted token is the number of pixel of
the image.

How it works?

1. Create a random salt of length 256.
2. Encrypt the secret message with salted password using AES method.
3. Embedding the encrypted token into an image:
    1. Define the password to be the seed, k = 1.
    2. To determine the $k$th random position, use SHA-512 to hash the seed
        into a number, $n$ in $Z_(W*H)$. If the n has already exists, go to step 4.
    3. Place the first encrypted token in the position $n$.
    4. Append the seed with the $k - 1$th character of itself. Repeat step 2.
        (Note 0th character means we append no character)
    5. k += 1.
"""

import base64
import os
import numpy as np
import hashlib
import cv2
import argparse
import utils
import constant

from PIL import Image
from getpass import getpass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from constant import LEN_SALT, IMG_WIDTH, IMG_HEIGHT


def encrypt(password, secret_message):
    salt = os.urandom(LEN_SALT)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    f = Fernet(key)
    token = f.encrypt(secret_message)
    return salt, token


def embedding(password, salt, token):
    width, height = IMG_WIDTH, IMG_HEIGHT

    # Get the mode of the image
    mode = "RGB"

    # Get the number of channels
    num_channels = 3
    if mode == "L":
        num_channels = 1
    elif mode == "RGB":
        num_channels = 3
    elif mode == "RGBA":
        num_channels = 4

    # Create a writeable copy of the pixel data
    pixel_array = np.array(np.random.rand(height, width, num_channels) * 255, dtype=np.uint8)
    position_array = np.array(np.ones((height, width, num_channels)) * 255, dtype=np.uint8)

    # Structure of encoded string
    len_token = len(token)
    len_encrypted_str = len(salt) + constant.LEN_NUM_DUPLICATION_BYTES + constant.LEN_INT_BYTES + len_token
    #len_encrypted_str = len(encrypted_str)

    #ba = b''.join([password, salt])
    ba = password
    random_position, num_duplication = utils.get_random_position(ba, len_encrypted_str, width, height)
    encrypted_str = salt + num_duplication.to_bytes(4, 'little') + len_token.to_bytes(4, 'little') + token

    # Assign the pixel (y, x) to a new value
    for i, rand_pos in enumerate(random_position):
        y, x, channel = utils.transform_to_pixel_position(rand_pos, IMG_HEIGHT, IMG_WIDTH)
        pixel_array[y][x][channel] = encrypted_str[i]
        if constant.DEBUG:
            cv2.circle(position_array, (y, x), 50, (255, 0, 0), 10)

    image = Image.fromarray(np.uint8(pixel_array))
    if constant.DEBUG:
        position = Image.fromarray(np.uint8(position_array))
        print(f'Output image size: {height} x {width}')
        print(f'Length of encrypted string: {len(encrypted_str)}')

    return image, position


def encrypt_message(password, secret_message):
    salt, token = encrypt(password, secret_message)
    image, position = embedding(password, salt, token)

    if constant.DEBUG:
        print(f'Salt: {salt}')
        print(f'Token: {token}')

    return image, position


def encrypt_file(password, filepath):
    assert os.path.exists(filepath), f'{filepath} not exists.'

    with open(filepath) as fp:
        data = fp.read().encode('utf-8')

    salt, token = encrypt(password, data)
    image, position = embedding(password, salt, token)
    return image, position


if __name__=='__main__':
    parser = argparse.ArgumentParser('Embedded message to a white noise image.')
    parser.add_argument('--filepath', type=str, help='Target file path', default=None)
    #parser.add_argument('--input', type=str, help='Path of image to be embedded', default=None)
    parser.add_argument('--output', type=str, help='Path of embedded image.', default='embed.png')
    args = parser.parse_args()

    output_path = args.output

    password = getpass('Password: ')
    confirmed_password = getpass('Confirm password: ')
    assert password == confirmed_password, 'Password not matched.'
    password = password.encode('utf-8')
    if args.filepath:
        print('Encrypting...')
        image, position = encrypt_file(password, args.filepath)
    else:
        secret_message = input('Secret message: ').encode('utf-8')
        print('Encrypting...')
        image, position = encrypt_message(password, secret_message)
    print(f'Saving image to {output_path}.')
    image.save(output_path)
    position.save('position.png')
    print('Done')

