import argparse
import base64
import os
import hashlib
import numpy as np

import utils
import constant

from PIL import Image
from getpass import getpass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from constant import LEN_SALT, IMG_WIDTH, IMG_HEIGHT


def decrypt(password, salt, token):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    f = Fernet(key)
    data = f.decrypt(token)
    return data


def hack_random_position(length):
    N = IMG_WIDTH * IMG_HEIGHT

    return np.random.choice(N, length, replace=False)


def unembedding(password, image_path):
    """
    TODO: take the password as input, so that the position of the salt and token is derived from password
    """
    im = Image.open(image_path)
    width, height = im.size
    mode = im.mode

    print(f'Input image size: {height} x {width}')

    # Get the number of channels
    num_channels = 3
    if mode == "L":
        num_channels = 1
    elif mode == "RGB":
        num_channels = 3
    elif mode == "RGBA":
        num_channels = 4

    # Create a writeable copy of the pixel data
    pixel_array = np.asarray(im)

    len_salt_and_int_bytes = constant.LEN_SALT + constant.LEN_NUM_DUPLICATION_BYTES + constant.LEN_INT_BYTES
    #random_position = hack_random_position(len_encrypted_str)
    random_position, _ = utils.get_random_position(password, len_salt_and_int_bytes, width, height)

    # Read salt
    print(f'Reading salt.')
    encrypted_str = ''
    for rand_pos in random_position[:LEN_SALT]:
        y, x, channel = utils.transform_to_pixel_position(rand_pos, height, width)
        encrypted_char = chr(pixel_array[y][x][channel])
        encrypted_str += encrypted_char
    salt = encrypted_str.encode('latin1')

    # TODO: To be removed. If the password is incorrect, the length of token may be decrypted
    # to a wrong number. There is a high chance that this number is a very
    # large number. To avoid trying to decrypt a long token that is obviously
    # wrong, given the number of random position duplication during encryption,
    # if the number of duplication in decryption is exceed this number, we
    # stop generating the random number generator and decrypt the truncated
    # token.
    # Read number of duplication
    print(f'Reading number of duplication.')
    encrypted_str = ''
    ba = bytearray()
    for rand_pos in random_position[LEN_SALT:LEN_SALT +
            constant.LEN_NUM_DUPLICATION_BYTES]:
        y, x, channel = utils.transform_to_pixel_position(rand_pos, height, width)
        ba.append(pixel_array[y][x][channel])
    num_duplication = constant.MAX_NUM_DUPLICATION #int.from_bytes(ba, 'little')
    print(f'Number of duplication: {num_duplication}')

    # Read length of token
    print(f'Reading length of token.')
    encrypted_str = ''
    ba = bytearray()
    for rand_pos in random_position[LEN_SALT + constant.LEN_NUM_DUPLICATION_BYTES:]:
        y, x, channel = utils.transform_to_pixel_position(rand_pos, height, width)
        ba.append(pixel_array[y][x][channel])
    len_token_bytes = int.from_bytes(ba, 'little')

    len_encrypted_str = len_salt_and_int_bytes + len_token_bytes
    print(f'Reading length of encrypted string.', len_salt_and_int_bytes, len_token_bytes)
    random_position, _ = utils.get_random_position(password, len_encrypted_str,
            width, height, num_duplication)

    # Read token
    print(f'Reading token.')
    encrypted_str = ''
    for rand_pos in random_position[LEN_SALT + constant.LEN_INT_BYTES:]:
        y, x, channel = utils.transform_to_pixel_position(rand_pos, height, width)
        encrypted_char = chr(pixel_array[y][x][channel])
        encrypted_str += encrypted_char

    token = encrypted_str.encode('utf-8')

    return salt, token


def main(image_path):
    password = getpass('Password: ')
    password = password.encode('utf-8')
    data = None

    try:
        salt, token = unembedding(password, image_path)
        print(f'Reading salt: {salt}')
        print(f'Reading token: {token}')
        print('Start decryption.')
        data = decrypt(password=password, salt=salt, token=token)
    except Exception as e:
        print(e)
        print(f'Exception caught: {e}')

    print('Done.')
    print('Data:')
    print(data.decode('utf-8'))


if __name__=='__main__':
    parser = argparse.ArgumentParser(description='Decrypt embedding image.')
    parser.add_argument('--image', type=str, required=True, help='image path.')
    args = parser.parse_args()

    main(args.image)

