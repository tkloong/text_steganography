import hashlib


def transform_to_pixel_position(n, height, width):
    y = n % height
    x = n % width
    channel = n % 3
    return y, x, channel


def get_random_position(password, length, width, height, max_num_duplication=None):
    k, seed = 0, password
    N = width * height

    num_duplication = 0
    random_positions = []
    seen = set()
    while len(random_positions) < length:
        hash_obj = hashlib.sha512(seed)
        rand_num = int(hash_obj.hexdigest(), 16) % N
        y, x, channel = transform_to_pixel_position(rand_num, height, width)
        label = f'{y},{x},{channel}'
        # Check if the pixel position is duplicate
        if label in seen:
            num_duplication += 1
            print(f'[Warning] Duplicate random number: {rand_num}')
            if max_num_duplication and num_duplication >= max_num_duplication:
                return random_positions, num_duplication
        else:
            seen.add(label)
            random_positions += [rand_num]
        seed = seed.decode('utf-8')
        #seed = seed.decode('latin1')
        seed += seed[k]
        seed = seed.encode('utf-8')
        #seed = seed.encode('latin1')
        k += 1

    return random_positions, num_duplication
