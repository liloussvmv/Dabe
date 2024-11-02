from charm.toolbox.pairinggroup import PairingGroup, pair, GT, G1
from charm.toolbox.secretutil import SecretUtil
import json
import boto3
import time
import psutil
import asyncio
import os
import warnings


group = PairingGroup('SS512')
util = SecretUtil(group, verbose=False)  # Utility for secret sharing and other operations


def save_to_s3(filename, bucket_name, access_key, secret_key):
    s3 = boto3.client('s3', aws_access_key_id=access_key, aws_secret_access_key=secret_key)
    s3.put_object(Body=open(filename, 'rb'), Bucket=bucket_name, Key=filename)


def download_s3(filename, bucket_name, access_key, secret_key):
    s3 = boto3.client('s3', aws_access_key_id=access_key, aws_secret_access_key=secret_key)
    json_data = s3.get_object(Bucket=bucket_name, Key=filename)
    # save the data in a json file
    with open(filename, 'wb') as f:
        f.write(json_data['Body'].read())
    # return json.load(json_data['Body'])

def load_user_keys(filename='user_keys.json'):
    """
    Loads a JSON file containing user keys and deserializes them.
    Parameters:
    - filename: Name of the file to load the keys from.

    Returns:
    - A dictionary containing the user's keys, deserialized.
    """
    with open(filename, 'r') as f:
        key_data = json.load(f)
    
    user_keys = {'gid': key_data['gid']}
    for attr, keys in key_data.items():
        if attr != 'gid':
            user_keys[attr] = {'k': group.deserialize(keys['k'].encode())}
    return user_keys


def load_ciphertext(filename):
    with open(filename, 'r') as f:
        ct_data = json.load(f)
    ct = {
        "C0": group.deserialize(ct_data['C0'].encode()),
        "C1": {k: group.deserialize(v.encode()) for k, v in ct_data['C1'].items()},
        "C2": {k: group.deserialize(v.encode()) for k, v in ct_data['C2'].items()},
        "C3": {k: group.deserialize(v.encode()) for k, v in ct_data['C3'].items()},
        "policy": ct_data['policy']
    }
    return ct



def decrypt(gp, user_keys, ct):
    user_attr = set(user_keys.keys()) - {'gid'}
    policy = util.createPolicy(ct['policy'])
    pruned = util.prune(policy, user_attr)
    if not pruned:
        raise Exception("Decryption failed: User does not have the required attributes.")

    h_gid = gp['H'](user_keys['gid'])
    egg_s = group.init(GT, 1)  # Identity element of the group GT
    coeffs = util.getCoefficients(policy)
    for node in pruned:
        x = node.getAttributeAndIndex()
        y = node.getAttribute()
        num = ct['C1'][x] * pair(h_gid, ct['C3'][x])
        dem = pair(user_keys[y]['k'], ct['C2'][x])
        egg_s *= (num / dem) ** coeffs[x]
    return ct['C0'] / egg_s




def serializechallenge(decrypted_challenge): 
    config_data = group.serialize(decrypted_challenge).decode()
    with open('decrypted_challenge.json', 'w') as f:
        json.dump(config_data, f, indent=4)
    print(f"Configuration saved to decrypted_challenge.json")



async def wait_for_file(filename, check_interval=1):
    """Wait until a file exists locally."""
    while not os.path.exists(filename):
        await asyncio.sleep(check_interval)

def cpu_usage():
    print(f"CPU Usage: {psutil.cpu_percent(interval=1)}%")

# Load configuration data
with open("api.json", "r") as config_file:
    apidata = json.load(config_file)

if __name__ == '__main__':
    warnings.filterwarnings("ignore")

    start_time_1 = time.time()

    bucket_name = apidata["bucket_name"]
    access_key = apidata["access_key"]
    secret_key = apidata["secret_key"]


    download_s3('user_keys.json', bucket_name=bucket_name, access_key=access_key, secret_key=secret_key)
    download_s3('challengct.json', bucket_name=bucket_name, access_key=access_key, secret_key=secret_key)

    gp = {'g': '<group element>', 'H': lambda x: group.hash(x, G1)}  # Placeholder
    user_keys = load_user_keys()
    # print("UserKeys", user_keys.keys())
    
    
    challengedecCT = load_ciphertext('challengct.json')
    
    

    decrypted_challenge = decrypt(gp, user_keys, challengedecCT)
    serializechallenge(decrypted_challenge)
    # print("Decrypted Challenge:", decrypted_challenge)
    save_to_s3('decrypted_challenge.json', bucket_name, access_key, secret_key)
    end_time_1 = time.time()
    total_time_1 = end_time_1 - start_time_1

    import time
    time.sleep(3) # This Should be Modified
    
    start_time_2 = time.time()

    download_s3('ciphertext.json', bucket_name=bucket_name, access_key=access_key, secret_key=secret_key)
    asyncio.run(wait_for_file('ciphertext.json'))
    ct = load_ciphertext('ciphertext.json')
    decrypted_message = decrypt(gp, user_keys, ct)
    print("Decrypted Message:", decrypted_message)

    end_time_2 = time.time()
    total_time_2 = end_time_2 - start_time_2

    print(f"Execution time: {total_time_1 + total_time_2} seconds")
    cpu_usage()


