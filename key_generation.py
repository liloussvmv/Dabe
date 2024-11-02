from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, GT, pair
from charm.toolbox.secretutil import SecretUtil
import json
import time
import psutil
import warnings

# from memory_profiler import profile

# Initialize the pairing group
group = PairingGroup('SS512')
util = SecretUtil(group, verbose=False)  # Utility for secret sharing and other operations



def setup():
    """Global Setup for the system, defining parameters used across all authorities and users."""
    g = group.random(G1)  # Generator for group G1
    H = lambda x: group.hash(x, G1)  # Hash function mapping identities to group elements
    GP = {'g': g, 'H': H}
    return GP



def authsetup(GP, attributes):
    """Sets up an authority with a given set of attributes, generating public and private keys."""
    SK = {}
    PK = {}
    for attr in attributes:
        alpha_i = group.random(ZR)
        y_i = group.random(ZR)
        e_gg_alpha_i = pair(GP['g'], GP['g']) ** alpha_i
        g_y_i = GP['g'] ** y_i
        SK[attr.upper()] = {'alpha_i': alpha_i, 'y_i': y_i}
        PK[attr.upper()] = {'e(gg)^alpha_i': e_gg_alpha_i, 'g^y_i': g_y_i}
    return (SK, PK)



def keygen(gp, sk, attributes, gid):
    """
    Generates keys for a user 'gid' for specific attributes using the authority's private keys.
    Parameters:
    - gp: Global parameters.
    - sk: Authority's private key dictionary.
    - attributes: List of attributes for which keys are to be generated.
    - gid: User's global identifier.
    Returns:
    - A dictionary with keys for each attribute.
    """
    user_keys = {'gid': gid}
    h_gid = gp['H'](gid)  # Compute the hash of the GID once for efficiency

    for attr in attributes:
        attr = attr.upper()
        if attr in sk:
            alpha_i = sk[attr]['alpha_i']
            y_i = sk[attr]['y_i']
            K = (gp['g'] ** alpha_i) * (h_gid ** y_i)
            user_keys[attr] = {'k': K}
        else:
            print(f"No keys available for attribute {attr} from the authority.")

    return user_keys


## --------------- This part is to save configuration data needed for encryption ----------------------------------


def generate_configuration(gp, pk, filename='config.json'):
    """
    Generates a JSON configuration file containing global parameters and public keys.
    Parameters:
    - gp: Global parameters (dictionary).
    - pk: Public keys (dictionary).
    - filename: Name of the file to save the configuration.
    """
    config_data = {
        'GP': {
            'g': group.serialize(gp['g']).decode(),
            'H': str(gp['H'])  # We store only a descriptor since the hash function is not serializable.
        },
        'PK': {k: {sub_k: group.serialize(v).decode() for sub_k, v in pk[k].items()} for k in pk}
    }

    with open(filename, 'w') as f:
        json.dump(config_data, f, indent=4)
    # print(f"Configuration saved to {filename}")


def generate_userkeys(user_keys, filename='user_keys.json'):
    key_data = {'gid': user_keys['gid']}
    for attr, keys in user_keys.items():
        if attr == 'gid':
            continue  # Skip the 'gid' since it's just an identifier
        key_data[attr] = {'k': group.serialize(keys['k']).decode()}

    with open(filename, 'w') as f:  
        json.dump(key_data, f, indent=4)
    # print(f"Configuration saved to {filename}")
# ------------------------------------------------------------------------------------------

# Generate function that saves user_keys.json and config.json to an amazon s3 bucket
import boto3

def save_to_s3(filename, bucket_name, access_key, secret_key):
    s3 = boto3.client('s3', aws_access_key_id=access_key, aws_secret_access_key=secret_key)
    s3.put_object(Body=open(filename, 'rb'), Bucket=bucket_name, Key=filename)

def cpu_usage():
    print(f"CPU Usage: {psutil.cpu_percent(interval=1)}%")

# @profile
# def main():
with open("api.json", "r") as config_file:
    apidata = json.load(config_file)

if __name__ == '__main__':
    warnings.filterwarnings("ignore")
    start_time = time.time()
    GP = setup()
    attributes = ['ONE', 'TWO', 'THREE', 'FOUR']
    SK, PK = authsetup(GP, attributes)
    # print("Authority Public Keys:", PK)
    # print("Authority Private Keys:", SK)

    # Example of generating keys for a user with multiple attributes
    user_gid = 'alice'
    user_attributes = ['ONE', 'FOUR']
    user_keys = keygen(GP, SK, user_attributes, user_gid)
    # print("Keys for Alice:", user_keys)

    generate_configuration(GP, PK)
    generate_userkeys(user_keys)
    bucket_name = apidata["bucket_name"]
    access_key = apidata["access_key"]
    secret_key = apidata["secret_key"]
    save_to_s3('config.json', bucket_name, access_key, secret_key)
    save_to_s3('user_keys.json', bucket_name, access_key, secret_key)
    
    end_time = time.time()
    print(f"Execution time: {end_time - start_time} seconds")
    cpu_usage()

# if __name__ == '__main__':
#     main()
