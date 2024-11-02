from charm.toolbox.pairinggroup import PairingGroup, GT, pair, G1
from charm.toolbox.secretutil import SecretUtil
import json
import boto3
import time
import psutil
import warnings


# Initialize the pairing group
group = PairingGroup('SS512')
util = SecretUtil(group, verbose=False)  # Utility for secret sharing and other operations

def encrypt(gp, pk, message, policy_str):
    """
    Encrypt a message with the given policy string using public parameters and public keys.
    Parameters:
    - gp: Global parameters.
    - pk: Consolidated public keys of all attributes from all authorities.
    - message: The message to be encrypted (must be an element of GT).
    - policy_str: The policy string specifying access requirements.
    Returns:
    - Dictionary representing the encrypted message.
    """
    s = group.random()  # Random element for blinding the message
    egg_s = pair(gp['g'], gp['g']) ** s
    C0 = message * egg_s

    # Parsing the policy string into a policy tree
    policy = util.createPolicy(policy_str)
    sshares = util.calculateSharesList(s, policy)  # Shares of the secret
    
    C1, C2, C3 = {}, {}, {}
    for (node, s_share) in sshares:
        attr = node.getAttributeAndIndex()  # Get attribute as a string, including any index
        k_attr = util.strip_index(attr)  # Strip index from attribute if present
        r_x = group.random()
        C1[attr] = (pair(gp['g'], gp['g']) ** s_share) * (pk[k_attr]['e(gg)^alpha_i'] ** r_x)
        C2[attr] = gp['g'] ** r_x
        C3[attr] = (pk[k_attr]['g^y_i'] ** r_x) * (gp['g'] ** 0)  # zero element in ZR
    return {'C0': C0, 'C1': C1, 'C2': C2, 'C3': C3, 'policy': policy_str}





# Function to retrieve two json files from s3 buckets
def download_s3(filename, bucket_name, access_key, secret_key):
    s3 = boto3.client('s3', aws_access_key_id=access_key, aws_secret_access_key=secret_key)
    json_data = s3.get_object(Bucket=bucket_name, Key=filename)
    # save the data in a json file
    with open(filename, 'wb') as f:
        f.write(json_data['Body'].read())
    # return json.load(json_data['Body'])

def save_to_s3(filename, bucket_name, access_key, secret_key):
    s3 = boto3.client('s3', aws_access_key_id=access_key, aws_secret_access_key=secret_key)
    s3.put_object(Body=open(filename, 'rb'), Bucket=bucket_name, Key=filename)




def load_configuration(filename='config.json'):
    with open(filename, 'r') as f:
        config_data = json.load(f)
    gp = {
        'g': group.deserialize(config_data['GP']['g'].encode()),
        'H': config_data['GP']['H']  #  H can be directly used as it was saved as a string
    }
    pk = {k: {sub_k: group.deserialize(v.encode()) for sub_k, v in config_data['PK'][k].items()} for k in config_data['PK']}
    return gp,pk


def deSerializechallenge(decrypted_challenge): 
    with open(decrypted_challenge, 'r') as f:
        config_data = json.load(f)
    challenge = group.deserialize(config_data.encode())
    return challenge


def serializeCipher(filename,ciphertext):
    serialized_data = {
        'C0': group.serialize(ciphertext['C0']).decode(),
        'C1': {k: group.serialize(v).decode() for k, v in ciphertext['C1'].items()},
        'C2': {k: group.serialize(v).decode() for k, v in ciphertext['C2'].items()},
        'C3': {k: group.serialize(v).decode() for k, v in ciphertext['C3'].items()},
        'policy': ciphertext['policy']
    }
    # save it to a jsonfile named ciphertext.json
    with open(filename, 'w') as f:
        json.dump(serialized_data, f, indent=4)

    return serialized_data




# def load_ciphertext(filename):
#     with open(filename, 'r') as f:
#         ct_data = json.load(f)
#     ct = {
#         "C0": group.deserialize(ct_data['C0'].encode()),
#         "C1": {k: group.deserialize(v.encode()) for k, v in ct_data['C1'].items()},
#         "C2": {k: group.deserialize(v.encode()) for k, v in ct_data['C2'].items()},
#         "C3": {k: group.deserialize(v.encode()) for k, v in ct_data['C3'].items()},
#         "policy": ct_data['policy']
#     }
#     return ct




import asyncio
import os

async def wait_for_file(filename, check_interval=1):
    """Wait until a file exists locally."""
    while not os.path.exists(filename):
        await asyncio.sleep(check_interval)

def cpu_usage():
    print(f"CPU Usage: {psutil.cpu_percent(interval=1)}%")

with open("api.json", "r") as config_file:
    apidata = json.load(config_file)

if __name__ == '__main__':
    warnings.filterwarnings("ignore")

    start_time_1 = time.time()
    bucket_name = apidata["bucket_name"]
    access_key = apidata["access_key"]
    secret_key = apidata["secret_key"]


    download_s3('config.json', bucket_name=bucket_name, access_key=access_key, secret_key=secret_key)
    gp,pk = load_configuration()


    # Define a message and a policy
    policy_str = '((ONE or THREE) and (TWO or FOUR))'



    ############################ challenge ###############################
    challenge = group.random(GT)
    challengct = encrypt(gp, pk, challenge, policy_str)
    serializeCipher('challengct.json',challengct)
    save_to_s3('challengct.json', bucket_name, access_key, secret_key)
    print("Run decryption")


    #download_s3('decrypted_challenge.json', bucket_name=bucket_name, access_key=access_key, secret_key=secret_key)
    # await wait_for_file('decrypted_challenge.json')
    
    end_time_1 = time.time()
    total_time_1 = end_time_1 - start_time_1
    
    asyncio.run(wait_for_file('decrypted_challenge.json'))
    
    start_time_2 = time.time()



    download_s3('decrypted_challenge.json', bucket_name=bucket_name, access_key=access_key, secret_key=secret_key)
    decrypted_challenge= deSerializechallenge('decrypted_challenge.json')

    #challengeog = load_ciphertext('challengct.json') 

    if challenge == decrypted_challenge:
        print("=============================================================")
        print("User Got Attributes")
        print("=============================================================")
        message = group.random(GT)
        # print("OG Message Here", message)
        ciphertext = encrypt(gp, pk, message, policy_str)
        serializeCipher('ciphertext.json',ciphertext)
        save_to_s3('ciphertext.json', bucket_name, access_key, secret_key)
        try:
            os.remove('ciphertext.json')
            # print(f"{'ciphertext.json'} has been deleted.")
        except FileNotFoundError:
            print(f"{'ciphertext.json'} does not exist.")
        except Exception as e:
            print(f"An error occurred while trying to delete {'ciphertext.json'}: {e}")
    else:
        print("=============================================================")
        print("User does not have the required attributes")
        print("=============================================================")
    
    end_time_2 = time.time()
    total_time_2 = end_time_2 - start_time_2

    print(f"Execution time: {total_time_1 + total_time_2} seconds")
    cpu_usage()


# if __name__ == '__main__':
#     asyncio.run(main())