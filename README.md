# Telegram Passport Data Decryption (Python)
###### Hope you find this useful!
# Requirements
```sh
pip install pycryptodome
```
# Example
```python
import json
passport_data = update['message']['passport_data']
credentials = passport_data['credentials']
credentials_secret = decrypt_credential_secret(credentials['secret'])
credentials = json.loads(decrypt_data(
                            credentials['data'],
                            credentials_secret,
                            credentials['hash']
                    ))
personal_details = json.loads(decrypt_data(
    data,
    credentials['secure_data']['personal_details']['data']['secret'],
    credentials['secure_data']['personal_details']['data']['data_hash']
    ))
```
