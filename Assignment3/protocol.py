# system imports
import hmac # https://docs.python.org/3/library/hmac.html
import hashlib # https://docs.python.org/3/library/hashlib.html#module-hashlib
import os
import json
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM # For AES GCM Encryption: https://cryptography.io/en/latest/hazmat/primitives/aead/#cryptography.hazmat.primitives.ciphers.aead.AESGCM

class Protocol:
    # Initializer (Called from app.py)
    # TODO: MODIFY ARGUMENTS AND LOGIC AS YOU SEEM FIT
    def __init__(self, sharedSecret, appendLog):
        self._sharedSecret = sharedSecret # Store shared secret
        self._appendLog = appendLog 
        self._key = None # The session key

        # Generate the proposed key using sha256. both client and server will generate the same as they have the same shared secret
        hmac_obj = hmac.new(self._sharedSecret.encode(), digestmod=hashlib.sha256)
        hmac_digest = hmac_obj.digest()
        self._proposedKey = hmac_digest # The proposed key

        self._challenge = None # The challenge sent to the other party
        self._received_challenge = None # The challenge received from the other party
        self._secure = False # Securing the protocol

    '''
    Helper function to generate random bytes
    '''
    def GetRandomBytes(self, numBytes=16):
        return os.urandom(numBytes)
    
    '''
    Helpler function to generate a nonce
    '''
    def GenerateNonce(self, numBytes=12):
        return self.GetRandomBytes(numBytes)
    
    '''
    Helper function to generate a challenge
    '''
    def GenerateChallenge(self, numBytes=16):
        # Randomly Generate Challenge
        return self.GetRandomBytes(numBytes)


    # Creating the initial message of your protocol (to be send to the other party to bootstrap the protocol)
    # TODO: IMPLEMENT THE LOGIC (MODIFY THE INPUT ARGUMENTS AS YOU SEEM FIT)
    def GetProtocolInitiationMessage(self):
        # Generate a challenge as a string. Using Mutual Authentication Protocol similar to Figure 9.12 in Stamp Book.
        self._challenge = str(self.GenerateChallenge())
        print("generated challenge: " + self._challenge)
        # Using JSON for Message Format
        # This message will be sent in the clear as a key has not yet been established.
        return json.dumps({
            "sender": "client",
            "type": "protocol", 
            "action": "initiate", 
            "data": [self._challenge]
        })


    # Checking if a received message is part of your protocol (called from app.py)
    # TODO: IMPLMENET THE LOGIC
    def IsMessagePartOfProtocol(self, message):
        print("Checking if message is part of protocol")
        try:
            # Check if the message is a valid JSON
            message = json.loads(message)
            if not self._secure and message["type"] == "protocol":
                print("Message is part of protocol")
                # Message is a valid protocol message
                return True
            else: 
                print("Message is not part of protocol")
                # Message is not a valid protocol message
                return False
        except:
            
            if not self._secure and self._key is None:
                return False
            elif self._secure and self._key is not None:
                return False
            else: return False

    # Processing protocol message
    # TODO: IMPLMENET THE LOGIC (CALL SetSessionKey ONCE YOU HAVE THE KEY ESTABLISHED)
    # THROW EXCEPTION IF AUTHENTICATION FAILS
    def ProcessReceivedProtocolMessage(self, message):
        # Already know that this is a protocol message
        message = json.loads(message)
        
        # Check action of protocol message
        if message["action"] == "initiate" and message["sender"] == "client":
            print("Server Received Initiate Message")
            self._appendLog("Secure Connection Initiating...")
            # Generate Response to Challenge
            self._challenge = str(self.GenerateChallenge())

            # Client has initiated the protocol. Now server has to respond with the challenge
            received_challenge = message["data"][0] # Only one data in the list
            self._received_challenge = received_challenge

            # Encrypt the challenge and send it back
            print("Server Encrypting Challenge")
            print("Got Challenge: " + str(received_challenge))
            encrypted_challenge = self.EncryptChallenge(received_challenge)
            return json.dumps({
                "sender": "server",
                "type": "protocol", 
                "action": "initiate_response", 
                "data": [self._challenge, encrypted_challenge]
            })

        elif message["action"] == "initiate_response" and message["sender"] == "server":
            # Check if the challenge is the same
            received_challenge = message["data"][0]
            self._received_challenge = received_challenge
            encrypted_challenge = message["data"][1] 
            print("received challenge: " + received_challenge)
            print("encrypted challenge: " + encrypted_challenge)
            # Decrypt the challenge and verify that it is the same
            decrypted_challenge = self.DecryptChallenge(encrypted_challenge)
            print("decrypted challenge: " + str(decrypted_challenge))
            if decrypted_challenge == self._challenge:
                print("decrypted challenge same as challenge")
                encrypted_response = self.EncryptChallenge(received_challenge)
                # Set the session key
                print("Client Setting Session Key")
                # Generate a random nonce to use for session key - can be sent in the clear as the shared secret is secret.
                self.SetSessionKey(self._received_challenge)
                # Client authenticated server. Now server has to authenticate client.

                return json.dumps({
                    "sender": "client",
                    "type": "protocol", 
                    "action": "initiate2", 
                    "data": [encrypted_response]
                })
            
        elif message["action"] == "initiate2" and message["sender"] == "client":
            encrypted_challenge = message["data"][0]
            # Decrypt the challenge and verify that it is the same
            decrypted_challenge = self.DecryptChallenge(encrypted_challenge)
            if decrypted_challenge == self._challenge:
                # Set the session key
                print("Server Setting Session Key")
                self.SetSessionKey(self._received_challenge)
                # Now server has also authenticated client. 
                return None

        else:
            raise Exception("Invalid Protocol Message, Authentication Failed")
    
    # Setting the key for the current session
    # TODO: MODIFY AS YOU SEEM FIT
    def SetSessionKey(self, received_challenge):
        # XOR the proposed key with the received challenge
        xor_result = str(bool(self._challenge) ^ bool(received_challenge))
        hmac_obj = hmac.new(self._sharedSecret.encode(), xor_result.encode(), digestmod=hashlib.sha256)
        hmac_digest = hmac_obj.digest()
        self._key = hmac_digest # The proposed key
        self._secure = True
        print("Session Key Set: " + str(self._key))
        self._appendLog("Secure Connection Established")

    def isSecure(self):
        return self._secure

    '''
    Helper function to encrypt the challenge
    Used before key is established
    '''
    def EncryptChallenge(self, challenge):
        # Encrypt using AESGCM using the proposed key
        aesgcm = AESGCM(self._proposedKey)
        nonce = self.GenerateNonce()
        if isinstance(challenge, str):
            challenge = challenge.encode()
        encrypted_challenge = aesgcm.encrypt(nonce, challenge, None)
        return base64.b64encode(nonce + encrypted_challenge).decode()

    '''
    Helper function to decrypt the challenge
    Used before key is established
    '''
    def DecryptChallenge(self, encrypted_challenge):
        # Decrypt using AESGCM now that key is established
        encrypted_challenge = base64.b64decode(encrypted_challenge)
        aesgcm = AESGCM(self._proposedKey)
        nonce = encrypted_challenge[:12] # First 12 bytes are nonce
        encrypted_challenge = encrypted_challenge[12:]
        try:
            decrypted_challenge = aesgcm.decrypt(nonce, encrypted_challenge, None).decode()
            return decrypted_challenge
        except:
            raise Exception("Challenge Decryption Failed")

    # Encrypting messages
    # TODO: IMPLEMENT ENCRYPTION WITH THE SESSION KEY (ALSO INCLUDE ANY NECESSARY INFO IN THE ENCRYPTED MESSAGE FOR INTEGRITY PROTECTION)
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    def EncryptAndProtectMessage(self, plain_text):
        # cipher_text = plain_text if sef._key is None
        if self._key is None:
            print("Key not established yet, returning plain_text")
            # Key not established yet. Return the plain_text
            return plain_text
        
        # Encrypt using AESGCM now that key is established
        aesgcm = AESGCM(self._key)
        nonce = self.GenerateNonce()
        if isinstance(plain_text, str):
            plain_text = plain_text.encode()
        cipher_text = aesgcm.encrypt(nonce, plain_text, None)
        return base64.b64encode(nonce + cipher_text).decode()


    # Decrypting and verifying messages
    # TODO: IMPLEMENT DECRYPTION AND INTEGRITY CHECK WITH THE SESSION KEY
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    def DecryptAndVerifyMessage(self, cipher_text):
        # plain_text = cipher_text if self._key is None
        if self._key is None:
            print("Key not established yet, returning cipher_text")
            # Key not established yet. return the cipher_text
            return "[Insecure] ".encode() + cipher_text
        
        # Decrypt using AESGCM now that key is established
        cipher_text = base64.b64decode(cipher_text)
        aesgcm = AESGCM(self._key)
        nonce = cipher_text[:12] # First 12 bytes are nonce
        cipher_text = cipher_text[12:]
        try:
            plain_text = aesgcm.decrypt(nonce, cipher_text, None)
            return "[Secure] ".encode() + plain_text
        except:
            raise Exception("Integrity Verification (Decryption) Failed")
        