# system imports
import hmac # https://docs.python.org/3/library/hmac.html
import hashlib # https://docs.python.org/3/library/hashlib.html#module-hashlib
import os
import json

class Protocol:
    # Initializer (Called from app.py)
    # TODO: MODIFY ARGUMENTS AND LOGIC AS YOU SEEM FIT
    def __init__(self, sharedSecret):
        self._sharedSecret = sharedSecret
        self._key = None # The session key

        hmac_obj = hmac.new(self._sharedSecret.encode(), digestmod=hashlib.sha256)
        hmac_digest = hmac_obj.digest()
        self._proposedKey = hmac_digest # The proposed key

        self._challenge = None # The challenge sent to the other party

    def GetRandomBytes(self, numBytes=16):
        return os.urandom(numBytes)
    
    def GenerateNonce(self):
        return self.GetRandomBytes(16)
    
    def GenerateChallenge(self):
        # Randomly Generate Challenge
        return self.GetRandomBytes(16)

    # Creating the initial message of your protocol (to be send to the other party to bootstrap the protocol)
    # TODO: IMPLEMENT THE LOGIC (MODIFY THE INPUT ARGUMENTS AS YOU SEEM FIT)
    def GetProtocolInitiationMessage(self):
        # Using JSON for Message Format
        self._challenge = str(self.GenerateChallenge())
        return json.dumps({
            "sender": "client",
            "type": "protocol", 
            "action": "initiate", 
            "data": [self._challenge]
        })


    # Checking if a received message is part of your protocol (called from app.py)
    # TODO: IMPLMENET THE LOGIC
    def IsMessagePartOfProtocol(self, message):
        try:
            print("Checking if message is part of protocol")
            message = json.loads(message)
            if message["type"] == "protocol":
                print("Message is part of protocol")
                return True
            else: 
                print("Message is not part of protocol")
                return False
        except:
            return False

    # Processing protocol message
    # TODO: IMPLMENET THE LOGIC (CALL SetSessionKey ONCE YOU HAVE THE KEY ESTABLISHED)
    # THROW EXCEPTION IF AUTHENTICATION FAILS
    def ProcessReceivedProtocolMessage(self, message):
        # Already know that this is a protocol message
        message = json.loads(message)
        print("Processing protocol message")

        # Check action of protocol message
        if message["action"] == "initiate" and message["sender"] == "client":
            print("Received Initiate Message from Client")
            # Generate Response to Challenge
            self._challenge = str(self.GenerateChallenge())
            received_challenge = message["data"][0] # Only one data in the list
            encrypted_challenge = self.EncryptAndProtectMessage(received_challenge)
            print("Received Challenge: " + received_challenge)
            return json.dumps({
                "sender": "server",
                "type": "protocol", 
                "action": "initiate_response", 
                "data": [self._challenge, encrypted_challenge]
            })

        elif message["action"] == "initiate_response" and message["sender"] == "server":
            print("Received Initiate Response from Server")
            # Check if the challenge is the same
            received_challenge = message["data"][0]
            encrypted_challenge = message["data"][1] 
            # Decrypt the challenge and verify that it is the same
            decrypted_challenge = self.DecryptAndVerifyMessage(encrypted_challenge)
            if decrypted_challenge == self._challenge:
                print("Challenge is the same")
                # Set the session key
                self.SetSessionKey(self._proposedKey)
                print("Session Key Set for Client")
                encrypted_response = self.EncryptAndProtectMessage(received_challenge)
                # Client authenticated server. Now server has to authenticate client.
                return json.dumps({
                    "sender": "client",
                    "type": "protocol", 
                    "action": "initiate2", 
                    "data": [encrypted_response]
                })
            
        elif message["action"] == "initiate2" and message["sender"] == "client":
            print("Received Initiate2 from Client")
            encrypted_challenge = message["data"][0]
            # Decrypt the challenge and verify that it is the same
            decrypted_challenge = self.DecryptAndVerifyMessage(encrypted_challenge)
            if decrypted_challenge == self._challenge:
                print("Challenge is the same")
                # Set the session key
                self.SetSessionKey(self._proposedKey)
                print("Session Key Set for Server")
                # Now server has also authenticated client. 

        else:
            print("Invalid Protocol Message")
            raise Exception("Invalid Protocol Message, Authentication Failed")
    
    # Setting the key for the current session
    # TODO: MODIFY AS YOU SEEM FIT
    def SetSessionKey(self, key):
        self._key = key
        pass


    # Encrypting messages
    # TODO: IMPLEMENT ENCRYPTION WITH THE SESSION KEY (ALSO INCLUDE ANY NECESSARY INFO IN THE ENCRYPTED MESSAGE FOR INTEGRITY PROTECTION)
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    def EncryptAndProtectMessage(self, plain_text):
        cipher_text = plain_text
        return cipher_text


    # Decrypting and verifying messages
    # TODO: IMPLEMENT DECRYPTION AND INTEGRITY CHECK WITH THE SESSION KEY
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    def DecryptAndVerifyMessage(self, cipher_text):
        plain_text = cipher_text
        return plain_text
