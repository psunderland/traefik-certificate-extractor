import sys
import os
import errno
import time
import json
import glob
import datetime
from base64 import b64decode

class Handler():

    def checkforchange(self, file):
        try:
            mtime = os.path.getmtime(file)
        except OSError:
            mtime = 0
        if mtime != 0:
            check_last_modified_date = datetime.datetime.fromtimestamp(mtime)
            if check_last_modified_date != self._base_last_modified_date:
                # File change detected, extract the certificates from the changed file
                print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ': Traefik certificates json file change detected, extracting certificates...')
                self._base_last_modified_date = check_last_modified_date
                self.handle_file(file)

    def handle_file(self, file):
        # Read JSON file
        jsondata = json.loads(open(file).read())
        # Skip the top level resolvername key in the json

        data = jsondata[list(jsondata.keys())[0]]


        # Determine ACME version
        try:
            acme_version = 2 if 'acme-v02' in data['Account']['Registration']['uri'] else 1
        except TypeError:
            if 'DomainsCertificate' in data:
                acme_version = 1
            else:
                acme_version = 2

        # Get the certificates
        certs = data['Certificates']
        print(str(len(certs)) + ' certificates found')

        # Loop over all certificates
        for c in certs:
            if acme_version == 1:
                name = c['Certificate']['Domain']
                privatekey = c['Certificate']['PrivateKey']
                fullchain = c['Certificate']['Certificate']
                sans = c['Domains']['SANs']
            elif acme_version == 2:
                name = c['domain']['main']
                privatekey = c['key']
                fullchain = c['certificate']
                sans = c['domain']['sans']

            # Decode private key, certificate and chain
            privatekey = b64decode(privatekey).decode('utf-8')
            fullchain = b64decode(fullchain).decode('utf-8')
            start = fullchain.find('-----BEGIN CERTIFICATE-----', 1)
            cert = fullchain[0:start]
            chain = fullchain[start:]

            # Create domain directory if it doesn't exist
            directory = 'certs/' + name + '/'
            try:
                os.makedirs(directory)
            except OSError as error:
                if error.errno != errno.EEXIST:
                    raise

            # Write private key, certificate and chain to file
            with open(directory + 'privkey.pem', 'w') as f:
                f.write(privatekey)

            with open(directory + 'cert.pem', 'w') as f:
                f.write(cert)

            with open(directory + 'chain.pem', 'w') as f:
                f.write(chain)

            with open(directory + 'fullchain.pem', 'w') as f:
                f.write(fullchain)

            # Write private key, certificate and chain to flat files
            directory = 'certs_flat/'

            with open(directory + name + '.key', 'w') as f:
                f.write(privatekey)
            with open(directory + name + '.crt', 'w') as f:
                f.write(fullchain)
            with open(directory + name + '.chain.pem', 'w') as f:
                f.write(chain)

            if sans:
                for name in sans:
                    with open(directory + name + '.key', 'w') as f:
                        f.write(privatekey)
                    with open(directory + name + '.crt', 'w') as f:
                        f.write(fullchain)
                    with open(directory + name + '.chain.pem', 'w') as f:
                        f.write(chain)

            print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ': Extracted certificate for: ' + name + (', ' + ', '.join(sans) if sans else ''))

if __name__ == "__main__":
    # Determine path to watch
    path = sys.argv[1] if len(sys.argv) > 1 else './data'

    # Create output directories if it doesn't exist
    try:
        os.makedirs('certs')
    except OSError as error:
        if error.errno != errno.EEXIST:
            raise
    try:
        os.makedirs('certs_flat')
    except OSError as error:
        if error.errno != errno.EEXIST:
            raise

    # Create event handler
    event_handler = Handler()

    # Extract certificates from current file(s) before watching
    files = glob.glob(os.path.join(path, '*.json'))
    try:
        for file in files:
            print('Certificate storage found (' + os.path.basename(file) + ')')
            event_handler.handle_file(file)
        # Establish the base_last_modified_date
        try:
            mtime = os.path.getmtime(file)
        except OSError:
            mtime = 0
        base_last_modified_date = datetime.datetime.fromtimestamp(mtime)
        event_handler._base_last_modified_date = base_last_modified_date
    except Exception as e:
        print(e)

    while True:
        event_handler.checkforchange(file)
        time.sleep(1)