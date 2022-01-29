# Traefik Certificate Extractor

Tool to extract Let's Encrypt certificates from Traefik's (v2.5.6) ACME storage file, supports ACME storage files on NAS / Remote shares including cifs / SMB, etc. types.

Forked from DanielHuisman/traefik-certificate-extractor:
https://github.com/DanielHuisman/traefik-certificate-extractor


## Installation
```
git clone https://github.com/psunderland/traefik-certificate-extractor
cd traefik-certificate-extractor
```

## Usage
```
python3 extractor.py [directory]
```
Default input directory is `./data`. The output directories are `./certs` and `./certs_flat`. The certificate extractor will extract certificates from `acme.json` JSON file in the input directory, so make sure this is the same as Traefik's ACME directory.

## Docker
There is a Docker image available for this tool: [patricksunderland/traefikcertificateextractor:2.5.6](https://hub.docker.com/r/patricksunderland/traefikcertificateextractor:2.5.6/).
Example run:
```
docker run --name extractor -d -v /srv/traefik/acme:/app/data -v /srv/extractor/certs:/app/certs patricksunderland/traefik-certificate-extractor
```

## Output
```
certs/
    example.com/
        cert.pem
        chain.pem
        fullchain.pem
        privkey.pem
    sub.example.nl/
        cert.pem
        chain.pem
        fullchain.pem
        privkey.pem
certs_flat/
    example.com.crt
    example.com.key
    example.com.chain.pem
    sub.example.nl.crt
    sub.example.nl.key
    sub.example.nl.chain.pem
```
