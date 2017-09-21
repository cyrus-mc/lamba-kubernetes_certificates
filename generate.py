import botocore
import boto3
from OpenSSL import crypto

TYPE_RSA = crypto.TYPE_RSA
TYPE_DSA = crypto.TYPE_DSA

s3 = boto3.resource('s3')

def createKeyPair(type, bits):
    """
    Create a public/private key pair.
    Arguments: type - Key type, must be one of TYPE_RSA and TYPE_DSA
               bits - Number of bits to use in the key
    Returns:   The public/private key pair in a PKey object
    """
    pkey = crypto.PKey()
    pkey.generate_key(type, bits)
    return pkey

def createCertRequest(pkey, digest="sha256", **name):
    """
    Create a certificate request.
    Arguments: pkey   - The key to associate with the request
               digest - Digestion method to use for signing, default is md5
               **name - The name of the subject of the request, possible
                        arguments are:
                          C     - Country name
                          ST    - State or province name
                          L     - Locality name
                          O     - Organization name
                          OU    - Organizational unit name
                          CN    - Common name
                          emailAddress - E-mail address
    Returns:   The certificate request in an X509Req object
    """
    req = crypto.X509Req()

    subj = req.get_subject()

    for (key,value) in name.items():
        setattr(subj, key, value)

    req.set_pubkey(pkey)
    req.sign(pkey, digest)
    return req

def createCertificate(req, (issuerCert, issuerKey), serial, (notBefore, notAfter), extensions, digest="sha256"):
    """
    Generate a certificate given a certificate request.
    Arguments: req        - Certificate reqeust to use
               issuerCert - The certificate of the issuer
               issuerKey  - The private key of the issuer
               serial     - Serial number for the certificate
               notBefore  - Timestamp (relative to now) when the certificate
                            starts being valid
               notAfter   - Timestamp (relative to now) when the certificate
                            stops being valid
               digest     - Digest method to use for signing, default is md5
    Returns:   The signed certificate in an X509 object
    """
    cert = crypto.X509()

    # we want version 3 certs since we use v3 extensions (2 = Version 3 for some reason)
    cert.set_version(2)

    cert.set_serial_number(serial)
    cert.gmtime_adj_notBefore(notBefore)
    cert.gmtime_adj_notAfter(notAfter)
    cert.set_issuer(issuerCert.get_subject())
    cert.set_subject(req.get_subject())

    # add in any supplied extensions (not gonna validate, will just fail if you supply
    # invalid extension)
    cert.add_extensions(extensions)

    cert.set_pubkey(req.get_pubkey())
    cert.sign(issuerKey, digest)
    return cert

"""
Create our CertificateAuthority.

Stores the generate Key and Certificate in the specified S3 bucket.

Return tuple containing key and certificate.

"""
def createCertificateAuthority():

    # generate 2048 bit key
    key = createKeyPair(TYPE_RSA, 2048)
    # create certificate signing request
    req = createCertRequest(key, CN="kubernetes-ca")

    # generate certificate, which will be our CA
    extensions = [ crypto.X509Extension('basicConstraints', True, 'CA:TRUE') ]
    certificate = createCertificate(req, (req, key), 0, (0, 60 * 60 * 24 * 365 * 10), extensions)

    # return both the key and certificate for later use (CSR isn't needed)
    return (key, certificate)

def createCerts(ca_key, ca_cert, cn, subjectAlt = []):
    
    # generate 2048 bit key
    key = createKeyPair(TYPE_RSA, 2048)
    # create certificate signing request
    req = createCertRequest(key, CN=cn)

    # generate certificate
    extensions = [ crypto.X509Extension('basicConstraints', True, 'CA:FALSE'),
            crypto.X509Extension('keyUsage', True, 'nonRepudiation, digitalSignature, keyEncipherment') ]

    # check if there are supplied SAN
    if not len(subjectAlt) == 0:
        extensions.append( crypto.X509Extension('subjectAltName', True, "%s" % (",".join(subjectAlt))))
        #extensions.append( crypto.X509Extension('subjectAltName', True, 'DNS:apiserver.%s.%s' % ('cluster', 'k8s')) )
        # add all the subjectAltNames to the certificate
        #for san in subjectAlt:
        #    extensions.append( crypto.X509Extension('subjectAltName', True, san) )

    certificate = createCertificate(req, (ca_cert, ca_key), 0, (0, 60 * 60 * 24 * 365 * 10), extensions)

    # return both the key and certificate for later use (CSR isn't needed)
    return (key, certificate)

def lambda_handler(event, context):

    # event should contain cluster-name and region where cluster exists
    # bucket name = cluster-name
    bucket = "smarsh-k8s-%s" % (event['cluster-name'])
    region = event['region']

    exists = True
    
    try:
        s3.meta.client.head_bucket(Bucket=bucket)
    except botocore.exceptions.ClientError as e:
        error_code = int(e.response['Error']['Code'])
        if error_code == 404:
            # create the bucket if not found
            s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={'LocationConstraint': region})
            exists = False
   
    # we are going to make some assumptions here. If the bucket doesn't exist that means none
    # of the certificates (CA, API, etc, etc) exist. If the bucket does exist, the assumption is
    # that this function ran and succeeded, thus all the certificates should exist.

    if exists is False:
        (ca_key, ca_cert) = createCertificateAuthority()

        # write the CA key and certificate to our S3 bucket
        s3.Object(bucket, 'ca.key').put(Body=crypto.dump_privatekey(crypto.FILETYPE_PEM, ca_key))
        s3.Object(bucket, 'ca.pem').put(Body=crypto.dump_certificate(crypto.FILETYPE_PEM, ca_cert))

        # next up, generate the API server key and certificate
        (api_key, api_cert) = createCerts(ca_key, ca_cert, "kube-apiserver", [ 'IP:10.3.0.1', 'DNS:kubernetes',
            'DNS:kubernetes.default',
            'DNS:kubernetes.default.svc',
            'DNS:kubernetes.default.svc.cluster.local',
            "DNS:*.{0}.elb.amazonaws.com".format(region),
            "DNS:apiserver.{0}.{1}".format(event['cluster-name'], event['internal-tld']) ])

        # write API key and certificate to our S3 bucket
        s3.Object(bucket, 'apiserver-key.pem').put(Body=crypto.dump_privatekey(crypto.FILETYPE_PEM, api_key))
        s3.Object(bucket, 'apiserver.pem').put(Body=crypto.dump_certificate(crypto.FILETYPE_PEM, api_cert))

        # next up, worker node key and certificate (will use one universal certificate for all nodes)
        (wrk_key, wrk_cert) = createCerts(ca_key, ca_cert, "kube-worker", [])

        # write worker key and certificate to our S3 bucket
        s3.Object(bucket, 'worker-key.pem').put(Body=crypto.dump_privatekey(crypto.FILETYPE_PEM, wrk_key))
        s3.Object(bucket, 'worker.pem').put(Body=crypto.dump_certificate(crypto.FILETYPE_PEM, wrk_cert))

        # finally, generate admin key and certificate
        (admin_key, admin_cert) = createCerts(ca_key, ca_cert, "kube-admin", [])

        # write admin key and certificate to our S3 bucket
        s3.Object(bucket, 'admin-key.pem').put(Body=crypto.dump_privatekey(crypto.FILETYPE_PEM, admin_key))
        s3.Object(bucket, 'admin.pem').put(Body=crypto.dump_certificate(crypto.FILETYPE_PEM, admin_cert))

    return True
