import subprocess
import binascii
import os, stat
from tobytes import tobytes
from tobase64 import tobase64
from savesync import savesync
from subprocessrun import subprocessrun

def sslutils_x509_dertopem(x = ""):
        """
        Conversion from DER to PEM format
        XXX TODO - remove dependency on openssl
        """
        certificate_header = "BEGIN CERTIFICATE"
        if isinstance(x, bytes):
                certificate_header = b"BEGIN CERTIFICATE"
        if x.find(certificate_header) != -1:
                return x

        cmd = ['openssl', 'x509', '-inform', 'der', '-outform', 'pem']
        p = subprocess.Popen(cmd, stdout = subprocess.PIPE, stdin = subprocess.PIPE)
        ret = p.communicate(x)[0]
        if (p.returncode != 0):
                raise Exception("%s: failed" % (" ".join(cmd)))
        return ret

def sslutils_x509_pemtoder(x = ""):
        """
        Conversion from PEM to DER format
        XXX TODO - remove dependency on openssl
        """

        certificate_header = "BEGIN CERTIFICATE"
        if isinstance(x, bytes):
                certificate_header = b"BEGIN CERTIFICATE"
        if x.find(certificate_header) != -1:
                return x

        cmd = ['openssl', 'x509', '-inform', 'pem', '-outform', 'der']
        p = subprocess.Popen(cmd, stdout = subprocess.PIPE, stdin = subprocess.PIPE)
        ret = p.communicate(x)[0]
        if (p.returncode != 0):
                raise Exception("%s: failed" % (" ".join(cmd)))
        return ret


def sslutils_x509_pemtotext(x = ""):
        """
        Conversion from PEM format to text form
        XXX TODO - remove dependency on openssl
        """

        cmd = ['openssl', 'x509', '-inform', 'pem', '-noout', '-text']
        p = subprocess.Popen(cmd, stdout = subprocess.PIPE, stdin = subprocess.PIPE)
        ret = p.communicate(x)[0]
        if (p.returncode != 0):
                raise Exception("%s: failed" % (" ".join(cmd)))
        return ret

def _sslutils_req(domains = [], cfg = "", key = "", ecdsa = False):
        """
        Create new RSA key and simple CSR request.
        XXX TODO - remove dependency on openssl
        """

        if len(domains) == 0:
                raise Exception("no domains")

        i = 1
        subject = "/CN="
        config  = "[req]\n"
        config += "distinguished_name = req_distinguished_name\n"
        config += "req_extensions=v3_req\n"
        config += "[req_distinguished_name]\n"
        config += "[v3_req]\n"
        config += "basicConstraints=CA:FALSE\n"
        config += "keyUsage=nonRepudiation,digitalSignature,keyEncipherment\n"
        config += "subjectAltName=@alt_names\n"
        config += "[alt_names]\n"

        for domain in domains:
                if domain.find('/') >= 0:
                        raise Exception("bad domain %s" % (domain))
                if domain.find('*') >= 0:
                        raise Exception("bad domain %s" % (domain))
                config += "DNS.%d=%s\n" % (i, domain)
                if i == 1:
                        subject += domain
                i += 1

        savesync(cfg, tobytes(config))

        if ecdsa:
                #create ECDSA key
                _sslutils_ecdsa_makekey(key)
        else:
                #create RSA key
                _sslutils_rsa_makekey(key, "", 2048)

        #create request
        cmd = ['openssl', 'req', '-sha256', '-nodes', '-subj', subject, '-key', key, '-new', '-outform', 'der', '-config', cfg]
        p = subprocess.Popen(cmd, stdout = subprocess.PIPE, stdin = subprocess.PIPE)
        ret = p.communicate('')[0]
        if (p.returncode != 0):
                raise Exception("%s: failed" % (" ".join(cmd)))
        return ret

def sslutils_req(domains = [], cfg = "", key = "", ecdsa = False):
        """
        SECURITY: Secret key operation is isolated in separate process.
        """

        return subprocessrun(_sslutils_req, domains, cfg, key, ecdsa)



def _sslutils_rsa_signsha256(key, data):
        """
        Sign SHA256('data') using RSA key 'key'.
        XXX TODO - remove dependency on openssl
        """

        cmd = ['openssl', 'dgst', '-sha256', '-sign', key]
        p = subprocess.Popen(cmd, stdout = subprocess.PIPE, stdin = subprocess.PIPE)
        ret = p.communicate(data)[0]
        if (p.returncode != 0):
                raise Exception("%s: failed" % (" ".join(cmd)))
        return ret

def sslutils_rsa_signsha256(key, data):
        """
        SECURITY: Secret key operation is isolated in separate process.
        """

        return subprocessrun(_sslutils_rsa_signsha256, key, data)


def _sslutils_rsa_makekey(sk = "", pk = "", size = 2048):
        """
        Create RSA key
        XXX TODO - remove dependency on openssl
        """

        cmd = ['openssl', 'genrsa']
        p = subprocess.Popen(cmd, stdout = subprocess.PIPE, stdin = subprocess.PIPE, stderr = subprocess.PIPE)
        data = p.communicate("")[0]
        if (p.returncode != 0):
                raise Exception("%s: failed" % (" ".join(cmd)))
        f = open(sk, "wb")
        os.fchmod(f.fileno(), stat.S_IRUSR | stat.S_IWUSR)
        f.write(data)
        os.fsync(f.fileno())
        f.close()

        if not pk:
                return

        cmd = ['openssl', 'rsa', '-in', sk, '-pubout']
        p = subprocess.Popen(cmd, stdout = subprocess.PIPE, stdin = subprocess.PIPE, stderr = subprocess.PIPE)
        data = p.communicate("")[0]
        if (p.returncode != 0):
                raise Exception("%s: failed" % (" ".join(cmd)))
        f = open(pk, "wb")
        os.fchmod(f.fileno(), stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)
        f.write(data)
        os.fsync(f.fileno())
        f.close()

def _sslutils_ecdsa_makekey(sk = ""):
        """
        Create ECDSA key
        XXX TODO - remove dependency on openssl
        """

        cmd = ['openssl', 'ecparam', '-name', 'prime256v1', '-genkey', '-rand', '/dev/urandom']
        p = subprocess.Popen(cmd, stdout = subprocess.PIPE, stdin = subprocess.PIPE, stderr = subprocess.PIPE)
        data = p.communicate("")[0]
        if (p.returncode != 0):
                raise Exception("%s: failed" % (" ".join(cmd)))
        f = open(sk, "wb")
        os.fchmod(f.fileno(), stat.S_IRUSR | stat.S_IWUSR)
        f.write(data)
        os.fsync(f.fileno())
        f.close()



def sslutils_rsa_makekey(sk = "", pk = "", size = 2048):
        """
        SECURITY: Secret key operation is isolated in separate process.
        """

        return subprocessrun(_sslutils_rsa_makekey, sk, pk, size)


def sslutils_rsa_getpk(pkfn):
        """
        Import RSA public key and return (exponent, modulus)
        XXX temporary dirty HACK XXX
        XXX TODO - remove dependency on openssl
        """

        cmd = ['openssl', 'rsa', '-modulus', '-text', '-pubin', '-noout', '-in', pkfn]
        p = subprocess.Popen(cmd, stdout = subprocess.PIPE, stdin = subprocess.PIPE)
        data = p.communicate('')[0]
        if (p.returncode != 0):
                raise Exception("%s: failed" % (" ".join(cmd)))

        for line in tostr(data).split('\n'):
                if len(line) < 10:
                        continue
                if line[0:9] == "Exponent:":
                        exponent = line.split(')')[0].split('(')[1][2:]
                if line[0:8] == "Modulus=":
                        modulus = line[8:]

        if (len(exponent) % 2):
                exponent = "0" + exponent

        exponent = binascii.unhexlify(exponent)
        modulus = binascii.unhexlify(modulus)
        return (exponent, modulus)
