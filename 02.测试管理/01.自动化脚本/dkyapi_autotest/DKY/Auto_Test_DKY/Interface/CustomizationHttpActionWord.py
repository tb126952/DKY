# coding=utf-8
import requests
import logging
import RequestsLibrary
from RequestsLibrary import RequestsKeywords
import time
import robot
# from bson.objectid import ObjectId
from robot.api import logger
import json


# import pymongo
# import requests


class CustomizationHttpActionWord(RequestsKeywords):
    """
        Customization http action word base requests lib
    """
    ROBOT_LIBRARY_SCOPE = 'TEST CASE'

    def __init__(self):
        RequestsKeywords.__init__(self)
        self.header = {}

    def reset_header(self):
        self.header = {}

    def set_header_item(self, key, value):
        self.header[key] = value

    def set_param(self):
        pass

    def set_client_side_certificates(self, session, clientCert, clientKey):
        session.cert = (clientCert, clientKey)
        return session

    def read_xml_file_info(self, filepath):
        file_obj = open(filepath)
        ret_info = file_obj.read()
        file_obj.close()

        return ret_info

    def create_session_a(self, url, headers={}, cookies=None,
                         auth=None, timeout=None, proxies=None,
                         verify=False, debug=0, max_retries=3, backoff_factor=0.10, disable_warnings=0):
        # print 'create_self_session'
        alias = str(time.time()) + '_' + url
        # print alias
        session = self.create_session(alias, url, self.header, cookies, auth, timeout, proxies, verify, debug,
                                      max_retries, backoff_factor, disable_warnings)
        return session

    def get_request_a(self, session, uri, headers=None, json=None, params=None, allow_redirects=None, timeout=None):
        print 'get_request'
        redir = True if allow_redirects is None else allow_redirects

        response = self._get_request(session, uri, params, headers, json, redir, timeout)

        logger.info('Get Request using : session=%s, uri=%s, headers=%s, params=%s, json=%s' % (
            session, uri, headers, params, json))

        return response

    def post_request_a(self, session, uri, data=None, params=None, headers=None, files=None, allow_redirects=None,
                       timeout=None):
        print files
        # print 'post_requst'
        print(type(params))
        print(params)
        print(uri)
        if not files:
            data = self._format_data_according_to_header(session, data, headers)
        redir = True if allow_redirects is None else allow_redirects

        response = self._body_request("post", session, uri, data, params, files, headers, redir, timeout)
        dataStr = self._format_data_to_log_string_according_to_header(data, headers)

        logger.info('Post Request using : session=%s, uri=%s, data=%s, headers=%s, files=%s, allow_redirects=%s '
                    % (session, uri, dataStr, headers, files, redir))

        return response

    def put_request_a(self, session, uri, data=None, params=None, files=None, headers=None, allow_redirects=None,
                      timeout=None):

        data = self._format_data_according_to_header(session, data, headers)
        redir = True if allow_redirects is None else allow_redirects

        response = self._body_request("put", session, uri, data, params, files, headers, redir, timeout)

        if isinstance(data, bytes):
            data = data.decode('utf-8')
        logger.info('Put Request using : session=%s, uri=%s, data=%s, \
                    headers=%s, allow_redirects=%s ' % (session, uri, data, headers, redir))

        return response

    def patch_request_a(self, session, uri, data=None, params=None, headers=None, files=None, allow_redirects=None,
                        timeout=None):

        data = self._format_data_according_to_header(session, data, headers)
        redir = True if allow_redirects is None else allow_redirects

        response = self._body_request("patch", session, uri, data, params, files, headers, redir, timeout)

        if isinstance(data, bytes):
            data = data.decode('utf-8')
        logger.info('Patch Request using : session=%s, uri=%s, data=%s, \
                    headers=%s, files=%s, allow_redirects=%s '
                    % (session, uri, data, headers, files, redir))

        return response

    def delete_request_a(self, session, uri, data=(), params=None, headers=None, allow_redirects=None, timeout=None):

        data = self._format_data_according_to_header(session, data, headers)
        redir = True if allow_redirects is None else allow_redirects

        response = self._delete_request(
            session, uri, data, params, headers, redir, timeout)

        if isinstance(data, bytes):
            data = data.decode('utf-8')
        logger.info('Delete Request using : session=%s, uri=%s, data=%s, \
                    headers=%s, allow_redirects=%s ' % (session, uri, data, headers, redir))

        return response

    def head_request_a(self, session, uri, headers=None, allow_redirects=None, timeout=None):

        redir = False if allow_redirects is None else allow_redirects
        response = self._head_request(session, uri, headers, redir, timeout)
        logger.info('Head Request using : session=%s, uri=%s, headers=%s, \
        allow_redirects=%s ' % (session, uri, headers, redir))

        return response

    def options_request_a(self, session, uri, headers=None, allow_redirects=None, timeout=None):

        redir = True if allow_redirects is None else allow_redirects
        response = self._options_request(session, uri, headers, redir, timeout)
        logger.info(
            'Options Request using : session=%s, uri=%s, headers=%s, allow_redirects=%s ' %
            (session, uri, headers, redir))

        return response

    def post2_request_a(self, session, uri, data=None, params=None, headers=None, files=None, allow_redirects=None,
                        timeout=None):
        # print files
        # # print 'post_requst'
        # print(type(data))
        # print(data)
        # if not files:
        #     data = self._format_data_according_to_header(session, data, headers)
        redir = True if allow_redirects is None else allow_redirects
        response = self._body_request("post", session, uri, data, params, files, headers, redir, timeout)
        dataStr = self._format_data_to_log_string_according_to_header(data, headers)

        logger.info('Post Request using : session=%s, uri=%s, data=%s, headers=%s, files=%s, allow_redirects=%s '
                    % (session, uri, dataStr, headers, files, redir))
        return response

if __name__ == '__main__':
    # file1 = open("./test_files/csr1.txt", "rb")
    # print file1.read()
    lib = CustomizationHttpActionWord()
    # lib.set_header_item("Content-Type", "multipart/form-data")
    # lib.set_header_item("User-Agent", "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36")
    # lib.set_header_item("X-Requested-With", "XMLHttpRequest")
    # lib.set_header_item("Accept-Language", "zh-CN,zh;q=0.9")
    # lib.set_header_item("X-Requested-With", "XMLHttpRequest")

    url_ip_port = 'http://172.16.88.15:9015'
    url_uri = "/clientCertificate/signCertificate"

    params = {"validDays": "10"}
    # url_ip_port = 'http://httpbin.org'
    # url_uri = "/post"

    # "/clientCertificate/signCertificate" 这个接口,fields名称必是files
    files = [
        ("files", ("csr1.txt", open("csr1.txt", "rb"))),
        ("files", ("csr2.txt", open("csr2.txt", "rb"))),
        ("files", ("csr3.txt", open("csr3.txt", "rb")))
    ]

    # s = lib.create_session_a(url_ip_port)
    # r = lib.post_request_a(s, url_uri, files=files, params=params)
    # s = r.text
    # s_j = json.loads(s)
    # print json.dumps(s_j, indent=2)

    requestStr = []
    requestStr.append("""-----BEGIN CERTIFICATE REQUEST-----
MIIC0DCCAbgCAQAwgYoxCzAJBgNVBAYTAkNOMRAwDgYDVQQIDAdzaWNodWFuMRAw
DgYDVQQHDAdjaGVuZ2R1MRAwDgYDVQQKDAdvcmcvY29tMQswCQYDVQQLDAJJVDEY
MBYGA1UEAwwPd3d3LmV4YW1wbGUuY29tMR4wHAYJKoZIhvcNAQkBFg82MzgzODg5
M0BxcS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDF/rhqDD6f
usx6pDuZkQZxefiY+TZTFAWaBU6b8Eyatuxm5efaKbR5ZmtqtVERCyK7UA2KESgi
Yhi7SosAs4+Rjl1VsRUYRd3nPl70JXz2BvtWwHrJffmlQO7RpZNJYB3bsJR+BK8j
HSJeeXahiCqYUA+63zLhTPBpqMrTxJmeZ5rYm6bZHXzWqFS/wFc8RjexJ2gzGKzG
T7pnBEANjfH9a4JudxsoIVb3l2uUyxWG134xz/ygosLXE4AbpDGE+ZEYdHpqgvu2
rmZiF+ZxTrazyK+ssl8EFcgeuWimR48iUz3SxEb7FEWZ/ZYJRBxYqjvvKZO+Xfob
nmTSEKa3vytdAgMBAAGgADANBgkqhkiG9w0BAQsFAAOCAQEAr3z4DW91fGRcpMbx
O8CEeR1y4Gwb+LKNZzyxaDWHod5f9gI/2NND0if/StYYdQ8wUDTnEr0askOWW7Wc
PtAgOXHCsmhCk8ATQ2qQQLPbrxgGSCu4SMSx4x7vqOHtXTDuWulwb/boE5xH/Wi7
eXT2U5JAJqL/68YZibYVFUfvsBwy9SRlypkprQkB2ojBNDA+pkeX85Bh62DMQOrY
+R0kXJiTWdbgPFgPeCVd/Fo2EpODJqB7iHKRupr6vootxTOjo1+VqkniWgxlCsS2
XqijnaEdCAaMFZLolDo7gOXX8EvABrwaHn3jOmY2x1uVxJsnjucubhw9I/4OnyHw
/7lCxQ==
-----END CERTIFICATE REQUEST-----""")
    requestStr.append("""-----BEGIN CERTIFICATE REQUEST-----
MIICuzCCAaMCAQAwdjELMAkGA1UEBhMCQ04xCzAJBgNVBAgMAlNDMQswCQYDVQQH
DAJDRDEMMAoGA1UECgwDb3JnMQswCQYDVQQLDAJJVDESMBAGA1UEAwwJZXhhbXBs
ZTAyMR4wHAYJKoZIhvcNAQkBFg82MzgzODg5M0BxcS5jb20wggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQDRtk3Dk3Gh3TQBgJipn3wbfos0ou8RIjpf6+hU
KbmU/3ccGqRBJI6e4eCIbHjUaltuDxM19CdHVGbbNgOEbz/pJz0AUYK7mMiAC0M7
/bElCvJmupR5fzEQMNGXWtQF66MyQhJ3ffZIa1eP82vGuQv24BOpY2ybtB8NBd2C
qOJ2U3AEWH2PwVfh/vUVRKAuPLHXIlbQBkkHfjnU1/0VoX4zuKB/4fbOT4/F9riP
nRwBqzSqH7cudXgwJT9jpWeW5P0n4WSJ1T27qjN/tmEux6wIKg+8UE8ohqKA/zIU
teVQPNmhtwPGSyBrTwjEvsNj2gEC3jhIlYJ0me7mqGs5l58FAgMBAAGgADANBgkq
hkiG9w0BAQsFAAOCAQEAXfsEFlP4e+YAN1rOnm/Vq9vSWjAI5UEkON5d7FgLMN69
XfARphHNWToMLZmxx9vKqalEk8bpByjd4VzQ6NhAUSN+RfHyrdnr9Td49SGaU/QZ
YYyT5YQ6BWk3CYKhxTGngWhwDP3K6JJFogBMMoko1q80XwQ/MhBPrfsD143J7PEZ
ORUeYWIBIaymY/CUYYkQmfdDk+Vh115cx4wffQBhJPqlhtdtIJ2fHT98vRLR4+h3
1qDS0DhCIUXzAHWBSfxZFcdJDYVBDCs0ogvAM9fZ4StZ6E3pMsWDHPC+XWU/lYmJ
R9E8+o2g6cGko+55QbsMpfS8pA+Hf5cLcMtp0t0YrQ==
-----END CERTIFICATE REQUEST-----
""")
    print requestStr

    # requestStr =json.dumps(requestStr)
    print requestStr
    url_ip_port = 'http://172.16.88.15:9015'
    url_uri = "/clientCertificate/signCertificateByCsrStr"
    # data = {'requestStr': requestStr}
    data = requestStr
    print data
    lib.set_header_item("Content-Type", "application/json")
    lib.set_header_item("Accept", "application/json")
    s = lib.create_session_a(url_ip_port)
    r = lib.post_request_a(s, url_uri, data=data)
    s = r.text
    s_j = json.loads(s)
    print json.dumps(s_j, indent=2)

    # url = url_ip_port + url_uri
    # r = requests.post(url, data=files)
    # print r.text

    # url = 'http://httpbin.org/post'
    # r = requests.post(url, files=files1)

    #
    # print r.text

    # header = {
    #             "Content-Type": "application/json"
    #           }
    # lib.set_header_item("Content-Type", "application/json")
    # lib.set_header_item("ice-auth-appkey", "application/json")
    # lib.set_header_item("ice-auth-timestamp", "application/json")
    # lib.set_header_item("ice-auth-token", "")
    # lib.set_header_item("ice-auth-sign", "application/json")
    #
    #
    # url_ip_port ='http://172.16.88.15:8999'
    # url_uri = "/dashboard-api/signin"
    # url = url_ip_port + url_uri
    #
    # data_json ={}
    # data_json['username'] = 'admin'
    # data_json['password'] = 'Admin$123'
    #
    # s = lib.create_session_a(url_ip_port)
    #
    # reponse = lib.post_request_a(s, url_uri, data_json)
    #
    # print reponse.text

#     string1 = """
#     {
#         "command": "CMD_UP_REGISTER",
#         "body": {
#             "keySize": 18,
#             "publicKey": "1234567890ABCDEFGH",
#             "md5Data": "11112222333344445555666677778888"
#         },
#         "msgSize": 83,
#         "sn": "TBOX000000000001",
#         "encryptionModel": "NONE",
#         "seqNum": 2,
#         "checkSum": 36
#     }
# """
# data = json.loads(string1)
# print data
#
# print lib.post_request_a(s, "/register", data).text
# print lib.delete_request_a(s, '/?').text
# print lib.put_request_a(s, '/？').text
# RedisFuncObj = RedisLibraryKeywords()
# IP = "10.10.10.10"
# RedisConnect = RedisFuncObj.connect_to_redis(IP)


# a = ObjectId()
# print a
#
# json_1= {}
# json_1['_id'] = a
