# coding=utf-8
import requests
import json
import logging
import sys


def send_post(url, data, headers):
    print(url,data,headers)
    result = requests.post(url, data=data, headers=headers)
    return result
    # logging.info res


def send_get(url, headers):
    result = requests.get(url=url, headers=headers)
    return result


def send_put(url, data, headers):
    result = requests.put(url, data=data, headers=headers)
    return result


def send_delete(url, data, headers):
    result = requests.put(url, data=data, headers=headers)
    return result


def request_main(method, url=None, uri=None, data=None, headers=None):
    """
    :description：根据方法名，执行对应的请求方法
    :param method:
    :param url:
    :param data:
    :param headers:
    :return:
    """
    # result = None
    # print(data)
    # print(type(data))
    # data = json.dumps(data)
    # print(data)
    # print(type(data))
    url = url + uri
    headers = header()
    if isinstance(data, dict):
        data = json.dumps(data)
        if method == 'post_method':
            result = send_post(url, data, headers)
            return result
        elif method == 'get_method':
            result = send_get(url, headers)
            return result
        elif method == 'put_method':
            result = send_put(url, data, headers)
            return result
        elif method == 'delete_method':
            result = send_delete(url, headers)
            return result
    else:
        if method == 'post_method':
            result = send_post(url, data, headers)
            return result
        elif method == 'get_method':
            result = send_get(url, headers)
            return result
        elif method == 'put_method':
            result = send_put(url, data, headers)
            return result
        elif method == 'delete_method':
            result = send_delete(url, headers)
            return result

def header(**kwargs):
    """
    :description：获取header，返回值为dict
    :author:
    :param kwargs:
    :return: headers
    """
    headers = {
        'Content-Type': "application/json;charset=UTF-8",
        'cache-control': "no-cache",
    }

    if kwargs == {}:
        headers = headers
    else:
        headers.update(kwargs)  # 向字典中添加字典
        # 遍历字典获取key,作用同上
        # for key in kwargs:
        #     headers[key] = kwargs[key]
        logging.info("headers:{}".format(headers))
    return headers


def convert_json(data):
    try:
        if isinstance(data, dict):
            data = json.dumps(data)
    except ValueError:
        data = json.loads(data)
        data = json.dumps(data)
    return data


if __name__ == "__main__":
    data = {"address": "上海市嘉定区安亭镇", "age": 0, "avatar": "http://www.bao.com/ddf.jpg", "birthday": 1528712906000,
            "brand": "SKD", "cityCode": "string", "credentialsType": "ID_CARD", "districtCode": "string",
            "email": "ccc@qq.com", "idNumber": "string", "mobile": 18583920601, "name": "小明", "nickname": "小明",
            "password": "asdfqerewq1234", "provinceCode": "string", "sex": 0, "signature": "string",
            "userName": 18583920601}
    print(type(data))
    print(data)
    # data = json.dumps(data)
    # print(type(data))
    # header = header()
    # print(type(header))
    # res = request_main("POST01",
    #                    "http://ne-api-gateway-80-nx-ice.nx-cloud.tx/user-core-data-service/ucd_core_data/api/v1/user",
    #                    data,
    #                    header)
    # print(res.status_code)
    # print(res.text)
