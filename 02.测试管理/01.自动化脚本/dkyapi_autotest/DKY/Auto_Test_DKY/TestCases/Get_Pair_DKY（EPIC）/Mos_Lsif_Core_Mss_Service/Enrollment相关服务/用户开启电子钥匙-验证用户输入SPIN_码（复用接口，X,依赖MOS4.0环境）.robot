*** Settings ***
Library           ../../../../Interface/CustomizationHttpActionWord.py
Library           HttpLibrary.HTTP
Resource          ../../../../Commonkeywords/CommonKeywords_HTTP.txt
Resource          ../../../../Resources/ServiceResources/mos_lsif_core_mss_service_Resources.txt

*** Test Cases ***
验证输入正确的SPIN码，校验成功
    #获取用户ID以及VIN码
    ${mosUserId}    Set Variable    50388
    ${vin}    Set Variable    BVWTDMW0B19061133
    #将参数转换为JSON格式
    ${data_json}    TO JSON    {"spin": 1234 }
    #验证SPIN码
    ${response_text}    ${response_tatus_code}    common_put_method    ${URL_mos-lsif-core-mss}    @{URI_mos-lsif-core-mss}[0]/${mosUserId}/vehicle/${vin}/spin/validated    ${data_json}
    Should Contain    ${response_text}    "code":"000000"
    Should Contain    ${response_text}    "description":"SUCCESS"
    Should Contain    ${response_text}    "data":true
    #状态码校验成功
    should be equal As integers    ${response_tatus_code}    200
    ${description}    Get Json Value    ${response_text}    /description
    Should Be Equal As Strings    ${description}    "SUCCESS"

验证SPIN码输入为空，校验失败
    #将参数转换为JSON格式
    ${data_json}    TO JSON    {"spin":""}
    #验证SPIN码输入为空
    ${response_text}    ${response_tatus_code}    common_put_method    ${URL_mos-lsif-core-mss}    @{URI_mos-lsif-core-mss}[0]/${mosUserId}/vehicle/${vin}/spin/validated    ${data_json}
    Should Contain    ${response_text}    "code":"135002"
    Should Contain    ${response_text}    "description":"参数错误, spin应为四位数字"
    #状态码校验失败
    should be equal As integers    ${response_tatus_code}    400
    ${description}    Get Json Value    ${response_text}    /description
    Should Be Equal As Strings    ${description}    "参数错误, spin应为四位数字"

SPIN码输入不支持的字符，校验失败
    #将参数转换为JSON格式
    ${data_json}    TO JSON    {"spin": "123!"}
    #SPIN码中存在非限制字符
    ${response_text}    ${response_tatus_code}    common_put_method    ${url}    @{enrollment-service}[0]    ${data_json}
    Comment    Comment    Should Contain    ${response_text}    "description":"参数错误, spin应为四位数字"
    Comment    Comment    #状态码校验成功
    Comment    Comment    should be equal As integers    ${response_tatus_code}    400
    Comment    Comment    ${description}    Get Json Value    ${response_text}    /description
    Comment    Comment    Should Be Equal As Strings    ${description}    "参数错误, spin应为四位数字"

验证输入不存在的SPIN码，验证失败
    #获取用户ID以及VIN码
    ${mosUserId}    Set Variable    50388
    ${vin}    Set Variable    BVWTDMW0B19061133
    #将参数转换为JSON格式
    ${data_json}    TO JSON    {"spin": 1234 }
    #验证SPIN码
    ${response_text}    ${response_tatus_code}    common_put_method    ${URL_mos-lsif-core-mss}    @{URI_mos-lsif-core-mss}[0]/${mosUserId}/vehicle/${vin}/spin/validated    ${data_json}
    Should Contain    ${response_text}    "code":"000000"
    Should Contain    ${response_text}    "description":"SUCCESS"
    Should Contain    ${response_text}    "data":true
    #状态码校验成功
    should be equal As integers    ${response_tatus_code}    200
    ${description}    Get Json Value    ${response_text}    /description
    Should Be Equal As Strings    ${description}    "SUCCESS"
