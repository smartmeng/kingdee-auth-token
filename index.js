const axios = require('axios')
const crypto = require('crypto')
const _ = require('lodash')

let sha256AndBase64 = function (key, secret) {
    let sha256 = crypto.createHmac('sha256', secret)
    sha256.update(key)
    let hex = sha256.digest('hex')
    let base64 = Buffer.from(hex, 'utf8').toString('base64')
    return base64
}

let randomInt = function () {
    let max = 9999999999999999
    let min = 1000000000000000
    return Math.floor(Math.random() * (max - min + 1)) + min
}

let getQueryString = function (queryString) {
    let queryStrings = queryString.split('&')
    queryStrings = queryStrings.sort()
    let queryStringResult = ''

    queryStrings.map(item => {
        strArr = item.split('=')
        key = strArr[0]
        value = strArr[1]
        if (queryStringResult.length > 0)
            queryStringResult = queryStringResult + "&" + encodeURIComponent(key) + "=" + encodeURIComponent(value)
        else
            queryStringResult = encodeURIComponent(key) + "=" + encodeURIComponent(value)
    })
    // console.log("queryStringResult", queryStringResult)

    return queryStringResult
}

let getSignature = function ({ path, method, headers, queryString, clientSecret }) {
    path = encodeURIComponent(path)

    queryString = getQueryString(queryString)
    // console.log("queryString", queryString)

    let headersString = ''
    let strArr = headers['X-Api-SignHeaders'].split(',')
    strArr = strArr.sort()
    strArr.map(item => {
        headersString = headersString + _.toLower(item) + ":" + headers[item] + "\n"
    })

    let signString = method + "\n"
        + path + "\n"
        + queryString + "\n"
        + headersString
    // console.log("signString", signString)

    let signature = sha256AndBase64(signString, clientSecret)
    // console.log("signature", signature)

    return signature
}

let getKingdeeAuthToken = async function ({ appKey, appSecret, clientID, clientSecret }) {
    let options = {
        path: '/jdyconnector/app_management/kingdee_auth_token',
        method: 'GET',
        headers: {
            "X-Api-ClientID": clientID,
            "X-Api-Auth-Version": "2.0",
            "X-Api-TimeStamp": Date.now(),
            "X-Api-SignHeaders": "X-Api-TimeStamp,X-Api-Nonce",
            "X-Api-Nonce": randomInt(),
            "X-Api-Signature": ""
        },
        queryString: "app_key=" + encodeURIComponent(appKey) + "&" + "app_signature=" + encodeURIComponent(sha256AndBase64(appKey, appSecret)),
        clientSecret: clientSecret
    }

    options.headers['X-Api-Signature'] = getSignature(options)

    let result = await axios({
        "url": "https://api.kingdee.com/jdyconnector/app_management/kingdee_auth_token" + "?" + options.queryString,
        "method": "get",
        "headers": options.headers
    })
    return result.data
}

module.exports = getKingdeeAuthToken;