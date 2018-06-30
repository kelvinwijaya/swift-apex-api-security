//
//  AuthorizationTokenTest.swift
//  ApexApiSecurityTests
//
//  Created by Kelvin Wijaya on 30/6/18.
//  Copyright © 2018 GovTech. All rights reserved.
//

import XCTest
@testable import ApexApiSecurity

class AuthorizationTokenTest: XCTestCase {
    
//    let privateCertNameP12 = getLocalPath("certificates/ssc.alpha.example.com.p12")
//    try SecurityUtil().getPrivateKeyFromP12(p12KeystoreName: strFileName, p12Key: strSecret)
    let fileName = "ssc.alpha.example.com"
    let alias = "alpha"
    let liveTest = false
    let realm = "http://example.api.test/token"
    let authPrefixL1 = "Apex_l1_ig"
    let authPrefixL2 = "Apex_l2_ig"
    let httpMethod = "get"
    let url = "https://example.lab:443/api/v1/rest/level1/in-in/?ap=裕廊坊%20心邻坊"
    let appId = "example-4Swyn7qwKeO32EXdH1dKTeIQ"
    let secret = "ffef0c5087f8dc24a3f122e1e2040cdeb5f72c73"
    let nonce = "-5816789581922453013"
    let timestamp = "1502199514462"
    let passphrase = "passwordp12"

    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }

    func testL1_Basic_Test() {
        let expectedToken = "Apex_l1_ig realm=\"http://example.api.test/token\", apex_l1_ig_app_id=\"example-4Swyn7qwKeO32EXdH1dKTeIQ\", apex_l1_ig_nonce=\"-5816789581922453013\", apex_l1_ig_signature=\"DoARux+dvq/A2ioQfRybInAQ4Lt4DTAI6DrDJRx7zcs=\", apex_l1_ig_signature_method=\"HMACSHA256\", apex_l1_ig_timestamp=\"1502199514462\", apex_l1_ig_version=\"1.0\""
        do {
            let authorizationToken = try SecurityUtil().getToken(strRealm: realm, strAppId: appId, strSecret: secret, strURLNoPortNbr: url, strAuthPrefix: authPrefixL1, strHttpMethod: httpMethod, strNonce: nonce, strTimeStamp: timestamp, formList: [:], strPassword: nil, strAlias: alias, strFileName: nil)
            debugPrint("expectedToken(L1): " + expectedToken)
            debugPrint("authorizationToken(L1): " + authorizationToken)
            XCTAssertEqual(expectedToken, authorizationToken)
        } catch let error {
            print(error)
            XCTFail("Should not throw any exception during test execution")
        }
        
    }
    
    func testL2_Basic_Test() {
        let expectedToken = "Apex_l2_ig realm=\"http://example.api.test/token\", apex_l2_ig_app_id=\"example-4Swyn7qwKeO32EXdH1dKTeIQ\", apex_l2_ig_nonce=\"-5816789581922453013\", apex_l2_ig_signature=\"Za7B8MaOlGZjc8DTEh9HwhcL+5DiiuTMy+s0bQ8/lajy1Ug64gPCyNEbcYkD/XBEHFyg6vlY9/J85Y+Ui6DeYbXmUFnQjDWdOKf13xJvpsnAQgOqWi+LSc0+gy3pvsQ50nyES3E04vb3RvGwd7UC6SyBhmQ5P8Mz0UUgWBX6L6N3n+xergTg3DKWEPyQih+dqN3DkOmNE8fstAp+HOqiVq2OBxNeg9x5Kp0tq2vka7cC86zdYSNhsQR+D7hC+S1NPninWvdxUF1EwrPrEZYSYXka0Md1XFVjaL6b0htcFo6LxwJ8X6wsOqS4g4qmrAadwm7fITZLxcI0Zdaz7dRw9UFUsGWEVPG8MQztVXleimDxYvorLKTD5bhWGHe+XNwyL+IdR7ErooOHP9pTslJ7yBEmsePTRIAL//h0AEXaBN4pCmBPJnVtYtUWdQsUq/iv/4FLtWvOK77EReAtq3uqndJfGInXUMESqS4PzGDajTZj+oDP7xektLh7umELQBnSKNuv3BR9H63sf+Z9mZQ1531LYEmQWR8p3LCP8E0DcROo0OP1gcE76N9Z1HKLtJjLYDRyQRUQMM2FlJRkb3sy2g60yNThkPprzohBvHowCRFs02tlkyBbOuKC2cV9hwSz8eMqhUTzNn/WMi2Dr2V7iTJtyJHT9kdebVY2Cvnlt5I=\", apex_l2_ig_signature_method=\"SHA256withRSA\", apex_l2_ig_timestamp=\"1502199514462\", apex_l2_ig_version=\"1.0\""
        do {
            let authorizationToken = try SecurityUtil().getToken(strRealm: realm, strAppId: appId, strSecret: nil, strURLNoPortNbr: url, strAuthPrefix: authPrefixL2, strHttpMethod: httpMethod, strNonce: nonce, strTimeStamp: timestamp, formList: [:], strPassword: passphrase, strAlias: alias, strFileName: fileName)
            debugPrint("expectedToken(L2): " + expectedToken)
            debugPrint("authorizationToken(L2): " + authorizationToken)
            XCTAssertEqual(expectedToken, authorizationToken)
        } catch let error {
            print(error)
            XCTFail("Should not throw any exception during test execution")
        }
        
    }
    
}
