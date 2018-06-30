//
//  BaseStringTest.swift
//  ApexApiSecurityTests
//
//  Created by Kelvin Wijaya on 19/6/18.
//  Copyright © 2018 GovTech. All rights reserved.
//

import XCTest
@testable import ApexApiSecurity

class BaseStringTest: XCTestCase {
    
    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }
    
    func testBaseString_Basic_Test() throws {
        let url = "https://example.lab:443/api/v1/rest/level1/in-in/?ap=裕廊坊%20心邻坊"
        let expectedBaseString = "GET&https://example.lab/api/v1/rest/level1/in-in/&ap=裕廊坊 心邻坊&apex_l1_ig_app_id=example-4Swyn7qwKeO32EXdH1dKTeIQ&apex_l1_ig_nonce=1355584618267440511&apex_l1_ig_signature_method=HMACSHA256&apex_l1_ig_timestamp=1502175057654&apex_l1_ig_version=1.0"
        
        let baseString = try SecurityUtil().getBaseString(strAppId : "example-4Swyn7qwKeO32EXdH1dKTeIQ",
                                                           strURLNoPortNbr : url,
                                                           strAuthPrefix : "Apex_L1_IG",
                                                           strHttpMethod : "get",
                                                           strSignatureMethod : "HMACSHA256",
                                                           strNonce : "1355584618267440511",
                                                           strTimeStamp : "1502175057654",
                                                           formList : [:])
        print("BaseString[testBaseString_Basic_Test]: " + baseString)
        XCTAssertEqual(expectedBaseString, baseString)
    }
    
    func testBaseString_FormData_Test() throws {
        let url = "https://example.lab:443/api/v1/rest/level1/in-in/?ap=裕廊坊%20心邻坊";
        let expectedBaseString = "POST&https://example.lab/api/v1/rest/level1/in-in/&ap=裕廊坊 心邻坊&apex_l1_ig_app_id=example-4Swyn7qwKeO32EXdH1dKTeIQ&apex_l1_ig_nonce=6584351262900708156&apex_l1_ig_signature_method=HMACSHA256&apex_l1_ig_timestamp=1502184161702&apex_l1_ig_version=1.0&param1=data1"
        
        let form = ["param1": "data1"]
        
        let baseString = try SecurityUtil().getBaseString(strAppId : "example-4Swyn7qwKeO32EXdH1dKTeIQ",
                                                      strURLNoPortNbr : url,
                                                      strAuthPrefix : "Apex_L1_IG",
                                                      strHttpMethod : "post",
                                                      strSignatureMethod : "HMACSHA256",
                                                      strNonce : "6584351262900708156",
                                                      strTimeStamp : "1502184161702",
                                                      formList : form)
        
        print("BaseString[testBaseString_FormData_Test]: " + baseString)
        XCTAssertEqual(expectedBaseString, baseString)
    }
    
    func testBaseString_Invalid_Url_01_Test() {
        let url = "ftp://example.lab:443/api/v1/rest/level1/in-in/?ap=裕廊坊%20心邻坊";
        
        do {
            let baseString = try SecurityUtil().getBaseString(strAppId : "example-4Swyn7qwKeO32EXdH1dKTeIQ",
                                                              strURLNoPortNbr : url,
                                                              strAuthPrefix : "Apex_L1_IG",
                                                              strHttpMethod : "post",
                                                              strSignatureMethod : "HMACSHA256",
                                                              strNonce : "6584351262900708156",
                                                              strTimeStamp : "1502184161702",
                                                              formList : [:])
            print("BaseString[testBaseString_Invalid_Url_01_Test]: " + baseString)
        } catch SecurityUtil.ApiValidationError.ApiUtilException(("Support http and https protocol only.")) {
            XCTAssertTrue(true)
        } catch let error {
            print(error)
            XCTAssertTrue(false)
        }
    }
    
}
