//
//  L1SignatureTest.swift
//  ApexApiSecurityTests
//
//  Created by Kelvin Wijaya on 19/6/18.
//  Copyright © 2018 GovTech. All rights reserved.
//

import XCTest
@testable import ApexApiSecurity

class L1SignatureTest: XCTestCase {
    
    let strBaseString = "message"
    let strSecret = "secret"
    let strExpectedResult = "i19IcCmVwVmMVz2x4hhmqbgl1KeU0WnXBgoDYFeWNgs="
    let strCommonDigest = "CC_SHA256"
    
    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }
    
    func testL1_Verify_Signature_Test() throws
    {
        XCTAssertTrue((try SecurityUtil().verifyL1Signature(signature:strExpectedResult, secret:strSecret, baseString:strBaseString, commonDigest:strCommonDigest))!)
    }
    
    func testL1_Verify_Signature_With_Wrong_BaseString_Test() throws
    {
        XCTAssertFalse((try SecurityUtil().verifyL1Signature(signature:strExpectedResult, secret:strSecret, baseString: strBaseString + "x", commonDigest:strCommonDigest))!)
    }
    
}
