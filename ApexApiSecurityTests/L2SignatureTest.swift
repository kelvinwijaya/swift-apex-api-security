//
//  L2SignatureTest.swift
//  ApexApiSecurityTests
//
//  Created by Kelvin Wijaya on 19/6/18.
//  Copyright © 2018 GovTech. All rights reserved.
//

import XCTest
@testable import ApexApiSecurity

class L2SignatureTest: XCTestCase {
    
    // file name follow unix convention...
    let strFileName = "ssc.alpha.example.com"
    
    //let baseString = "message"
    let strSecret = "passwordp12"
    let alias = "alpha"
    let strCommonDigest = "CC_SHA256"
    
    let message = "Lorem ipsum dolor sit amet, vel nihil senserit ei. Ne quo erat feugait disputationi."
    let expectedSignature = "OsOqG/6hJfGmpCDkqBSZ4netNJDex1lzBYTzGjvjShSFEhJEzAD1zNHKg8Zf9Dve7o9lx3+Yrhrn68nMocgUSOvinhUNF3ttLWw36GzXG7BFJRSIbeUfY3C1vAhkjxmE8oiYoIWctT9qBOL/3GY5QD1H3DiWrb3OLUjy52dsAPmK2P5ofdo8Erd5/0mTxgX+OLMADLJUXq/Aajp1ZIF+djQipPHg0Ms1sNkSHCURxyCjRMKOHNe8DH15lKcApBBjd3XPlb+PGlFl/ffc5Q1ALnAOmsqN6hi8mW+R6Eb0QZsvoRMFSA7kQdWvkCrlWtP5ux+A2Ji/b48SWFSJurVz7yRBhJFDYlvTTCGcgLfwn3TJXa/YbCK05qy307i6X9jnfYaqSYhKC61ExTZYE2SyfagAcWVlSlq3bEovZXllKAwq8Yqyez2EqkOoSzJdj5gmJ1Pb4wN/ss7yYybRSvFShQunj/t6TiQDCJuhghXOfV5Scs/wqjDMWViqrA65YOQHROqAku81NiWFmciVHjk6bNAGsp7iE0p5XnA4z9B41ZVPsxsSXUg4tZvpUrZSpNzlGFBi/uEa1UYcrUd8APzBCvUa75RhZsfxRsCOkpyOEmqoFzg4ngCfegJzBpU5La9e0SOlRvW29p9CK7fS/FZC5YJtP1kucaBN5pX/mxaYeUQ="
    
    //getPrivateKeyLocal(privateCertName, password, alias)
    //let PublicKey publicKey = getPublicKeyLocal(publicCertName)
    
    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }
    
    func testPrivateKeyLocal() {
        do {
            try SecurityUtil().getPrivateKeyFromP12(p12KeystoreName: strFileName, p12Key: strSecret)
        } catch let error {
            print(error)
            XCTFail("Should not throw any exception during test execution")
        }
    }
    
    func testGetPublicKeyLocal() {
        do {
            try SecurityUtil().getPublicCertFromP12(p12KeystoreName: strFileName, p12Key: strSecret)
        } catch let error {
            print(error)
            XCTFail("Should not throw any exception during test execution")
        }
    }
    
    //L2 BaseString Happy Path Test
    func testL2Signature_1() throws {
        let privateKey:SecKey = try SecurityUtil().getPrivateKeyFromP12(p12KeystoreName: strFileName, p12Key: strSecret)
        do {
            let signature = try SecurityUtil().getL2Signature(
                baseString: "GET&https://loadtest-pvt.api.lab/api/v1/rest/level2/in-in/&apex_l2_ig_app_id=loadtest-pvt-4Swyn7qwKeO32EXdH1dKTeIQ&apex_l2_ig_nonce=7798278298637796436&apex_l2_ig_signature_method=SHA256withRSA&apex_l2_ig_timestamp=1502163142423&apex_l2_ig_version=1.0",
                privateKey: privateKey, commonDigest: "CC_SHA256")
            XCTAssertEqual("SEPV4fLkd0QAXHdWwLqJ9QKgerDWrwU6DTeqxFz25GKYkcWfnua23NSxn6nvKEZawSS4glF5Ii3MUd1GQTeez4wRJAIRi01+6HZk58jtH4adYlJ7cW+qHOGz9iOFLJG7023j0S5FaIaxjkKjFx9xncP6CPB3Sd+MbbeinBZc7z8Efe8rNAAi+F0iPLECJq6/UiuRrxxb9VbRSNfvWtkD1NIlIXDabPEcE72Z7KEK9v+Olj36VTbELAxzN2zIrqqNM3PbDaOgJ6gkQ4oiIb/Uxv+9Se8FlWz5dnef2PUkoAxNFF5alzSn8cx+egtb1lZs7VHHTUQ7BVfLdI57VoR+rabIcUOz/ar/DjGEMNDUwc/Hg9kEWHjw48Pck53A1UmTBpJTA4QAORxKe0CbVexMGaOwXtAT2X7IPxs4cRCWbE8Tl0BmfTOPrvGP+3QlrmelnXMSkrWVxdo3Auf62CuRb5zO8iajazl5REW+HN+ggDfjy0HmYS1t1NoKqwjb5EiKTsfcOO7WLp7FhzGu8S+LtqbUphZ+dh40gvNhjT94iOZVuzwIZRpsp2IQLLrEUkCzw5Z6BWvB+WQgywKcpx+xiONR/tMmKVC16zP3nthpcQsvpygQnygL2wfUBHU6sTQBUpqwgGnHBDH3ZWWnFQr5Ymyalm0KJIvp45tM04uYvEE=", signature)
        } catch let error {
            print(error)
            XCTFail("Should not throw any exception during test execution")
        }
    }
    
    //L2 BaseString with UTF8 Parameters Test
    func testL2Signature_2() throws {
        let privateKey:SecKey = try SecurityUtil().getPrivateKeyFromP12(p12KeystoreName: strFileName, p12Key: strSecret)
        do {
            let signature = try SecurityUtil().getL2Signature(
                baseString: "GET&https://loadtest-pvt.api.lab/api/v1/rest/level2/in-in/&ap=裕廊坊 心邻坊&apex_l2_ig_app_id=loadtest-pvt-4Swyn7qwKeO32EXdH1dKTeIQ&apex_l2_ig_nonce=7231415196459608363&apex_l2_ig_signature_method=SHA256withRSA&apex_l2_ig_timestamp=1502164219425&apex_l2_ig_version=1.0&oq=c# nunit mac&q=c# nunit mac",
                privateKey: privateKey, commonDigest: "CC_SHA256")
            XCTAssertEqual("PAtGMMC5vWprJh4T1QkXiZWpqH9wA1hZz6AEjvHfEIalaejYdpDG31vb1boMjnKqoF2moydAyz97pd1s6FMHYZ3cv2YI/K3Wjf2pjcepI2nXwErncSve2W45CtzJ+TQWwqcttcfm/avhFpOYw74v/AHSrWbuoqPpVLAuznLBHwkiKJPBpt/Tdj1S/6Fmqu7OJu81OEQUBdhySVXtZMBtFHEFMviR2eDG7NcOZ2fspQUrCSdtEFKVyjMAcaFY6uxP5knRoq54FEHCmYotQ/J+VIWD3I0FL1ZswVtJ1zAM41rxpvfEvQFe9jucV6KN3kXnWD6hJbu4pXnakvcQKADgcBDvX0A9dzdhB9ibiWpKT8bXQwZDxYc6HqX9p83HikodV7x6p5Cd03Tol/9JaJqRQHe5ahwucCjnP5WqbTb4PrCNHeCGRj207ncpxBuafllsYfSadGFgeafpnc+5svnuZw9v9Y/H4msFbetoXUH9AQtcs+oCal5zG+AmBNZSqRROsdE6VczPPpwwn5lUCvI5XGXcFuo4X/tcQn9i6t314lgy1XYN6PAubbGDI1rnhlohMVy0XBwEi6xNWRT2vVx5ZxJmAfkSRE12n+AtdVrUQObr8cdzF9lei+DTd1fYz7QRiaJjkljEP4/J0GAiWv8z0JyDzbF9tlypJWkdWaO86eY=", signature)
        } catch let error {
            print(error)
            XCTFail("Should not throw any exception during test execution")
        }
    }
    
    func testL2_Verify_Signature_Test() throws{
        
        let publicCert:SecCertificate = try SecurityUtil().getPublicCertFromP12(p12KeystoreName: strFileName, p12Key: strSecret)
        
        XCTAssertTrue((try SecurityUtil().verifyL2Signature(signature: expectedSignature, publicCert: publicCert, baseString: message, commonDigest:strCommonDigest))!)
        
    }
    
}
