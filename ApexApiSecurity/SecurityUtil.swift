//
//  SecurityUtil.swift
//  ApexApiSecurity
//
//  Created by Kelvin Wijaya on 7/6/18.
//  Copyright © 2018 GovTech. All rights reserved.
//

import Foundation
import Security
import CommonCrypto

/// Utility Class for performing APEX API Security operations
struct SecurityUtil {
    
    private var g_userAgent: String = String("Mozilla/5.0")
    private var g_secPadding = SecPadding.PKCS1SHA256
    private var g_sha256_digestLength: Int32 = CC_SHA256_DIGEST_LENGTH
    
    enum ApiSigningError : Error {
        case ApiUtilException(String)
    }
    
    enum ApiValidationError : Error {
        case ApiUtilException(String)
    }
    
    enum FileAndPathError : Error{
        
        case NoSuchPath(String)
        case UnSuccessfulCreateUrlObjAsUrlStringCannotBeUsed
        
    }
    
    /// Function to retrive private key from keystore in p12 format
    ///
    /// - Parameters:
    ///   - p12KeystoreName: keystore filename (Note: No need to put extenstion .p12 in the parameter)
    ///   - p12Key: keystore password
    /// - Returns: SecKey Object (Private Key)
    /// - Throws: Exception (e.g. FileAndPathError)
    func getPrivateKeyFromP12(p12KeystoreName : String, p12Key : String) throws -> SecKey{
        
        debugPrint("p12KeystoreName: " + p12KeystoreName)
        
        //Refer to framework bundle
        let bundle = Bundle(identifier: "sg.gov.tech.ApexApiSecurity")
        let keystorePath = bundle?.path(forResource: p12KeystoreName, ofType: "p12", inDirectory: "certificates")

        let keystoreData =  NSData(contentsOfFile: keystorePath!)
        
        if(keystorePath == nil){
            
            throw FileAndPathError.NoSuchPath("No such filename")
        }
        
        var status: OSStatus
        
        //let certificateKey = "passwordkey"
        
        let options = [kSecImportExportPassphrase as String : p12Key]
        
        
        //-- client certificates
        
        var optItems: CFArray? = nil
        
        status = SecPKCS12Import(keystoreData as CFData!, (options as CFDictionary), &optItems)
        
        
        if status != errSecSuccess {
            
            debugPrint("Cannot sign the device id info: failed importing keystore.")
            
            throw  FileAndPathError.NoSuchPath("No such optItems")
        }
        
        
        guard let items = optItems else {
            
            throw  FileAndPathError.NoSuchPath("No such items")
            
        }
        
        
        //----- Cast CFArrayRef to Swift Array
        
        let itemsArray = items as [AnyObject]
        
        
        //---- Cast CFDictionaryRef as Swift Dictionary

        guard let myIdentityAndTrust = itemsArray.first as? [String : AnyObject] else {

            throw  FileAndPathError.NoSuchPath("No such IdentityAndTrust")
        }


        //---- Get our SecIdentityRef from the PKCS #12 blob

        let outIdentity = myIdentityAndTrust[kSecImportItemIdentity as String] as! SecIdentity
        
        //--- Get the private key associated with our identity
        
        var optPrivateKey: SecKey?
        
        status = SecIdentityCopyPrivateKey(outIdentity, &optPrivateKey)
        
        if status != errSecSuccess {
            
            debugPrint("Failed to extract the private key from the keystore.")
            throw  FileAndPathError.NoSuchPath("No such optPrivateKey")
            
        }
        
        
        //--- Unwrap privateKey from optional SecKeyRef
        
        guard let privateKey = optPrivateKey else {
            
            throw  FileAndPathError.NoSuchPath("No such privateKey")
            
        }
        
        return privateKey
        
    }
    
    /// Function to retrieve public certificate from keystore in p12 format
    ///
    /// - Parameters:
    ///   - p12KeystoreName: keystore filename (Note: No need to put extenstion .p12 in the parameter)
    ///   - p12Key: keystore password
    /// - Returns: SecCertificate Object (Public Certificate)
    /// - Throws: Exception (e.g. FileAndPathError)
    func getPublicCertFromP12(p12KeystoreName : String, p12Key : String) throws -> SecCertificate{
        
        // Refer to framework bundle
        let bundle = Bundle(identifier: "sg.gov.tech.ApexApiSecurity")
        let keystorePath = bundle?.path(forResource: p12KeystoreName, ofType: "p12", inDirectory: "certificates")
        
        
        if(keystorePath == nil){
            
            throw FileAndPathError.NoSuchPath("No such filename")
        }
        
        let keystoreData =  NSData(contentsOfFile: keystorePath!)
        
        var status: OSStatus
        
        let options = [kSecImportExportPassphrase as String : p12Key]
        
        
        //-- client certificates
        
        var optItems: CFArray? = nil
        
        status = SecPKCS12Import(keystoreData as CFData!, (options as CFDictionary), &optItems)
        
        
        if status != errSecSuccess {
            
            debugPrint("Cannot sign the device id info: failed importing keystore.")
            
            throw  FileAndPathError.NoSuchPath("No such filename")
        }
        
        
        guard let items = optItems else {
            
            throw  FileAndPathError.NoSuchPath("No such filename")
            
        }
        
        
        //----- Cast CFArrayRef to Swift Array
        
        let itemsArray = items as [AnyObject]
        
        
        //---- Cast CFDictionaryRef as Swift Dictionary
        
        guard let myIdentityAndTrust = itemsArray.first as? [String : AnyObject] else {
            
            throw  FileAndPathError.NoSuchPath("No such filename")
        }
        
        
        //---- Get our SecIdentityRef from the PKCS #12 blob
        
        let outIdentity = myIdentityAndTrust[kSecImportItemIdentity as String] as! SecIdentity
        
        var myReturnedCertificate: SecCertificate?
        
        status = SecIdentityCopyCertificate(outIdentity, &myReturnedCertificate)
        
        
        if status != errSecSuccess {
            
            throw  FileAndPathError.NoSuchPath("No such filename")
            
            
        }
        
        //--- Unwrap privateKey from optional SecKeyRef
        
        guard let publicCert = myReturnedCertificate else {
            
            throw  FileAndPathError.NoSuchPath("No such filename")
            
        }
        debugPrint(publicCert)
        return publicCert
    }
    
    /// Function to generate APEX L2 Signature
    ///
    /// - Parameters:
    ///   - baseString: Base value used for signature generation
    ///   - privateKey: Private key object obtain from keystore;
    ///   - commonDigest: Algorithm used for digest calculation (default: CC_SHA256)
    /// - Returns: L2 Signature value
    /// - Throws: Exception
    func getL2Signature(baseString:String, privateKey:SecKey, commonDigest:String) throws -> String? {
        
        //validation
        if(baseString == .none || baseString.isEmpty) {
            throw ApiSigningError.ApiUtilException("baseString must not be null or empty.")
        }
        
        if(privateKey == .none) {
            throw ApiSigningError.ApiUtilException("privateKey must not be null.")
        }
        
        var digestLegth : Int32 = 0
        
        //default to CC_SHA256
        if(commonDigest == .none || commonDigest == "CC_SHA256") {
            digestLegth = g_sha256_digestLength;
        }
        let messageDigest = NSMutableData(length: Int(digestLegth))!
        
        let baseStringData: NSData = baseString.data(using: String.Encoding.utf8)! as NSData
        
        
        CC_SHA256(baseStringData.bytes, CC_LONG(baseStringData.length), UnsafeMutablePointer(messageDigest.mutableBytes.assumingMemoryBound(to: UInt8.self)))
        
        let signedData: NSMutableData = NSMutableData(length: SecKeyGetBlockSize(privateKey))!
        var signedDataLength: Int = signedData.length
        
        let err: OSStatus = SecKeyRawSign(
            privateKey,
            g_secPadding,
            UnsafePointer<UInt8>(messageDigest.mutableBytes.assumingMemoryBound(to: UInt8.self)),
            messageDigest.length,
            UnsafeMutablePointer<UInt8>(signedData.mutableBytes.assumingMemoryBound(to: UInt8.self)),
            &signedDataLength)
        
        let base64Encoded = signedData.base64EncodedString(options: []) //.endLineWithLineFeed) // or []
        
        switch err {
            case noErr: return base64Encoded
            default: throw ApiSigningError.ApiUtilException("Error during L2 Signature value generation")
        }
        
    }
    
    /// Function to generate APEX L1 Signature
    ///
    /// - Parameters:
    ///   - baseString: Base value used for signature generation
    ///   - secret: Application secret
    ///   - commonDigest: Algorithm used for digest calculation (default: CC_SHA256)
    /// - Returns: L1 Signature value
    /// - Throws: Exception
    func getL1Signature(baseString:String, secret:String, commonDigest:String) throws -> String? {
        
        //validation
        if(baseString == .none || baseString.isEmpty) {
            throw ApiSigningError.ApiUtilException("baseString must not be null or empty.")
        }
        
        if(secret == .none || secret.isEmpty) {
            throw ApiSigningError.ApiUtilException("secret must not be null or empty.")
        }
        
        var digestLegth : Int32 = 0
        
        //default to CC_SHA256
        if(commonDigest == .none || commonDigest == "CC_SHA256") {
            digestLegth = g_sha256_digestLength;
        }
        
        let hmac = NSMutableData(length: Int(digestLegth))!
        
        let baseStringData: NSData = baseString.data(using: String.Encoding.utf8)! as NSData
        
        let secretData: NSData = secret.data(using: String.Encoding.utf8)! as NSData
        
        
        CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA256), secretData.bytes, secretData.length, baseStringData.bytes, baseStringData.length, UnsafeMutablePointer(hmac.mutableBytes.assumingMemoryBound(to: UInt8.self)))
        
        let base64Encoded = hmac.base64EncodedString(options: []) //.endLineWithLineFeed) // or []
        
        return base64Encoded
        
    }
    
    /// Function to verify L1 Signature
    ///
    /// - Parameters:
    ///   - signature: APEX L1 Signature value
    ///   - secret: Application secret
    ///   - baseString: Base value used for signature generation
    ///   - commonDigest: Algorithm used for digest calculation (default: CC_SHA256)
    /// - Returns: Boolean value
    /// - Throws: Exception
    func verifyL1Signature(signature:String, secret:String, baseString:String, commonDigest:String) throws -> Bool? {
        
        debugPrint("Enter :: verifyL1Signature :: signature : \(signature) , baseString : \(baseString) , commonDigest: \(commonDigest) , secret: \(secret)")
        
        let expectedSignature = try getL1Signature(baseString: baseString, secret: secret, commonDigest: commonDigest)
        let verified = (expectedSignature == signature)
        
        debugPrint("Exit :: verifyL1Signature :: verified : \(verified)");
        
        return verified
        
    }
    
    /// Function to verify L2 Signature
    ///
    /// - Parameters:
    ///   - signature: APEX L2 Signature value
    ///   - publicCert: Application secret
    ///   - baseString: Base value used for signature generation
    ///   - commonDigest: Algorithm used for digest calculation (default: CC_SHA256)
    /// - Returns: Boolean value
    /// - Throws: Exception
    func verifyL2Signature(signature:String, publicCert:SecCertificate, baseString:String, commonDigest:String) throws -> Bool? {
        debugPrint("Enter :: verifyL2Signature :: signature : \(signature) , baseString : \(baseString) , commonDigest: \(commonDigest)")
        var digestLegth : Int32 = 0
        var verified = false
        let publicKey:SecKey = SecCertificateCopyPublicKey(publicCert)!
        
        if let signatureData = NSData(base64Encoded: signature, options: .ignoreUnknownCharacters){
            let signatureBytes = [UInt8](signatureData as Data)
            
            //default to CC_SHA256
            if(commonDigest == .none || commonDigest == "CC_SHA256") {
                digestLegth = g_sha256_digestLength;
            }
            let messageDigest = NSMutableData(length: Int(digestLegth))!
            
            let baseStringData: NSData = baseString.data(using: String.Encoding.utf8)! as NSData
            
            CC_SHA256(baseStringData.bytes, CC_LONG(baseStringData.length), UnsafeMutablePointer(messageDigest.mutableBytes.assumingMemoryBound(to: UInt8.self)))
            
            //let signedData: NSData = signedString.data(using: String.Encoding.utf8)! as NSData
            let err: OSStatus = SecKeyRawVerify(publicKey, g_secPadding, UnsafePointer<UInt8>(messageDigest.mutableBytes.assumingMemoryBound(to: UInt8.self)), messageDigest.length, UnsafePointer<UInt8>(signatureBytes), signatureData.length)
            
            switch err {
                case noErr: verified = true
                default: throw ApiSigningError.ApiUtilException("Error during L2 Signature value generation")
                
            }
            
            debugPrint("Exit :: verifyL2Signature :: verified : \(verified)")
           
        }
        return verified
    }
    
    /// <#Description#>
    ///
    /// - Returns: <#return value description#>
    func getNewNonce() -> String{
        
        let bytesCount = 8
        
        var randomBytes = [UInt8](repeating: 0, count: bytesCount)
        
        SecRandomCopyBytes(kSecRandomDefault,bytesCount,&randomBytes)
        
        let strRandomBytes = String(bytes: randomBytes, encoding: String.Encoding.utf8)
        
        return strRandomBytes!
        
    }
    
    /// Function to generate new timestamp
    ///
    /// - Returns: timestamp in String format
    func getNewTimeStamp() -> String{
        
        return String(currentTimeMilliseconds());
    }
    
    /// Function to generate new timestamp in milliseoconds
    ///
    /// - Returns: timestamp in ms
    func currentTimeMilliseconds() -> Int {
        
        let currentDate = Date()
        let since1970 = currentDate.timeIntervalSince1970
        
        return Int(since1970 * 1000)
        
        
    }
    
    /// Function to validate http URL
    ///
    /// - Parameter strURL: http URL
    /// - Returns: Boolean value
    func validateURLScheme(strURL:String ) -> Bool{
        
        var b_result = false
        
        let encodedUrlString = strURL.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed)
        let components = NSURLComponents(string: encodedUrlString!)
        
        let urlScheme = components?.scheme
        
        if( urlScheme == "http" || urlScheme == "https")
        {
            b_result = true
            return b_result
        }
        
        return b_result
        
    }
    
    
    /// Function to retrieve url encoded http URL
    ///
    /// - Parameter strURL: absolute http URL inclusive query parameters
    /// - Returns: encoded http URL
    func getAbsoluteURL(strURL:String ) -> String{
    
        let encodedUrlString = strURL.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed)
        let components = NSURLComponents(string: encodedUrlString!)
        
        let scheme = components?.scheme
        let host = components?.host
        let path = components?.path
        var url:String
        
        url = scheme! + "://" +  host! + path!
    
        debugPrint("AbsoluteURL: " + url)
        
        return url
   
    }
    
    /// Function to decode http URL
    ///
    /// - Parameter str: http URL
    /// - Returns: decoded http URL
    func decodeURL(str: String) -> String{
        
        let strWithPlusSign = str.removingPercentEncoding
        
        let  strResult = strWithPlusSign?.replacingOccurrences(of: "+", with: " ")
        
        return strResult!
        
        //return strWithPlusSign!
    }
    
    /// Function to generate Base String based on the HTTP headers, formdate, operation and various random variables such as timestamp and nonce
    ///
    /// - Parameters:
    ///   - strAppId: Application ID
    ///   - strURLNoPortNbr: http URL excluding port number (all APEX api it serve using default https port:443)
    ///   - strAuthPrefix: Apex Authorization header prefix
    ///   - strHttpMethod: http operation
    ///   - strSignatureMethod: 'HMACSHA256' for APEX L1 or 'SHA256withRSA' for APEX L2
    ///   - strNonce: nonce value
    ///   - strTimeStamp: timestamp in ms
    ///   - formList: http form data
    /// - Returns: Base value used for signature generation
    /// - Throws: Exception
    func getBaseString(strAppId: String,
                       strURLNoPortNbr: String,
                       strAuthPrefix:String,
                       strHttpMethod:String,
                       strSignatureMethod:String?,
                       strNonce:String,
                       strTimeStamp:String,
                       formList :[String:String]) throws -> String {
        
        debugPrint("Enter :: getBaseString :: strAppId : \(strAppId), strURLNoPortNbr : \(strURLNoPortNbr) , strAuthPrefix: \(strAuthPrefix), strAppId : \(strAppId), strHttpMethod : \(strHttpMethod), strSignatureMethod : \(strSignatureMethod), strNonce : \(strNonce), strTimeStamp : \(strTimeStamp)")
        
        let urlSchemeStatus = validateURLScheme(strURL: strURLNoPortNbr)
        
        if(urlSchemeStatus == false){
            throw ApiValidationError.ApiUtilException("Support http and https protocol only.")
        }
        
        let encodedstrURL = strURLNoPortNbr.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed)
        
        let strAbsoluteURL = getAbsoluteURL(strURL: strURLNoPortNbr)
        
        if(strAbsoluteURL == ""){
            throw ApiValidationError.ApiUtilException("Support http and https protocol only.")
        }
        
        let items = URLComponents(string:encodedstrURL!)?.queryItems
        
        var keyvalues :[String:String] = [:]
        
        items?.forEach{
            
            item in keyvalues[item.name] = item.value?.removingPercentEncoding
            
        }
        
        if (!(formList.isEmpty) && formList.count > 0) {
            formList.forEach{
                (k,v) in keyvalues[k] = v
            }
        }
        
        //-- add others that pass in here:
        
        let authPrefix = strAuthPrefix.lowercased()
        
        keyvalues[authPrefix + "_timestamp"] = strTimeStamp
        keyvalues[authPrefix + "_nonce"] = strNonce
        keyvalues[authPrefix + "_app_id"] = strAppId
        keyvalues[authPrefix + "_signature_method"] = strSignatureMethod
        keyvalues[authPrefix + "_version"] = "1.0"
        
        let sorted = keyvalues.map{$0}.sorted{$0.0.lowercased() < $1.0.lowercased()}
        
        let result = sorted.reduce("",
                                   {(result,kvp) -> String in
                                    result + "&\(kvp.key)=\(kvp.value)"
        })
        
        let baseString = strHttpMethod.uppercased() + "&" + strAbsoluteURL + result
        
        return baseString
        
    }
    
    /// Function to generate APEX Authorization token
    ///
    /// - Parameters:
    ///   - strRealm: Realm value (usually is Apex client domain url)
    ///   - strAppId: Application id
    ///   - strSecret: Application secret
    ///   - strURLNoPortNbr: http url without port number
    ///   - strAuthPrefix: Apex Authorization header prefix
    ///   - strHttpMethod: http operation
    ///   - strNonce: nonce value
    ///   - strTimeStamp: timestamp in ms
    ///   - formList: http form data
    ///   - strPassword: keystore password
    ///   - strAlias: private key alias
    ///   - strFileName: keystore filename in .p12 format excluding file extension
    /// - Returns: Apex Authorization token
    /// - Throws: Exception
    func getToken(strRealm: String,
                       strAppId: String,
                       strSecret: String?,
                       strURLNoPortNbr: String,
                       strAuthPrefix:String,
                       strHttpMethod:String,
                       strNonce:String,
                       strTimeStamp:String,
                       formList: [String:String],
                       strPassword: String?,
                       strAlias:String,
                       strFileName:String?) throws -> String {
        
        debugPrint("Enter :: getToken :: strRealm : \(strRealm) , strAppId : \(strAppId), strURLNoPortNbr : \(strURLNoPortNbr) , strAuthPrefix: \(strAuthPrefix), strSecret : \(strSecret), strHttpMethod : \(strHttpMethod), strNonce : \(strNonce), strTimeStamp : \(strTimeStamp), strPassword : \(strPassword), strAlias : \(strAlias), strFileName : \(strFileName)")
        
        //-- add others that pass in here:
        
        let authPrefix = strAuthPrefix.lowercased()
        var nonce = strNonce
        var timestamp = strTimeStamp
        var signatureMethod :String

        // Generate the nonce value
        if(nonce.isEmpty){
            nonce = getNewNonce()
        }
        
        if(timestamp.isEmpty){
            timestamp = getNewTimeStamp()
        }
        
        if (strSecret != nil) {
            signatureMethod = "HMACSHA256"
        } else {
            signatureMethod = "SHA256withRSA"
        }
        
        let baseString = try getBaseString(strAppId: strAppId
            , strURLNoPortNbr: strURLNoPortNbr, strAuthPrefix: strAuthPrefix, strHttpMethod: strHttpMethod
            , strSignatureMethod: signatureMethod, strNonce: strNonce, strTimeStamp: strTimeStamp, formList: formList)
        
        var base64Token = ""
        if (strSecret != nil) {
            base64Token = try getL1Signature(baseString: baseString, secret: strSecret!, commonDigest: "CC_SHA256")!

        } else {
            let privateKey:SecKey = try getPrivateKeyFromP12(p12KeystoreName: strFileName!, p12Key: strPassword!)
                base64Token = try getL2Signature(baseString: baseString, privateKey: privateKey, commonDigest: "CC_SHA256")!

            
        }
        var keyvalues :[String:String] = [:]
        keyvalues[authPrefix + "_timestamp"] = timestamp
        keyvalues[authPrefix + "_nonce"] = nonce
        keyvalues[authPrefix + "_app_id"] = strAppId
        keyvalues[authPrefix + "_signature_method"] = signatureMethod
        keyvalues[authPrefix + "_signature"] = base64Token
        keyvalues[authPrefix + "_version"] = "1.0"
        
        let sorted = keyvalues.map{$0}.sorted{$0.0.lowercased() < $1.0.lowercased()}
        
        
        let index = authPrefix.index(authPrefix.startIndex, offsetBy: 1)
        let tokenValues = sorted.reduce("realm" + "=\"" + strRealm + "\"",
                                   {(result,kvp) -> String in
                                    result + ", " + (kvp.key) + "=\"" + (kvp.value) + "\""
        })
        let authorizationToken = String(format:"%@ %@", authPrefix.prefix(1).uppercased() + authPrefix.suffix(from: index), tokenValues)

        
        return authorizationToken
        
    }
    
}
