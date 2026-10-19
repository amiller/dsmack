import Foundation
import Security
import CryptoKit
let out=URL(fileURLWithPath:CommandLine.arguments[1]);let tag=Data(CommandLine.arguments[2].utf8)
func save(_ n:String,_ d:Data)throws{try d.write(to:out.appendingPathComponent(n),options:.atomic)}
func hex(_ d:Data)->String{d.map{String(format:"%02x",$0)}.joined()}
var error:Unmanaged<CFError>?
let access=SecAccessControlCreateWithFlags(nil,kSecAttrAccessibleWhenUnlockedThisDeviceOnly,[.privateKeyUsage],&error)!
var attrs:[String:Any]=[kSecAttrKeyType as String:kSecAttrKeyTypeECSECPrimeRandom,kSecAttrKeySizeInBits as String:256,kSecAttrTokenID as String:kSecAttrTokenIDSecureEnclave,kSecUseDataProtectionKeychain as String:true,kSecPrivateKeyAttrs as String:[kSecAttrIsPermanent as String:true,kSecAttrApplicationTag as String:tag,kSecAttrAccessControl as String:access]]
let key:SecKey
#if MODIFIED
var found:CFTypeRef?
let q:[String:Any]=[kSecClass as String:kSecClassKey,kSecAttrApplicationTag as String:tag,kSecAttrKeyType as String:kSecAttrKeyTypeECSECPrimeRandom,kSecReturnRef as String:true,kSecUseDataProtectionKeychain as String:true]
let status=SecItemCopyMatching(q as CFDictionary,&found);guard status==errSecSuccess else{try save("failure.json",try JSONSerialization.data(withJSONObject:["lookupStatus":status]));exit(1)}
key=found as! SecKey
let variant="B"
#else
guard let created=SecKeyCreateRandomKey(attrs as CFDictionary,&error) else{try save("failure.json",try JSONSerialization.data(withJSONObject:["createError":String(describing:error?.takeRetainedValue())]));exit(2)}
key=created
let variant="A"
#endif
let pub=SecKeyCopyPublicKey(key)!,publicData=SecKeyCopyExternalRepresentation(pub,&error)! as Data
let message=Data("fresh-synthetic-persistent-SEP-\(variant)".utf8)
guard let sig=SecKeyCreateSignature(key,.ecdsaSignatureMessageX962SHA256,message as CFData,&error) else{exit(3)}
let d:[String:Any]=["variant":variant,"publicKeyX963":hex(publicData),"signatureDER":hex(sig as Data),"messageHex":hex(message),"verify":SecKeyVerifySignature(pub,.ecdsaSignatureMessageX962SHA256,message as CFData,sig,&error)]
try save("signature.json",try JSONSerialization.data(withJSONObject:d,options:[.sortedKeys,.prettyPrinted]))
#if !MODIFIED
var legacy:SecAccess?
let legacyStatus=SecAccessCreate("synthetic legacy ACL incompatibility" as CFString,[] as CFArray,&legacy)
var nested=attrs[kSecPrivateKeyAttrs as String] as! [String:Any];nested[kSecAttrApplicationTag as String]=Data((CommandLine.arguments[2]+".legacy").utf8);nested[kSecAttrAccess as String]=legacy!;attrs[kSecPrivateKeyAttrs as String]=nested
var legacyError:Unmanaged<CFError>?;let combined=SecKeyCreateRandomKey(attrs as CFDictionary,&legacyError)
let result:[String:Any]=["legacyAccessCreateStatus":legacyStatus,"combinedLegacyAndSEPAccessControlCreated":combined != nil,"error":legacyError.map{String(describing:$0.takeRetainedValue())} ?? "none"]
try save("legacy-combination.json",try JSONSerialization.data(withJSONObject:result,options:[.sortedKeys,.prettyPrinted]))
#endif
try save("done.txt",Data("done".utf8))
