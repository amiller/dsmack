// Own generated eligible attestor, following Apple's regression attestationTest.
// No system identity selectors, test keybags, persistence, account/network calls.
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#include <dlfcn.h>
typedef CFDataRef (*Attest)(SecKeyRef,SecKeyRef,CFErrorRef *);
static BOOL confirmedToken(SecKeyRef key,CFStringRef expected) {
    CFDictionaryRef attrs=SecKeyCopyAttributes(key);
    CFTypeRef token=attrs ? CFDictionaryGetValue(attrs,kSecAttrTokenID) : NULL;
    BOOL result=token && CFEqual(token,expected);
    if(attrs)CFRelease(attrs);return result;
}
int main(void) { @autoreleasepool {
    CFStringRef *type=dlsym(RTLD_DEFAULT,"kSecAttrKeyTypeSecureEnclaveAttestation");
    CFStringRef *provider=dlsym(RTLD_DEFAULT,"kSecAttrTokenIDAppleKeyStore");
    CFStringRef *osBound=dlsym(RTLD_DEFAULT,"kSecKeyOSBound");
    CFStringRef *sealed=dlsym(RTLD_DEFAULT,"kSecKeySealedHashesBound");
    Attest attest=(Attest)dlsym(RTLD_DEFAULT,"SecKeyCreateAttestation");
    NSLog(@"exact symbols attestorType=%d provider=%d OSBound=%d SealedHashesBound=%d attest=%d",!!type,!!provider,!!osBound,!!sealed,!!attest);
    if(!type || !provider || !osBound || !sealed || !attest)return 3;
    CFErrorRef error=NULL;
    SecAccessControlRef acl=SecAccessControlCreateWithFlags(NULL,kSecAttrAccessibleWhenUnlockedThisDeviceOnly,kSecAccessControlPrivateKeyUsage,&error);
    if(!acl){if(error)CFRelease(error);return 4;}
    NSDictionary *attestorAttrs=@{(__bridge id)kSecAttrTokenID:(__bridge id)*provider,
        (__bridge id)kSecAttrKeyType:(__bridge id)*type,
        (__bridge id)kSecAttrAccessControl:(__bridge id)acl,(__bridge id)kSecAttrIsPermanent:@NO};
    SecKeyRef ownAttestor=SecKeyCreateRandomKey((__bridge CFDictionaryRef)attestorAttrs,&error);
    NSLog(@"own eligible attestor created=%d error=%@",!!ownAttestor,(__bridge NSError *)error);
    if(error){CFRelease(error);error=NULL;}
    if(!ownAttestor){CFRelease(acl);return 0;}
    BOOL attestorEnclave=confirmedToken(ownAttestor,*provider);
    NSLog(@"own attestor confirmed requested AKS token=%d",attestorEnclave);
    if(!attestorEnclave){CFRelease(ownAttestor);CFRelease(acl);return 5;}
    NSData *message=[@"dsmack public platform attestation probe" dataUsingEncoding:NSUTF8StringEncoding];
    for(int variant=0;variant<2;variant++) {
        NSMutableDictionary *priv=[@{(__bridge id)kSecAttrAccessControl:(__bridge id)acl} mutableCopy];
        if(variant){priv[(__bridge id)*osBound]=@YES;priv[(__bridge id)*sealed]=@YES;}
        NSDictionary *attrs=@{(__bridge id)kSecAttrTokenID:(__bridge id)kSecAttrTokenIDSecureEnclave,
            (__bridge id)kSecAttrKeyType:(__bridge id)kSecAttrKeyTypeECSECPrimeRandom,
            (__bridge id)kSecAttrKeySizeInBits:@256,(__bridge id)kSecAttrIsPermanent:@NO,
            (__bridge id)kSecPrivateKeyAttrs:priv};
        SecKeyRef key=SecKeyCreateRandomKey((__bridge CFDictionaryRef)attrs,&error);
        NSLog(@"variant%d target created=%d error=%@",variant,!!key,(__bridge NSError *)error);
        if(error){CFRelease(error);error=NULL;}if(!key)continue;
        if(!confirmedToken(key,kSecAttrTokenIDSecureEnclave)){CFRelease(key);continue;}
        SecKeyRef pub=SecKeyCopyPublicKey(key);
        CFDataRef signature=SecKeyCreateSignature(key,kSecKeyAlgorithmECDSASignatureMessageX962SHA256,(__bridge CFDataRef)message,&error);
        BOOL verified=signature && pub && SecKeyVerifySignature(pub,kSecKeyAlgorithmECDSASignatureMessageX962SHA256,(__bridge CFDataRef)message,signature,&error);
        NSLog(@"variant%d signatureVerified=%d error=%@",variant,verified,(__bridge NSError *)error);
        if(error){CFRelease(error);error=NULL;}
        CFDataRef result=attest(ownAttestor,key,&error);
        // Never dump/export attestation or token blobs or device identifiers.
        NSLog(@"variant%d ownEligibleAttestationAvailable=%d bytes=%ld error=%@ flagEnforcement=unproven",variant,!!result,result ? CFDataGetLength(result) : 0,(__bridge NSError *)error);
        if(error){CFRelease(error);error=NULL;}if(result)CFRelease(result);
        if(signature)CFRelease(signature);if(pub)CFRelease(pub);CFRelease(key);
    }
    CFRelease(ownAttestor);CFRelease(acl);return 0;
} }
