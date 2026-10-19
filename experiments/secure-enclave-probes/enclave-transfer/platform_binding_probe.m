// Source-derived platform key options; own ephemeral keys and public message only.
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#include <dlfcn.h>
int main(void) { @autoreleasepool {
    CFStringRef *osBound=dlsym(RTLD_DEFAULT,"kSecKeyOSBound");
    CFStringRef *sealed=dlsym(RTLD_DEFAULT,"kSecKeySealedHashesBound");
    typedef CFDataRef (*Attest)(SecKeyRef,SecKeyRef,CFErrorRef *);
    Attest attest=(Attest)dlsym(RTLD_DEFAULT,"SecKeyCreateAttestation");
    NSLog(@"exact flag symbols OSBound=%d SealedHashesBound=%d",!!osBound,!!sealed);
    if(!osBound || !sealed)return 3;
    NSData *message=[@"dsmack public platform-bound-key test" dataUsingEncoding:NSUTF8StringEncoding];
    for(int variant=0;variant<2;variant++) {
        CFErrorRef error=NULL;
        SecAccessControlRef acl=SecAccessControlCreateWithFlags(NULL,kSecAttrAccessibleWhenUnlockedThisDeviceOnly,kSecAccessControlPrivateKeyUsage,&error);
        if(!acl){NSLog(@"ACL error=%@",(__bridge NSError *)error);if(error)CFRelease(error);return 4;}
        NSMutableDictionary *priv=[@{(__bridge id)kSecAttrAccessControl:(__bridge id)acl} mutableCopy];
        // Exact nesting in Apple's PCC AttestedTLS P-256 implementation.
        if(variant){priv[(__bridge id)*osBound]=@YES;priv[(__bridge id)*sealed]=@YES;}
        NSDictionary *attrs=@{(__bridge id)kSecAttrTokenID:(__bridge id)kSecAttrTokenIDSecureEnclave,
            (__bridge id)kSecAttrKeyType:(__bridge id)kSecAttrKeyTypeECSECPrimeRandom,
            (__bridge id)kSecAttrKeySizeInBits:@256,(__bridge id)kSecAttrIsPermanent:@NO,
            (__bridge id)kSecPrivateKeyAttrs:priv};
        SecKeyRef key=SecKeyCreateRandomKey((__bridge CFDictionaryRef)attrs,&error);CFRelease(acl);
        NSLog(@"variant%d flagsRequested=%d created=%d error=%@",variant,variant,!!key,(__bridge NSError *)error);
        if(error){CFRelease(error);error=NULL;}if(!key)continue;
        CFDictionaryRef returned=SecKeyCopyAttributes(key);
        CFTypeRef token=returned ? CFDictionaryGetValue(returned,kSecAttrTokenID) : NULL;
        BOOL enclave=token && CFEqual(token,kSecAttrTokenIDSecureEnclave);
        NSLog(@"variant%d enclaveRoute=%d returnedOSBound=%@ returnedSealedHashesBound=%@",variant,enclave,
              returned ? (__bridge id)CFDictionaryGetValue(returned,*osBound) : nil,
              returned ? (__bridge id)CFDictionaryGetValue(returned,*sealed) : nil);
        if(returned)CFRelease(returned);
        if(!enclave){CFRelease(key);continue;}
        SecKeyRef pub=SecKeyCopyPublicKey(key);
        CFDataRef signature=SecKeyCreateSignature(key,kSecKeyAlgorithmECDSASignatureMessageX962SHA256,(__bridge CFDataRef)message,&error);
        BOOL verified=signature && pub && SecKeyVerifySignature(pub,kSecKeyAlgorithmECDSASignatureMessageX962SHA256,(__bridge CFDataRef)message,signature,&error);
        NSLog(@"variant%d signVerified=%d error=%@ hardwareFlagEnforcement=unproven",variant,verified,(__bridge NSError *)error);
        if(error){CFRelease(error);error=NULL;}
        // Documented private function signature; self-attest own key only.
        // No system identity key selection or attestation blob/identifier export.
        CFDataRef ownAttestation=attest ? attest(key,key,&error) : NULL;
        NSLog(@"variant%d ownSelfAttestationAvailable=%d bytes=%ld error=%@",variant,!!ownAttestation,ownAttestation ? CFDataGetLength(ownAttestation) : 0,(__bridge NSError *)error);
        if(error)CFRelease(error);if(ownAttestation)CFRelease(ownAttestation);
        if(signature)CFRelease(signature);if(pub)CFRelease(pub);CFRelease(key);
    }
    return 0;
} }
