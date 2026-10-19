// Synthetic production-gate probe. Never calls test-keybag or Apple services.
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#include <dlfcn.h>
typedef CFDataRef (*CryptParams)(SecKeyRef, SecKeyAlgorithm, CFDataRef, CFDictionaryRef, CFErrorRef *);
static void report(NSString *step, CFErrorRef error) {
    NSLog(@"%@: %@", step, error ? (__bridge NSError *)error : @"ok");
}
int main(int argc, const char **argv) { @autoreleasepool {
    if (argc != 4) { fprintf(stderr, "usage: probe recipient-chain.der output-directory recipient-private.x963\n"); return 2; }
    NSString *out = @(argv[2]);
    if (![[NSFileManager defaultManager] fileExistsAtPath:out]) return 2;
    NSData *cert = [NSData dataWithContentsOfFile:@(argv[1])];
    if (!cert.length || ![[NSFileManager defaultManager] isReadableFileAtPath:@(argv[3])]) return 2;
    CryptParams decrypt = (CryptParams)dlsym(RTLD_DEFAULT, "SecKeyCreateDecryptedDataWithParameters");
    CFStringRef *applePay = dlsym(RTLD_DEFAULT, "kSecKeyApplePayEnabled");
    CFStringRef *recrypt = dlsym(RTLD_DEFAULT, "kSecKeyEncryptionParameterRecryptParameters");
    CFStringRef *recryptCert = dlsym(RTLD_DEFAULT, "kSecKeyEncryptionParameterRecryptCertificate");
    CFStringRef *size = dlsym(RTLD_DEFAULT, "kSecKeyEncryptionParameterSymmetricKeySizeInBits");
    NSLog(@"symbols decrypt=%d applePay=%d recrypt=%d cert=%d size=%d", !!decrypt, !!applePay, !!recrypt, !!recryptCert, !!size);
    if (!decrypt || !applePay || !recrypt || !recryptCert || !size) return 3;
    NSData *fixture = [@"dsmack synthetic public fixture; never a secret" dataUsingEncoding:NSUTF8StringEncoding];
    SecKeyAlgorithm alg = kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA256AESGCM;
    // Public SecKey input: synthetic software X9.63 private key, not an SE key.
    NSData *recipientRaw = [NSData dataWithContentsOfFile:@(argv[3])];
    if(recipientRaw.length != 97)return 2;
    CFErrorRef recipientError = NULL;
    SecKeyRef recipient = SecKeyCreateWithData((__bridge CFDataRef)recipientRaw, (__bridge CFDictionaryRef)@{(__bridge id)kSecAttrKeyType:(__bridge id)kSecAttrKeyTypeECSECPrimeRandom, (__bridge id)kSecAttrKeyClass:(__bridge id)kSecAttrKeyClassPrivate, (__bridge id)kSecAttrKeySizeInBits:@256}, &recipientError);
    report(@"synthetic recipient create",recipientError);
    if(recipientError)CFRelease(recipientError);
    if(!recipient)return 5;
    SecCertificateRef leaf = SecCertificateCreateWithData(NULL, (__bridge CFDataRef)cert);
    SecKeyRef leafPub = leaf ? SecCertificateCopyKey(leaf) : NULL;
    SecKeyRef recipientPub = SecKeyCopyPublicKey(recipient);
    CFDataRef leafBytes = leafPub ? SecKeyCopyExternalRepresentation(leafPub,NULL) : NULL;
    CFDataRef recipientBytes = recipientPub ? SecKeyCopyExternalRepresentation(recipientPub,NULL) : NULL;
    BOOL matches = leafBytes && recipientBytes && CFEqual(leafBytes,recipientBytes);
    NSLog(@"recipient certificate key matches=%d", matches);
    CFErrorRef controlError = NULL;
    CFDataRef controlCipher = matches ? SecKeyCreateEncryptedData(recipientPub,alg,(__bridge CFDataRef)fixture,&controlError) : NULL;
    CFDataRef controlPlain = controlCipher ? SecKeyCreateDecryptedData(recipient,alg,controlCipher,&controlError) : NULL;
    BOOL controlPassed = controlPlain && CFEqual(controlPlain,(__bridge CFDataRef)fixture);
    NSLog(@"recipient fixture encrypt/decrypt control=%d", controlPassed);
    report(@"recipient control", controlError);
    if(controlError)CFRelease(controlError);
    if(controlPlain)CFRelease(controlPlain); if(controlCipher)CFRelease(controlCipher);
    if(leafBytes)CFRelease(leafBytes); if(recipientBytes)CFRelease(recipientBytes);
    if(leafPub)CFRelease(leafPub); if(recipientPub)CFRelease(recipientPub); if(leaf)CFRelease(leaf);
    if(!controlPassed){CFRelease(recipient);return 6;}
    BOOL writeFailed = NO;
    for (int variant=0; variant<2; variant++) {
        CFErrorRef error = NULL;
        SecAccessControlRef acl = SecAccessControlCreateWithFlags(NULL, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, kSecAccessControlPrivateKeyUsage, &error);
        if (!acl) { report(@"acl", error); if(error)CFRelease(error); return 4; }
        NSMutableDictionary *attrs = [@{(__bridge id)kSecAttrTokenID:(__bridge id)kSecAttrTokenIDSecureEnclave, (__bridge id)kSecAttrKeyType:(__bridge id)kSecAttrKeyTypeECSECPrimeRandom, (__bridge id)kSecAttrKeySizeInBits:@256, (__bridge id)kSecAttrIsPermanent:@NO, (__bridge id)kSecAttrAccessControl:(__bridge id)acl} mutableCopy];
        if (variant) attrs[(__bridge id)*applePay] = @YES;
        SecKeyRef key = SecKeyCreateRandomKey((__bridge CFDictionaryRef)attrs, &error);
        CFRelease(acl);
        report([NSString stringWithFormat:@"variant%d create", variant], error);
        if(error) {CFRelease(error);error=NULL;}
        if (!key) continue;
        NSLog(@"variant%d decrypt-supported=%d",variant,SecKeyIsAlgorithmSupported(key,kSecKeyOperationTypeDecrypt,alg));
        SecKeyRef pub = SecKeyCopyPublicKey(key);
        if(!pub) { NSLog(@"variant%d copy public key failed",variant); CFRelease(key); continue; }
        CFDataRef ciphertext = SecKeyCreateEncryptedData(pub,alg,(__bridge CFDataRef)fixture,&error);
        report(@"encrypt public fixture", error); if(error){CFRelease(error);error=NULL;}
        if(ciphertext) {
            // Test both documented nesting and Apple's regression nesting.
            NSDictionary *nested = @{(__bridge id)*recryptCert:cert, (__bridge id)*size:@128};
            NSArray *params = @[@{(__bridge id)*recrypt:nested, (__bridge id)*size:@128}, @{(__bridge id)*recryptCert:cert, (__bridge id)*size:@128, (__bridge id)*recrypt:@{(__bridge id)*size:@128}}];
            for(NSUInteger layout=0;layout<params.count;layout++) {
                CFDataRef result=decrypt(key,alg,ciphertext,(__bridge CFDictionaryRef)params[layout],&error);
                report([NSString stringWithFormat:@"variant%d layout%lu recrypt",variant,(unsigned long)layout],error);
                if(error){CFRelease(error);error=NULL;}
                if(result) {
                    BOOL plaintext=[(__bridge NSData *)result isEqualToData:fixture];
                    NSLog(@"result length=%ld equals-public-plaintext=%d",CFDataGetLength(result),plaintext);
                    if(!plaintext) {
                        CFDataRef recovered = SecKeyCreateDecryptedData(recipient,alg,result,&error);
                        BOOL verified = recovered && CFEqual(recovered,(__bridge CFDataRef)fixture);
                        NSLog(@"variant%d layout%lu recipient-decrypt-matches=%d",variant,(unsigned long)layout,verified);
                        report(@"recipient decrypt recrypt result",error);
                        if(error){CFRelease(error);error=NULL;}
                        if(recovered)CFRelease(recovered);
                        NSString *name=[NSString stringWithFormat:@"v%d-l%lu-%@.bin",variant,(unsigned long)layout,verified ? @"verified" : @"unverified"];
                        NSError *writeError=nil;
                        BOOL written=[(__bridge NSData *)result writeToFile:[out stringByAppendingPathComponent:name] options:NSDataWritingAtomic error:&writeError];
                        NSLog(@"output write=%d error=%@",written,writeError);
                        if(!written)writeFailed=YES;
                    }
                    CFRelease(result);
                }
            }
            CFRelease(ciphertext);
        }
        if(pub)CFRelease(pub); CFRelease(key);
    }
    CFRelease(recipient);
    return writeFailed ? 7 : 0;
} }
