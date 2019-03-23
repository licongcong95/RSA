//
//  RSAPKCS1AndPKCS8.m
//  果物戦争
//
//  Created by yons on 2019/3/22.
//  Copyright © 2019年 cxzswq. All rights reserved.
//

#import "RSAPKCS1AndPKCS8.h"

@implementation RSAPKCS1AndPKCS8
+ (NSString*)encodeRsa:(NSString*)dataString andPublicKeyPath:(NSString*)filePath{
    
    //判断publicKey参数是否正确
    if ((filePath == nil) || (filePath == NULL)) {
        return nil;
    } else if (![filePath isKindOfClass:[NSString class]]) {
        return nil;
    } else if ([filePath length] <= 0) {
        return nil;
    }
    
    //判断originString参数是否正确
    if ((dataString == nil) || (dataString == NULL)) {
        return nil;
    } else if (![dataString isKindOfClass:[NSString class]]) {
        return nil;
    } else if ([dataString length] <= 0) {
        return nil;
    }
    
    
    NSString* publicKey = [[NSString alloc] initWithContentsOfFile:filePath encoding:NSUTF8StringEncoding error:nil];
    
    //获取需要加密的字符串内容编码数据流
    NSData *originData = nil, *encryptData = nil;
    
    //
    NSData* keyData = [[self class] publicKeyDecodeBase64:publicKey];
    
    keyData = [[self class] stripPublicKeyHeader:keyData];
    
    SecKeyRef keyRef = [[self class] publicKeyRef:keyData];
    
    
    originData = [dataString dataUsingEncoding:NSUTF8StringEncoding];
    
    encryptData = [self encryptData:originData withKeyRef:keyRef];
   
    NSDataBase64EncodingOptions options;
    options = NSDataBase64EncodingEndLineWithLineFeed;
    
    return [encryptData base64EncodedStringWithOptions:options];
    
}


+ (NSString*)decodeRsa:(NSString*)dataString andPublicKeyPath:(NSString*)filePath{
    //判断publicKey参数是否正确
    if ((filePath == nil) || (filePath == NULL)) {
        return nil;
    } else if (![filePath isKindOfClass:[NSString class]]) {
        return nil;
    } else if ([filePath length] <= 0) {
        return nil;
    }
    
    //判断originString参数是否正确
    if ((dataString == nil) || (dataString == NULL)) {
        return nil;
    } else if (![dataString isKindOfClass:[NSString class]]) {
        return nil;
    } else if ([dataString length] <= 0) {
        return nil;
    }
    
    
    NSString* privateKey = [[NSString alloc] initWithContentsOfFile:filePath encoding:NSUTF8StringEncoding error:nil];
    
    
//    keyRef
    
    //获取需要加密的字符串内容编码数据流
    NSData *encryptData = nil, *decryptData = nil;
//

    //先 生成私钥解码格式
    NSData* keyData = [self privateKeyDecodeBase64:privateKey];

    keyData = [self stripPrivateKeyHeader:keyData];

    SecKeyRef keyRef = [self privateKeyRef:keyData];
    
    encryptData = [[NSData alloc] initWithBase64EncodedString:dataString options:NSDataBase64DecodingIgnoreUnknownCharacters];
    
//    decryptData = [self decryptData:originData withKeyRef:keyRef];
    
    NSStringEncoding encoding = NSUTF8StringEncoding;
    
    decryptData = [self decryptData:encryptData withKeyRef:keyRef];
    
    return [[NSString alloc] initWithData:decryptData encoding:encoding];
    
}


+ (NSData *)decryptData:(NSData *)data withKeyRef:(SecKeyRef)keyRef
{
    const uint8_t *srcbuf = (const uint8_t *)[data bytes];
    size_t srclen = (size_t)data.length;
    
    size_t block_size = SecKeyGetBlockSize(keyRef) * sizeof(uint8_t);
    UInt8 *outbuf = malloc(block_size);
    size_t src_block_size = block_size;
    
    NSMutableData *ret = [[NSMutableData alloc] init];
    for (int idx = 0; idx < srclen; idx += src_block_size)
    {
        size_t data_len = srclen - idx;
        if(data_len > src_block_size)
        {
            data_len = src_block_size;
        }
        
        size_t outlen = block_size;
        OSStatus status = noErr;
        status = SecKeyDecrypt(keyRef, kSecPaddingNone,
                               srcbuf + idx, data_len,
                               outbuf, &outlen);
        if (status != 0)
        {
            NSLog(@"SecKeyEncrypt fail. Error Code: %d", (int)status);
            ret = nil;
            break;
        }
        else
        {
            int idxFirstZero = -1;
            int idxNextZero = (int)outlen;
            for (int i = 0; i < outlen; i ++)
            {
                if (outbuf[i] == 0)
                {
                    if (idxFirstZero < 0)
                    {
                        idxFirstZero = i;
                    }
                    else
                    {
                        idxNextZero = i;
                        break;
                    }
                }
            }
            NSUInteger length = idxNextZero-idxFirstZero-1;
            [ret appendBytes:&outbuf[idxFirstZero+1] length:length];
        }
    }
    free(outbuf);
    CFRelease(keyRef);
    return ret;
}

+ (SecKeyRef)privateKeyRef:(NSData*)data{
    if(!data){
        return nil;
    }
    
    //a tag to read/write keychain storage
    NSString *tag = @"RSAUtil_PrivKey";
    NSData *d_tag = [NSData dataWithBytes:[tag UTF8String] length:[tag length]];
    
    // Delete any old lingering key with the same tag
    NSMutableDictionary *privateKey = [[NSMutableDictionary alloc] init];
    [privateKey setObject:(__bridge id) kSecClassKey forKey:(__bridge id)kSecClass];
    [privateKey setObject:(__bridge id) kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [privateKey setObject:d_tag forKey:(__bridge id)kSecAttrApplicationTag];
    SecItemDelete((__bridge CFDictionaryRef)privateKey);
    
    // Add persistent version of the key to system keychain
    [privateKey setObject:data forKey:(__bridge id)kSecValueData];
    [privateKey setObject:(__bridge id) kSecAttrKeyClassPrivate forKey:(__bridge id)
     kSecAttrKeyClass];
    [privateKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)
     kSecReturnPersistentRef];
    
    CFTypeRef persistKey = nil;
    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)privateKey, &persistKey);
    if (persistKey != nil){
        CFRelease(persistKey);
    }
    if ((status != noErr) && (status != errSecDuplicateItem)) {
        return nil;
    }
    
    [privateKey removeObjectForKey:(__bridge id)kSecValueData];
    [privateKey removeObjectForKey:(__bridge id)kSecReturnPersistentRef];
    [privateKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];
    [privateKey setObject:(__bridge id) kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    
    // Now fetch the SecKeyRef version of the key
    SecKeyRef keyRef = nil;
    status = SecItemCopyMatching((__bridge CFDictionaryRef)privateKey, (CFTypeRef *)&keyRef);
    if(status != noErr){
        return nil;
    }
    return keyRef;
}

+ (NSData*)privateKeyDecodeBase64:(NSString*)base64String{
    
    NSRange spos = [base64String rangeOfString:@"-----BEGIN PRIVATE KEY-----"];
    
    if (spos.location == NSNotFound) {
        spos = [base64String rangeOfString:@"-----BEGIN RSA PRIVATE KEY-----"];
    }
    
    
    NSRange epos = [base64String rangeOfString:@"-----END PRIVATE KEY-----"];
    
    if (epos.location == NSNotFound) {
        epos = [base64String rangeOfString:@"-----END RSA PRIVATE KEY-----"];
    }

    if(spos.location != NSNotFound && epos.location != NSNotFound){
        NSUInteger s = spos.location + spos.length;
        NSUInteger e = epos.location;
        NSRange range = NSMakeRange(s, e-s);
        base64String = [base64String substringWithRange:range];
    }
    base64String = [base64String stringByReplacingOccurrencesOfString:@"\r" withString:@""];
    base64String = [base64String stringByReplacingOccurrencesOfString:@"\n" withString:@""];
    base64String = [base64String stringByReplacingOccurrencesOfString:@"\t" withString:@""];
    base64String = [base64String stringByReplacingOccurrencesOfString:@" "  withString:@""];
    
    NSDataBase64DecodingOptions options;
    options = NSDataBase64DecodingIgnoreUnknownCharacters;
    return [[NSData alloc] initWithBase64EncodedString:base64String options:options];
}



+ (NSData *)stripPrivateKeyHeader:(NSData *)d_key
{
    
    
    if (d_key == nil) return(nil);
    
    unsigned long len = [d_key length];
    if (!len) return(nil);
    
    unsigned char *c_key = (unsigned char *)[d_key bytes];
    unsigned int  idx     = 22; //magic byte at offset 22
    
    
    
    if (0x04 != c_key[idx++]) return d_key;
    
    //calculate length of the key
    unsigned int c_len = c_key[idx++];
    int det = c_len & 0x80;
    
    
    if (!det) {
        c_len = c_len & 0x7f;
    } else {
        int byteCount = c_len & 0x7f;
        if (byteCount + idx > len) {
            //rsa length field longer than buffer
            return nil;
        }
        unsigned int accum = 0;
        unsigned char *ptr = &c_key[idx];
        idx += byteCount;
        while (byteCount) {
            accum = (accum << 8) + *ptr;
            ptr++;
            byteCount--;
        }
        c_len = accum;
    }
    
    // Now make a new NSData from this buffer
    return [d_key subdataWithRange:NSMakeRange(idx, c_len)];
}


+ (NSData *)encryptData:(NSData *)data withKeyRef:(SecKeyRef)keyRef
{
    const uint8_t *srcbuf = (const uint8_t *)[data bytes];
    size_t srclen = (size_t)data.length;
    
    size_t block_size = SecKeyGetBlockSize(keyRef) * sizeof(uint8_t);
    void *outbuf = malloc(block_size);
    size_t src_block_size = block_size - 11;
    
    NSMutableData *ret = [[NSMutableData alloc] init];
    for (int idx = 0; idx < srclen; idx += src_block_size)
    {
        size_t data_len = srclen - idx;
        if(data_len > src_block_size){
            data_len = src_block_size;
        }
        
        size_t outlen = block_size;
        OSStatus status = noErr;
        status = SecKeyEncrypt(keyRef, kSecPaddingPKCS1,
                               srcbuf + idx, data_len,
                               outbuf, &outlen);
        if (status != 0)
        {
            NSLog(@"SecKeyEncrypt fail. Error Code: %d", (int)status);
            ret = nil;
            break;
        }
        else
        {
            [ret appendBytes:outbuf length:outlen];
        }
    }
    free(outbuf);
    CFRelease(keyRef);
    return ret;
}

+ (SecKeyRef)publicKeyRef:(NSData*)keyData {
    
    
    if ((keyData == nil) || (keyData == NULL)) {
        return nil;
    } else if (![keyData isKindOfClass:[NSData class]]) {
        return nil;
    } else if ([keyData length] <= 0) {
        return nil;
    }
    
    //a tag to read/write keychain storage
    NSString *tag = @"RSAUtil_PubKey";
    const void *bytes = [tag UTF8String];
    NSData *tagData = [NSData dataWithBytes:bytes length:[tag length]];
    
    //Delete any old lingering key with the same tag
    NSMutableDictionary *attributes = [[NSMutableDictionary alloc] init];
    [attributes setObject:(__bridge id)kSecClassKey
                   forKey:(__bridge id)kSecClass];
    [attributes setObject:(__bridge id)kSecAttrKeyTypeRSA
                   forKey:(__bridge id)kSecAttrKeyType];
    [attributes setObject:tagData
                   forKey:(__bridge id)kSecAttrApplicationTag];
    SecItemDelete((__bridge CFDictionaryRef)attributes);
    
    //Add persistent version of the key to system keychain
    [attributes setObject:keyData
                   forKey:(__bridge id)kSecValueData];
    [attributes setObject:(__bridge id)kSecAttrKeyClassPublic
                   forKey:(__bridge id)kSecAttrKeyClass];
    [attributes setObject:[NSNumber numberWithBool:YES]
                   forKey:(__bridge id)kSecReturnPersistentRef];
    
    OSStatus status = noErr;
    CFTypeRef persistKey = nil;
    status = SecItemAdd((__bridge CFDictionaryRef)attributes, &persistKey);
    if (persistKey != nil) CFRelease(persistKey);
    if ((status != noErr) && (status != errSecDuplicateItem))
    {
        return nil;
    }
    [attributes removeObjectForKey:(__bridge id)kSecValueData];
    [attributes removeObjectForKey:(__bridge id)kSecReturnPersistentRef];
    [attributes setObject:[NSNumber numberWithBool:YES]
                   forKey:(__bridge id)kSecReturnRef];
    [attributes setObject:(__bridge id)kSecAttrKeyTypeRSA
                   forKey:(__bridge id)kSecAttrKeyType];
    
    //Now fetch the SecKeyRef version of the key
    SecKeyRef publicKeyRef = nil;
    CFDictionaryRef query = (__bridge CFDictionaryRef)attributes;
    status = SecItemCopyMatching(query, (CFTypeRef *)&publicKeyRef);
    if (status != noErr)
    {
        return nil;
    }
    return publicKeyRef;
}

+ (NSData *)stripPublicKeyHeader:(NSData *)d_key
{
    //Skip ASN.1 public key header
    if (d_key == nil) {return nil;}
    
    unsigned long len = [d_key length];
    if (!len) return(nil);
    
    unsigned char *c_key = (unsigned char *)[d_key bytes];
    unsigned int idx = 0;
    if (c_key[idx++] != 0x30) {return nil;}
    if (c_key[idx] > 0x80)
    {
        idx += c_key[idx] - 0x80 + 1;
    }
    else
    {
        idx++;
    }
    
    //PKCS #1 rsaEncryption szOID_RSA_RSA
    static unsigned char seqiod[] = {0x30, 0x0d, 0x06, 0x09, 0x2a,
        0x86, 0x48, 0x86, 0xf7, 0x0d,
        0x01, 0x01, 0x01, 0x05, 0x00};
    if (memcmp(&c_key[idx], seqiod, 15)) {return nil;}
    idx += 15;
    if (c_key[idx++] != 0x03) {return nil;}
    if (c_key[idx] > 0x80)
    {
        idx += c_key[idx] - 0x80 + 1;
    }
    else
    {
        idx ++;
    }
    if (c_key[idx++] != '\0') {return nil;}
    
    //Now make a new NSData from this buffer
    return ([NSData dataWithBytes:&c_key[idx] length:len - idx]);
}

+ (NSData*)publicKeyDecodeBase64:(NSString*)base64String{
    NSRange spos = [base64String rangeOfString:@"-----BEGIN PUBLIC KEY-----"];
    
    
    NSRange epos = [base64String rangeOfString:@"-----END PUBLIC KEY-----"];

    
    if(spos.location != NSNotFound && epos.location != NSNotFound){
        NSUInteger s = spos.location + spos.length;
        NSUInteger e = epos.location;
        NSRange range = NSMakeRange(s, e-s);
        
        base64String = [base64String substringWithRange:range];
    }
    
    base64String = [base64String stringByReplacingOccurrencesOfString:@"\r" withString:@""];
    base64String = [base64String stringByReplacingOccurrencesOfString:@"\n" withString:@""];
    base64String = [base64String stringByReplacingOccurrencesOfString:@"\t" withString:@""];
    base64String = [base64String stringByReplacingOccurrencesOfString:@" "  withString:@""];
    
    NSDataBase64DecodingOptions options;
    options = NSDataBase64DecodingIgnoreUnknownCharacters;
    return [[NSData alloc] initWithBase64EncodedString:base64String options:options];
}


@end
