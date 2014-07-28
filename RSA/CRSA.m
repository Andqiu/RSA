#import "CRSA.h"

#define BUFFSIZE  1024
#import "Base64.h"

#define PADDING RSA_PADDING_TYPE_PKCS1
@implementation CRSA

+ (id)shareInstance
{
    static CRSA *_crsa = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        _crsa = [[self alloc] init];
    });
    return _crsa;
}
- (BOOL)importRSAKeyWithType:(KeyType)type
{
    FILE *file;
    NSString *keyName = type == KeyTypePublic ? @"rsa_public_key" : @"rsa_private_key";
    NSString *keyPath = [[NSBundle mainBundle] pathForResource:keyName ofType:@"pem"];
    
    file = fopen([keyPath UTF8String], "rb");
    
    if (NULL != file)
    {
        if (type == KeyTypePublic)
        {
            _rsa = PEM_read_RSA_PUBKEY(file, NULL, NULL, NULL);
            assert(_rsa != NULL);
        }
        else
        {
            _rsa = PEM_read_RSAPrivateKey(file, NULL, NULL, NULL);
            assert(_rsa != NULL);
        }
        
        fclose(file);
        
        return (_rsa != NULL) ? YES : NO;
    }
    
    return NO;
}

- (NSString *) encryptByRsa:(NSString*)content withKeyType:(KeyType)keyType
{
    if (![self importRSAKeyWithType:keyType])
         return nil;
    
    NSData *d = [content dataUsingEncoding:NSUTF8StringEncoding];
            int length  = [d length];
            unsigned char input[length];
            bzero(input, sizeof(input));
            memcpy(input, [d bytes], [d length]);
    
            unsigned char to[128];
            bzero(to, sizeof(to));
    
    int status;
//    int length  = [content length];
//    unsigned char input[length + 1];
//    bzero(input, length + 1);
//    int i = 0;
//    for (; i < length; i++)
//    {
//        input[i] = [content characterAtIndex:i];
//    }
    
    NSInteger  flen = [self getBlockSizeWithRSA_PADDING_TYPE:PADDING];
    
    char *encData = (char*)malloc(flen);
    bzero(encData, flen);
    
    switch (keyType) {
        case KeyTypePublic:
            status = RSA_public_encrypt(length, (unsigned char*)input, (unsigned char*)encData, _rsa, PADDING);
            break;
            
        default:
            status = RSA_private_encrypt(length, (unsigned char*)input, (unsigned char*)encData, _rsa, PADDING);
            break;
    }
    
    if (status)
    {
        NSData *returnData = [NSData dataWithBytes:encData length:status];
        free(encData);
        encData = NULL;
        
        NSString *ret = [returnData base64EncodedString];
        return ret;
    }
    
    free(encData);
    encData = NULL;
    
    return nil;
//    NSData *d = [content dataUsingEncoding:NSUTF8StringEncoding];
//    
//    if (d && [d length]) {
//        int flen = [d length];
//        unsigned char from[flen];
//        bzero(from, sizeof(from));
//        memcpy(from, [d bytes], [d length]);
//        
//        unsigned char to[128];
//        bzero(to, sizeof(to));
//        
//        [self encryptRSAKeyWithType:keyType :from :flen :to :PADDING];
//        
//        return [[NSData dataWithBytes:to length:sizeof(to)] base64EncodedString];
//        
//    }
//    return nil;
}

- (int)encryptRSAKeyWithType:(KeyType)keyType :(const unsigned char *)from :(int)flen :(unsigned char *)to :(RSA_PADDING_TYPE)padding{
    if (from != NULL && to != NULL) {
        int status = RSA_check_key(_rsa);
        if (!status) {
            NSLog(@"status code %i",status);
            return -1;
        }
        switch (keyType) {
            case KeyTypePrivate:{
                //start encrypt
                status =  RSA_private_encrypt(flen, from,to, _rsa,  padding);
            }
                break;
                
            default:{
                //start encrypt
                status =  RSA_public_encrypt(flen,from,to, _rsa,  padding);
            }
                break;
        }
        
        return status;
    }return -1;
}


- (NSString *) decryptByRsa:(NSString*)content withKeyType:(KeyType)keyType
{
    if (![self importRSAKeyWithType:keyType])
        return nil;
    
    int status;

    NSData *data = [content base64DecodedData];
    int length = [data length];
    
    NSInteger flen = [self getBlockSizeWithRSA_PADDING_TYPE:PADDING];
    char *decData = (char*)malloc(flen);
    bzero(decData, flen);
    
    switch (keyType) {
        case KeyTypePublic:
            status = RSA_public_decrypt(length, (unsigned char*)[data bytes], (unsigned char*)decData, _rsa, PADDING);
            break;
            
        default:
            status = RSA_private_decrypt(length, (unsigned char*)[data bytes], (unsigned char*)decData, _rsa, PADDING);
            break;
    }
    
    if (status)
    {
        NSMutableString *decryptString = [[NSMutableString alloc] initWithBytes:decData length:strlen(decData) encoding:NSUTF8StringEncoding];
        free(decData);
        decData = NULL;
        
        return decryptString;
    }
    
    free(decData);
    decData = NULL;
    
    return nil;
}

- (int)getBlockSizeWithRSA_PADDING_TYPE:(RSA_PADDING_TYPE)padding_type
{
    int len = RSA_size(_rsa);
    
    if (padding_type == RSA_PADDING_TYPE_PKCS1 || padding_type == RSA_PADDING_TYPE_SSLV23) {
        len -= 11;
    }
    
    return len;
}
@end
