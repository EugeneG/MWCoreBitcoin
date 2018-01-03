// CoreBitcoin by Oleg Andreev <oleganza@gmail.com>, WTFPL.

#import <Foundation/Foundation.h>

@class BTCKey;

// Implementation of [ECIES](http://en.wikipedia.org/wiki/Integrated_Encryption_Scheme)
// compatible with [Bitcore ECIES](https://github.com/bitpay/bitcore-ecies) implementation.
@interface BTCEncryptedMessage : NSObject

// When encrypting, sender's keypair must contain a private key.
@property(nonatomic) BTCKey * senderKey;
@property(nonatomic) NSData * senderKeyData;

// When decrypting, recipient's keypair must contain a private key.
@property(nonatomic) BTCKey * recipientKey;
@property(nonatomic) NSData * recipientKeyData;

- (NSData*) encrypt:(NSData*)plaintext;
- (NSData*) encrypt:(NSData*)plaintext shortkEkm:(BOOL)useSHortkEkm usePubKey:(BOOL)usePubKey;

- (NSData*) decrypt:(NSData*)ciphertext;
- (NSData*) decrypt:(NSData*)ciphertext shortkEkm:(BOOL)useSHortkEkm usePubKey:(BOOL)usePubKey;

@end
