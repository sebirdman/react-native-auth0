
#import "A0Auth0.h"

#import <CommonCrypto/CommonCrypto.h>

#if __has_include("RCTUtils.h")
#import "RCTUtils.h"
#else
#import <React/RCTUtils.h>
#endif

@interface A0Auth0 ()
@property (copy, nonatomic) RCTResponseSenderBlock sessionCallback;
@property (assign, nonatomic) BOOL closeOnLoad;
@end

@implementation A0Auth0
- (dispatch_queue_t)methodQueue
{
    return dispatch_get_main_queue();
}

RCT_EXPORT_MODULE();

RCT_EXPORT_METHOD(hide) {
    [self terminateWithError:nil];
}

RCT_EXPORT_METHOD(showUrl:(NSString *)urlString closeOnLoad:(BOOL)closeOnLoad callback:(RCTResponseSenderBlock)callback) {
    [self presentSafariWithURL:[NSURL URLWithString:urlString]];
    self.closeOnLoad = closeOnLoad;
    self.sessionCallback = callback;
}

RCT_EXPORT_METHOD(oauthParameters:(RCTResponseSenderBlock)callback) {
    callback(@[[self generateOAuthParameters]]);
}

- (NSDictionary *)constantsToExport {
    return @{ @"bundleIdentifier": [[NSBundle mainBundle] bundleIdentifier] };
}

#pragma mark - Internal methods

- (void)presentSafariWithURL:(NSURL *)url {
    BOOL opend = [RCTSharedApplication() openURL:url];
    if (!opend) {
        [self terminateWithError:RCTMakeError(@"Failed to open URL", nil, nil)];
    }
}

- (void)terminateWithError:(id)error {
    RCTResponseSenderBlock callback = self.sessionCallback ? self.sessionCallback : ^void(NSArray *_unused) {};
    if (error) {
        callback(@[error]);
    }
    self.sessionCallback = nil;
    self.closeOnLoad = NO;
}

- (NSString *)randomValue {
    NSMutableData *data = [NSMutableData dataWithLength:32];
    int result __attribute__((unused)) = SecRandomCopyBytes(kSecRandomDefault, 32, data.mutableBytes);
    NSString *value = [[[[data base64EncodedStringWithOptions:0]
                         stringByReplacingOccurrencesOfString:@"+" withString:@"-"]
                        stringByReplacingOccurrencesOfString:@"/" withString:@"_"]
                       stringByTrimmingCharactersInSet:[NSCharacterSet characterSetWithCharactersInString:@"="]];
    return value;
}

- (NSString *)sign:(NSString*)value {
    CC_SHA256_CTX ctx;

    uint8_t * hashBytes = malloc(CC_SHA256_DIGEST_LENGTH * sizeof(uint8_t));
    memset(hashBytes, 0x0, CC_SHA256_DIGEST_LENGTH);

    NSData *valueData = [value dataUsingEncoding:NSUTF8StringEncoding];

    CC_SHA256_Init(&ctx);
    CC_SHA256_Update(&ctx, [valueData bytes], (CC_LONG)[valueData length]);
    CC_SHA256_Final(hashBytes, &ctx);

    NSData *hash = [NSData dataWithBytes:hashBytes length:CC_SHA256_DIGEST_LENGTH];

    if (hashBytes) {
        free(hashBytes);
    }

    return [[[[hash base64EncodedStringWithOptions:0]
              stringByReplacingOccurrencesOfString:@"+" withString:@"-"]
             stringByReplacingOccurrencesOfString:@"/" withString:@"_"]
            stringByTrimmingCharactersInSet:[NSCharacterSet characterSetWithCharactersInString:@"="]];
}

- (NSDictionary *)generateOAuthParameters {
    NSString *verifier = [self randomValue];
    return @{
             @"verifier": verifier,
             @"code_challenge": [self sign:verifier],
             @"code_challenge_method": @"S256",
             @"state": [self randomValue]
             };
}

@end
