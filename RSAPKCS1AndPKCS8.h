//
//  RSAPKCS1AndPKCS8.h
//  果物戦争
//
//  Created by yons on 2019/3/22.
//  Copyright © 2019年 cxzswq. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface RSAPKCS1AndPKCS8 : NSObject

+ (NSString*)encodeRsa:(NSString*)dataString andPublicKeyPath:(NSString*)filePath;

+ (NSString*)decodeRsa:(NSString*)dataString andPublicKeyPath:(NSString*)filePath;

@end
