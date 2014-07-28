//
//  CMSViewController.m
//  RSA
//
//  Created by test on 14-7-15.
//  Copyright (c) 2014年 kanon. All rights reserved.
//

#import "CMSViewController.h"
#import "CRSA.h"

@interface CMSViewController ()

@end

@implementation CMSViewController

- (void)viewDidLoad
{
    [super viewDidLoad];
    
    CRSA *rsa = [CRSA shareInstance];
    [rsa importRSAKeyWithType:KeyTypePublic];

    [rsa importRSAKeyWithType:KeyTypePrivate];
    
    
   NSString *datastr =  [rsa encryptByRsa:@"13812152203" withKeyType:KeyTypePublic];
    
    NSString *str =  [rsa decryptByRsa:datastr withKeyType:KeyTypePrivate];
    NSLog(@"私钥解密 = %@",str);

    NSString *sf = [rsa decryptByRsa:@"UQwHVjVYJAokLjETlq7gCY7CwDSPai2BqQYfzWcF5mn+hYr6aGslV9vBCgEBfv/E5CgDx483YXoVgfToXj9HPUnyUTYqliMprBF1+8CMABgred4L8YEqBmuy0aIlTiE7pIpYqEON6webLk9VPmkp4Iz+7Ec9xPP8L8qYAITETh0=" withKeyType:KeyTypePrivate];
    NSLog(@"私钥解密%@",sf);
    
    
//    NSString *str1 =  [rsa decryptByRsa:@"UcIIxWNavBOhBUFHtBUD1n699f2lVMKyqsLRQ+LUz7HFVKIsxCwLcb8quBY23rV5jZZGtkNn0ZD/KZkZTJT2adJqIed6oyGG4uOdUKbTwhpGXLkSw4o/fFoSfsKGwmjCEtr5BrVBJzKM4z+m3cKHckAZRIUY9N6dfGl8lnxx8Ag=" withKeyType:KeyTypePublic];
//    NSLog(@"公钥解密 = %@",str1);
	// Do any additional setup after loading the view, typically from a nib.
}

- (void)didReceiveMemoryWarning
{
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

@end
