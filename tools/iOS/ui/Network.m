/*
 * Copyright (c) 2012, Andres Blanco and Matias Eissler
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    This product includes software developed by the authors.
 * 4. Neither the name of the authors nor the
 *    names of its contributors may be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#import "network.h"

@implementation Network

@synthesize ssid;
@synthesize bssid;
@synthesize protection;
@synthesize rssi;
@synthesize rssiString;
@synthesize channel;
@synthesize channelString;
@synthesize viewPosition;

+(id)networkWithDictionary:(NSDictionary *)aDictionary
{
    return [[[self alloc] initWithDictionary:aDictionary] autorelease];
}

-(id)initWithDictionary:(NSDictionary *)aDictionary
{
    self = [super init];
    self.ssid = [aDictionary objectForKey:@"ssid"];
    self.bssid = [aDictionary objectForKey:@"bssid"];
    self.rssi = [[aDictionary objectForKey:@"rssi"] intValue];
    self.rssiString = [NSString stringWithFormat: @"%d", self.rssi];
    self.channel = [[aDictionary objectForKey:@"channel"] intValue];
    self.channelString = [NSString stringWithFormat: @"%d", self.channel];
    self.protection = [aDictionary objectForKey:@"protection"];
    self.viewPosition = 0;
    return self;
}

@end

NSInteger protectionToInt(Network *n)
{
	if([n.protection compare:@"OPEN"] == NSOrderedSame)
		return 0;
	else if([n.protection compare:@"WEP"] == NSOrderedSame)
		return 1;
	else if([n.protection compare:@"WPA"] == NSOrderedSame)
		return 2;
	else if([n.protection compare:@"WPA2"] == NSOrderedSame)
		return 3;
	return 4; //??
}

NSInteger compareNetworks(id n1, id n2, void *field)
{
    NSString *sortKey = (NSString *)field;
    SEL keySelector = NSSelectorFromString(sortKey);

    int i1;
    int i2; 
 	if([sortKey compare:@"protection"] == NSOrderedSame) {
		i1 = protectionToInt(n1);
		i2 = protectionToInt(n2);
	}
	else {
 		i1 = (int)objc_msgSend(n1, keySelector);
		i2 = (int)objc_msgSend(n2, keySelector);
		if([sortKey compare:@"rssi"] == NSOrderedSame) {
			int tmp = i1;
			i1 = i2;
			i2 = tmp;
		} 
	}

    if(i1 > i2)
        return (NSComparisonResult)NSOrderedDescending;
    else if (i1 < i2)
        return (NSComparisonResult)NSOrderedAscending;
    else
        return (NSComparisonResult)NSOrderedSame;
}
