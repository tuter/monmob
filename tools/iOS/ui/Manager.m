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

#import "Manager.h"

// Server Commands:
#define CMD_BEACON_SEEN 0
#define CMD_NETWORK_DETAIL 1

// Client Commands:
#define SET_CHANNEL 0
#define SET_NETWORK 1
#define UNSET_NETWORK 2

// Called when server has a msg for us.
void networkCallback(CFReadStreamRef stream, CFStreamEventType event, void *myPtr);

@implementation Manager
@synthesize nets;
@synthesize netDetail;

// singleton static method.
+(Manager *) getInstance
{
    static Manager *inst = nil;
    if(inst == nil) {
        inst = [[Manager alloc] init];
    }

    return inst;
}

- (Manager *)init
{
    // TODO: Launch server.
    self.nets = nil;
    self.netDetail = nil;

    CFReadStreamRef rStream;
    CFStreamCreatePairWithSocketToHost(kCFAllocatorDefault, CFSTR("127.0.0.1"), 61000, &rStream, &wStream);
    CFStreamClientContext myContext = {0, self, NULL, NULL, NULL};
    CFOptionFlags registeredEvents = kCFStreamEventHasBytesAvailable | kCFStreamEventErrorOccurred | kCFStreamEventEndEncountered;
    CFReadStreamSetClient(rStream, registeredEvents, networkCallback, &myContext);
    CFReadStreamScheduleWithRunLoop(rStream, CFRunLoopGetCurrent(), kCFRunLoopCommonModes);
    CFReadStreamOpen(rStream);
    CFWriteStreamOpen(wStream);
    return self;
}

- (void)updateNetwork: (Network *) newNetwork
{
    if(self.nets != nil) 
        [self.nets updateNetwork: newNetwork];
}

- (void)updateNetworkDetail:(NetworkDetail *)newNetworkDetail
{
    if(self.netDetail != nil)
        [self.netDetail updateNetworkDetail:newNetworkDetail];
}

-(void)sendCmd:(NSDictionary *)d
{
    NSPropertyListFormat xml = NSPropertyListXMLFormat_v1_0;
    NSData *raw = [NSPropertyListSerialization dataWithPropertyList:d format:xml 
                    options:NSPropertyListImmutable error:nil];
    NSUInteger len = [raw length];

    CFWriteStreamWrite(wStream, (UInt8*)&len, sizeof(len));
    CFWriteStreamWrite(wStream, [raw bytes], len);
}

-(void)setChannel:(int) channel
{
    NSDictionary *cmd = [NSDictionary dictionaryWithObjects: [NSArray arrayWithObjects:
                                                                [NSNumber numberWithInt:SET_CHANNEL],
                                                                [NSNumber numberWithInt:channel], nil]
                                      forKeys: [NSArray arrayWithObjects: @"command", @"channel", nil]];

    [self sendCmd:cmd];
}

-(void)setNetwork:(NSString *)bssid
{
    NSDictionary *cmd = [NSDictionary dictionaryWithObjects: [NSArray arrayWithObjects:
                                                                [NSNumber numberWithInt:SET_NETWORK],
                                                                bssid, nil]
                                      forKeys: [NSArray arrayWithObjects: @"command", @"bssid", nil]];

    [self sendCmd:cmd];
}

-(void)unsetNetwork
{
    NSDictionary *cmd = [NSDictionary dictionaryWithObjects: [NSArray arrayWithObjects:
                                                                [NSNumber numberWithInt:UNSET_NETWORK],
                                                                nil]
                                      forKeys: [NSArray arrayWithObjects: @"command", nil]];

    [self sendCmd:cmd];
}

@end


void networkCallback (CFReadStreamRef stream, CFStreamEventType event, void *myPtr)
{
    CFIndex bytesRead;
    Manager *mgr = (Manager *)myPtr;
	UInt32 cmdLen;
    int cmd_id;

    switch(event) {
        case kCFStreamEventHasBytesAvailable:
            bytesRead = CFReadStreamRead(stream, (void *)&cmdLen, sizeof(cmdLen)); // Esto podria hacer short read
			if(bytesRead == 4) {
                UInt8 *buf = malloc(cmdLen);
				if(buf != NULL) {
                    NSData *raw = [NSData dataWithBytesNoCopy: buf length: cmdLen freeWhenDone: YES];
                    bytesRead = CFReadStreamRead(stream, (void *)buf, cmdLen); // Esto podria hacer short read

                    NSPropertyListFormat xml = NSPropertyListXMLFormat_v1_0;
                    NSDictionary *cmd = [NSPropertyListSerialization propertyListWithData: raw
                        options: NSPropertyListImmutable
                        format: &xml 
                        error: nil];

                    cmd_id = [((NSNumber *)[cmd objectForKey: @"command"]) intValue];
                    if(cmd_id  == CMD_BEACON_SEEN) {
	                	Network *newNetwork = [Network networkWithDictionary:cmd];
	                	[mgr updateNetwork:newNetwork];
					}
                    else if(cmd_id == CMD_NETWORK_DETAIL)   {
                        NetworkDetail *newNetworkDetail = [NetworkDetail networkDetailWithDictionary:cmd];
                        [mgr updateNetworkDetail:newNetworkDetail];
                    }
	            }
			}
            break;
        case kCFStreamEventErrorOccurred:
            /* 
            CFStreamError error = CFReadStreamGetError(stream);
            reportError(error);
            CFReadStreamUnscheduleFromRunLoop(stream, CFRunLoopGetCurrent(),
                                              kCFRunLoopCommonModes);
            CFReadStreamClose(stream);
            CFRelease(stream);
             */
            break;
        case kCFStreamEventEndEncountered:
            /* 
            reportCompletion();
            CFReadStreamUnscheduleFromRunLoop(stream, CFRunLoopGetCurrent(),
                                              kCFRunLoopCommonModes);
            CFReadStreamClose(stream);
            CFRelease(stream);
            */
            break;
    }
}
