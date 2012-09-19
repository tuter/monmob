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

#import "NetworksViewController.h"
#import "NetworkDetailController.h"
#import "Manager.h"

/*
 *
 * Class NetworksViewController: Manages network table view.
 *
 *
 */

@implementation NetworksViewController

@synthesize locked;

-(NetworksViewController *)init
{
    [super initWithStyle:UITableViewStylePlain];

    // Sort buttons
    NSArray *btns = [NSArray arrayWithObjects:@"channel",@"privacy",@"rssi",nil];
    sortControl = [[UISegmentedControl alloc] initWithItems:btns];
    sortControl.segmentedControlStyle = UISegmentedControlStyleBar;
    sortControl.selectedSegmentIndex = 2;
    [sortControl addTarget:self action:@selector(sortChanged:) forControlEvents:UIControlEventValueChanged];
    UIBarButtonItem *segmentBarItem = [[[UIBarButtonItem alloc] initWithCustomView:sortControl] autorelease];

	// channel picker
	channelPicker = [[[ChannelPicker alloc] initWithChannel:6 delegate:self] autorelease];
	channelPickerPopover = [[UIPopoverController alloc] initWithContentViewController:channelPicker];

    // Navigation bar.
	self.navigationItem.leftBarButtonItem = [[[UIBarButtonItem alloc] 	initWithTitle:@"channel" 
																		style:UIBarButtonItemStylePlain 
																		target:self
																		action:@selector(channelTapped:)] autorelease];
    self.navigationItem.title = @"wifi fafa";
    self.navigationItem.rightBarButtonItem = segmentBarItem;

    // Current networks.
    networksList = [[NSMutableArray alloc] initWithCapacity: 100];
    networksDict = [[NSMutableDictionary alloc] initWithCapacity:100];

    self.locked = false;
    return self;
}

-(void)dealloc
{
    [networksList release];
    [networksDict release];
    [sortControl release];
    [channelPickerPopover release];
    [super dealloc];
}

-(NSString *)currentOrder
{
    static NSString *orders[] = {@"channel", @"protection", @"rssi"};
    return orders[sortControl.selectedSegmentIndex];
}

-(void)sort
{
    [networksList sortUsingFunction:compareNetworks context:[self currentOrder]];
    NSUInteger i;
    for(i = 0 ; i < [networksList count] ; ++i)
        ((Network *) [networksList objectAtIndex:i]).viewPosition = i;
}

-(void)sortChanged:(id)sender
{
    [self sort];
    [self.tableView reloadData];
}

-(IBAction)channelTapped:(id)sender
{
	[channelPickerPopover presentPopoverFromBarButtonItem:sender 
        permittedArrowDirections:UIPopoverArrowDirectionAny animated:YES];
}

-(void)channelSelected:(int)channel
{
    [channelPickerPopover dismissPopoverAnimated:YES];
    Manager *mgr = [Manager getInstance];
    [mgr setChannel:channel];
}

-(void)addNetwork:(Network *)newNetwork
{
    NSUInteger i;
    NSRange r;

    r.location = 0;
    r.length = [networksList count];
    NSUInteger idx = [networksList indexOfObject:newNetwork inSortedRange:r 
                      options:NSBinarySearchingInsertionIndex usingComparator: 
                      ^(id obj1, id obj2) { return compareNetworks(obj1, obj2, [self currentOrder]); }];
    newNetwork.viewPosition = idx;
    [networksList insertObject:newNetwork atIndex:idx];
    
    [self.tableView insertRowsAtIndexPaths: 
                        [NSArray arrayWithObject: [NSIndexPath indexPathForRow:idx inSection:0]]
                    withRowAnimation:UITableViewRowAnimationNone];
    
    for(i = idx ; i < [networksList count] ; ++i)
        ((Network *)[networksList objectAtIndex:i]).viewPosition = i;
}

-(void)updateNetwork:(Network *)oldNet with:(Network *)newNetwork
{
    NSUInteger high, low, total, i;
    NSUInteger idx = oldNet.viewPosition;
    high = low = idx;
    total = [networksList count];
    [networksList replaceObjectAtIndex:idx withObject:newNetwork];

    while(high < total - 1 &&
          NSOrderedDescending == compareNetworks(newNetwork, 
                                                [networksList objectAtIndex:high+1],
                                                [self currentOrder]))
    {
        [networksList exchangeObjectAtIndex:high withObjectAtIndex:high+1];
        ((Network *)[networksList objectAtIndex:high]).viewPosition = high;
        ++high;
    }
    ((Network *)[networksList objectAtIndex:high]).viewPosition = high;

    while(low > 0 && 
          NSOrderedAscending == compareNetworks(newNetwork, 
                                               [networksList objectAtIndex:low-1],
                                               [self currentOrder]))
    {
        [networksList exchangeObjectAtIndex:low withObjectAtIndex:low-1];
        ((Network *)[networksList objectAtIndex:low]).viewPosition = low;
        --low;
    }
    ((Network *)[networksList objectAtIndex:low]).viewPosition = low;

    NSIndexPath *from = [NSIndexPath indexPathForRow:idx inSection:0];
    NSIndexPath *to = nil; 
    if(low != idx) {
        to = [NSIndexPath indexPathForRow:low inSection:0];
        [self.tableView moveRowAtIndexPath:from toIndexPath:to];
    } else if(high != idx) {
        to = [NSIndexPath indexPathForRow:high inSection:0];
        [self.tableView moveRowAtIndexPath:from toIndexPath:to];
    }

    NSMutableArray *toReload = nil;
    if(to != nil)
        toReload = [NSArray arrayWithObject:to];
    else
        toReload = [NSArray arrayWithObject:from];

    [self.tableView reloadRowsAtIndexPaths:toReload withRowAnimation:UITableViewRowAnimationNone];

}

-(void)updateNetwork:(Network *)newNetwork
{
    if(! self.locked) {
        NSString *bssid = newNetwork.bssid;
        Network *oldNet = [networksDict objectForKey:bssid];
    
        if(oldNet == nil) 
            [self addNetwork: newNetwork];
        else 
            [self updateNetwork:oldNet with:newNetwork];
    
        [networksDict setObject:newNetwork forKey:bssid];
    }
}


- (int)numberOfSectionsInTableView:(UITableView *)tableView
{
    return 1;
}

- (int)tableView:(UITableView *)tableView numberOfRowsInSection:(int)section
{
    return [networksList count];
}

- (UILabel *)createLabelWithTag:(int)tag height:(CGFloat)h alignment:(UITextAlignment)algn
{
    UILabel *lbl = [[[UILabel alloc] initWithFrame:CGRectMake(0.0, 0.0, 220.0, h)] autorelease];
    lbl.tag = tag;
    lbl.font = [UIFont systemFontOfSize:18.0];
    lbl.textAlignment = algn;
    lbl.textColor = [UIColor blackColor];
    lbl.backgroundColor = [UIColor clearColor];
    lbl.autoresizingMask = UIViewAutoresizingFlexibleLeftMargin | UIViewAutoresizingFlexibleHeight;
    return lbl;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath 
{
    static NSString *netId = @"net";
    enum {
        PROTECTION_TAG = 1,
        CHANNEL_TAG,
        RSSI_TAG
    };

    Network *network = [networksList objectAtIndex: indexPath.row];
    UILabel *protectionLabel;
    UILabel *rssiLabel;
    UILabel *channelLabel;

    // Try to retrieve from the table view a now-unused cell with the given identifier.
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:netId];
    if (cell == nil) {
        cell = [[[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:netId] autorelease];

        // Create column labels
        CGFloat h = cell.contentView.bounds.size.height;
        protectionLabel = [self createLabelWithTag:PROTECTION_TAG height:h alignment:UITextAlignmentLeft];
        channelLabel = [self createLabelWithTag:CHANNEL_TAG height:h alignment:UITextAlignmentRight];
        rssiLabel = [self createLabelWithTag:RSSI_TAG height:h alignment:UITextAlignmentCenter];

        // Add labels to new cell.
        [cell.contentView addSubview:protectionLabel];
        [cell.contentView addSubview:channelLabel];
        [cell.contentView addSubview:rssiLabel];
        
    } else {
        rssiLabel = (UILabel *)[cell.contentView viewWithTag:RSSI_TAG];
        channelLabel = (UILabel *)[cell.contentView viewWithTag:CHANNEL_TAG];
        protectionLabel = (UILabel *)[cell.contentView viewWithTag:PROTECTION_TAG];
    }

    cell.textLabel.text = network.ssid;
    cell.detailTextLabel.text = network.bssid;
    cell.accessoryType = UITableViewCellAccessoryDetailDisclosureButton;
    protectionLabel.text = network.protection;
    rssiLabel.text = network.rssiString;
    channelLabel.text = network.channelString;

    return cell;
}

-(void) tableView:(UITableView *)tv accessoryButtonTappedForRowWithIndexPath:(NSIndexPath *) path
{
    Network *net = (Network *)[networksList objectAtIndex: path.row];
    NSString *ssid = net.ssid;
    NSString *bssid = net.bssid;
    Manager *mgr = [Manager getInstance];
    [mgr setNetwork:bssid];

    UIViewController *view = [[NetworkDetailController alloc] initWithName:ssid]; // autorelease];
    mgr.netDetail = (NetworkDetailController *) view;
    [((UINavigationController *)[self parentViewController]) pushViewController:view animated:YES];
}

- (void)scrollViewWillBeginDragging:(UIScrollView *)scrollView
{
    self.locked = true;
}

- (void)scrollViewDidEndDecelerating:(UIScrollView *)scrollView
{
    self.locked = false;
}

@end
