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


#import "NetworkDetailController.h"
#import "Manager.h"

/*
 *
 * Class NetworksViewController: Manages network table view.
 *
 *
 */

@implementation NetworkDetailController 

-(NetworkDetailController *)initWithName:(NSString *)ssid
{
    [super initWithStyle: UITableViewStyleGrouped];

    // Current clients.
    // clientList = [[NSMutableArray alloc] initWithCapacity: 10];
    networkData = [[NSMutableArray alloc] initWithObjects:@"SSID",@"BSSID",@"Vendor",@"Signal",@"Protection",@"IVs/Handshackes",@"WPS",nil]; 
    clientList = [[NSMutableArray alloc] initWithCapacity:10]; //@"client1",@"client2",@"cient3",nil];

	self.navigationItem.leftBarButtonItem = [[[UIBarButtonItem alloc] 	initWithTitle:@"back" 
																		style:UIBarButtonItemStylePlain 
																		target:self
																		action:@selector(backTapped:)] autorelease];

    self.navigationItem.title = ssid;
    return self;

}

-(IBAction)backTapped:(id)sender
{
    Manager *mgr = [Manager getInstance];
    [mgr unsetNetwork];
    [((UINavigationController *)[self parentViewController]) popViewControllerAnimated:YES]; 
}

-(void)updateNetworkDetail:(NetworkDetail *)newNetworkDetail
{
    [clientList setArray: newNetworkDetail.clients];
    [self.tableView reloadData];
}
    

-(void)dealloc
{
    [clientList release];
    [networkData release];
    [super dealloc];
}

- (int)numberOfSectionsInTableView:(UITableView *)tableView
{
    return 2;
}

- (int)tableView:(UITableView *)tableView numberOfRowsInSection:(int)section
{
    if(section == 0)
        return [networkData count];
    else
        return [clientList count];
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
    static NSString *netId = @"detail";

    // Try to retrieve from the table view a now-unused cell with the given identifier.
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:netId];
    if (cell == nil) {
        cell = [[[UITableViewCell alloc] initWithStyle:UITableViewCellStyleValue1 reuseIdentifier:netId] autorelease];
    }

    if(indexPath.section == 0) {
        cell.textLabel.text = [networkData objectAtIndex:indexPath.row];
        cell.detailTextLabel.text = @"blablabla";
    }
    else if(indexPath.section == 1) {
        NSDictionary *station = [clientList objectAtIndex:indexPath.row];
        NSString *client = [station objectForKey: @"addr"];
        client = [client stringByAppendingString: @" ("];
        client = [client stringByAppendingString: [station objectForKey: @"vendor"]];
        client = [client stringByAppendingString: @")"];
        cell.textLabel.text = client;
        cell.detailTextLabel.text = [[station objectForKey: @"sentDataFrames"] stringValue];
    }


    return cell;
}

@end
