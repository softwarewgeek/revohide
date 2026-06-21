//
//  DOSettingsController.m
//  Dopamine
//
//  Created by tomt000 on 08/01/2024.
//

#import "DOSettingsController.h"
#import <objc/runtime.h>
#import <Photos/Photos.h>
#import <libjailbreak/util.h>
#import "DOUIManager.h"
#import "DOPkgManagerPickerViewController.h"
#import "DOHeaderCell.h"
#import "DOEnvironmentManager.h"
#import "DOExploitManager.h"
#import "DOPSListItemsController.h"
#import "DOPSExploitListItemsController.h"
#import "DOThemeManager.h"
#import "DOSceneDelegate.h"
#import "DOPSJetsamListItemsController.h"
#import "DOButtonCell.h"

// ─── Revohide hook-log viewer ─────────────────────────────────────────────────
// Reads from POSIX shared memory (/revohide) written by systemhook/launchdhook.
// Nothing is stored on disk — the segment lives in RAM and disappears on reboot.

#import <sys/mman.h>
#import <fcntl.h>
#import <sys/stat.h>

#define RH_SHM_NAME  "/revohide"
#define RH_SHM_TOTAL (1 << 18)
#define RH_BUF_CAP   (RH_SHM_TOTAL - 8)

typedef struct {
    volatile uint32_t write_pos;
    volatile uint32_t enabled;   // 1 = logging on, 0 = off
    char buf[RH_SHM_TOTAL - 8];
} rh_ui_shm_t;

@interface DORevohideLogViewController : UIViewController
@property (nonatomic, strong) UITextView  *textView;
@property (nonatomic, strong) UILabel     *emptyLabel;
@property (nonatomic, strong) UILabel     *statusLabel;
@property (nonatomic, strong) NSTimer     *refreshTimer;
@property (nonatomic, assign) NSUInteger   lastWritePos;
@end

@implementation DORevohideLogViewController

- (NSString *)readShm {
    int fd = shm_open(RH_SHM_NAME, O_RDONLY, 0);
    if (fd < 0) return nil;
    void *m = mmap(NULL, RH_SHM_TOTAL, PROT_READ, MAP_SHARED, fd, 0);
    close(fd);
    if (m == MAP_FAILED) return nil;
    rh_ui_shm_t *shm = (rh_ui_shm_t *)m;
    uint32_t pos = shm->write_pos;
    NSString *result = nil;
    if (pos > 0 && pos <= RH_BUF_CAP) {
        result = [[NSString alloc] initWithBytes:shm->buf length:pos encoding:NSUTF8StringEncoding];
    }
    munmap(m, RH_SHM_TOTAL);
    return result;
}

- (void)clearShm {
    int fd = shm_open(RH_SHM_NAME, O_RDWR, 0);
    if (fd < 0) return;
    void *m = mmap(NULL, RH_SHM_TOTAL, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if (m == MAP_FAILED) return;
    rh_ui_shm_t *shm = (rh_ui_shm_t *)m;
    uint32_t savedEnabled = shm->enabled;
    shm->write_pos = 0;
    shm->buf[0] = '\0';
    shm->enabled = savedEnabled; // preserve toggle state after clear
    munmap(m, RH_SHM_TOTAL);
    _lastWritePos = 0;
}

// ── Logging toggle helpers (used by DOSettingsController) ─────────────────────
+ (BOOL)isLoggingEnabled {
    int fd = shm_open(RH_SHM_NAME, O_RDONLY, 0);
    if (fd < 0) return NO; // default off if shm not yet created
    void *m = mmap(NULL, RH_SHM_TOTAL, PROT_READ, MAP_SHARED, fd, 0);
    close(fd);
    if (m == MAP_FAILED) return YES;
    rh_ui_shm_t *shm = (rh_ui_shm_t *)m;
    BOOL result = (shm->enabled != 0);
    munmap(m, RH_SHM_TOTAL);
    return result;
}

+ (void)setLoggingEnabled:(BOOL)on {
    int fd = shm_open(RH_SHM_NAME, O_CREAT | O_RDWR, 0600);
    if (fd < 0) return;
    struct stat st;
    if (fstat(fd, &st) == 0 && st.st_size == 0) ftruncate(fd, RH_SHM_TOTAL);
    void *m = mmap(NULL, RH_SHM_TOTAL, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if (m == MAP_FAILED) return;
    ((rh_ui_shm_t *)m)->enabled = on ? 1 : 0;
    munmap(m, RH_SHM_TOTAL);
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"Revohide Log";
    self.view.backgroundColor = [UIColor colorWithRed:0.05 green:0.05 blue:0.08 alpha:1];

    UIBarButtonItem *share = [[UIBarButtonItem alloc]
        initWithBarButtonSystemItem:UIBarButtonSystemItemAction
        target:self action:@selector(shareLog)];
    UIBarButtonItem *copy = [[UIBarButtonItem alloc]
        initWithTitle:@"Copy" style:UIBarButtonItemStylePlain
        target:self action:@selector(copyLog)];
    UIBarButtonItem *clear = [[UIBarButtonItem alloc]
        initWithTitle:@"Clear" style:UIBarButtonItemStylePlain
        target:self action:@selector(clearLog)];
    self.navigationItem.rightBarButtonItems = @[share, copy, clear];

    // Terminal-style text view
    _textView = [[UITextView alloc] initWithFrame:CGRectZero];
    _textView.translatesAutoresizingMaskIntoConstraints = NO;
    _textView.editable = NO;
    _textView.selectable = YES;
    _textView.backgroundColor = [UIColor clearColor];
    _textView.textColor = [UIColor colorWithRed:0.2 green:1.0 blue:0.4 alpha:1];
    _textView.font = [UIFont monospacedSystemFontOfSize:11 weight:UIFontWeightRegular];
    _textView.textContainerInset = UIEdgeInsetsMake(8,8,8,8);
    [self.view addSubview:_textView];

    // Status bar at bottom: shows live refresh indicator
    _statusLabel = [[UILabel alloc] init];
    _statusLabel.translatesAutoresizingMaskIntoConstraints = NO;
    _statusLabel.text = @"● Live";
    _statusLabel.textColor = [UIColor colorWithRed:0.2 green:1.0 blue:0.4 alpha:0.6];
    _statusLabel.font = [UIFont monospacedSystemFontOfSize:10 weight:UIFontWeightRegular];
    _statusLabel.textAlignment = NSTextAlignmentRight;
    [self.view addSubview:_statusLabel];

    // Empty state
    _emptyLabel = [[UILabel alloc] init];
    _emptyLabel.translatesAutoresizingMaskIntoConstraints = NO;
    _emptyLabel.text = @"No hooks fired yet.\n\nOpen Revolut, then return here.";
    _emptyLabel.numberOfLines = 0;
    _emptyLabel.textAlignment = NSTextAlignmentCenter;
    _emptyLabel.textColor = [UIColor colorWithWhite:0.4 alpha:1];
    _emptyLabel.font = [UIFont systemFontOfSize:15];
    [self.view addSubview:_emptyLabel];

    [NSLayoutConstraint activateConstraints:@[
        [_statusLabel.leadingAnchor  constraintEqualToAnchor:self.view.leadingAnchor  constant:8],
        [_statusLabel.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor constant:-8],
        [_statusLabel.bottomAnchor   constraintEqualToAnchor:self.view.safeAreaLayoutGuide.bottomAnchor constant:-4],
        [_statusLabel.heightAnchor   constraintEqualToConstant:16],

        [_textView.topAnchor    constraintEqualToAnchor:self.view.safeAreaLayoutGuide.topAnchor],
        [_textView.leadingAnchor  constraintEqualToAnchor:self.view.leadingAnchor],
        [_textView.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor],
        [_textView.bottomAnchor constraintEqualToAnchor:_statusLabel.topAnchor constant:-2],

        [_emptyLabel.centerXAnchor constraintEqualToAnchor:self.view.centerXAnchor],
        [_emptyLabel.centerYAnchor constraintEqualToAnchor:self.view.centerYAnchor],
        [_emptyLabel.leadingAnchor  constraintEqualToAnchor:self.view.leadingAnchor  constant:32],
        [_emptyLabel.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor constant:-32],
    ]];

    [self reloadLog];
}

- (void)viewDidAppear:(BOOL)animated {
    [super viewDidAppear:animated];
    _refreshTimer = [NSTimer scheduledTimerWithTimeInterval:2.0 target:self
        selector:@selector(reloadLog) userInfo:nil repeats:YES];
}

- (void)viewDidDisappear:(BOOL)animated {
    [super viewDidDisappear:animated];
    [_refreshTimer invalidate];
    _refreshTimer = nil;
}

- (void)reloadLog {
    NSString *content = [self readShm];
    if (content.length) {
        _textView.text = content;
        NSUInteger pos = content.length;
        if (pos != _lastWritePos) {
            [_textView scrollRangeToVisible:NSMakeRange(pos > 0 ? pos - 1 : 0, 1)];
            _lastWritePos = pos;
        }
        _textView.hidden   = NO;
        _emptyLabel.hidden = YES;
        NSUInteger lines = [[content componentsSeparatedByString:@"\n"] count];
        _statusLabel.text = [NSString stringWithFormat:@"● Live  |  %lu entries", (unsigned long)lines];
    } else {
        _textView.hidden   = YES;
        _emptyLabel.hidden = NO;
        _statusLabel.text  = @"● Live  |  waiting…";
    }
}

- (void)shareLog {
    NSString *text = _textView.text;
    if (!text.length) {
        UIAlertController *a = [UIAlertController alertControllerWithTitle:@"No Log"
            message:@"Nothing captured yet." preferredStyle:UIAlertControllerStyleAlert];
        [a addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
        [self presentViewController:a animated:YES completion:nil];
        return;
    }
    UIActivityViewController *ac = [[UIActivityViewController alloc]
        initWithActivityItems:@[text] applicationActivities:nil];
    ac.popoverPresentationController.barButtonItem = self.navigationItem.rightBarButtonItems.firstObject;
    [self presentViewController:ac animated:YES completion:nil];
}

- (void)copyLog {
    NSString *text = _textView.text;
    if (!text.length) {
        UIAlertController *a = [UIAlertController alertControllerWithTitle:@"No Log"
            message:@"Nothing captured yet." preferredStyle:UIAlertControllerStyleAlert];
        [a addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
        [self presentViewController:a animated:YES completion:nil];
        return;
    }
    [[UIPasteboard generalPasteboard] setString:text];
    // Brief toast-style confirmation — no modal
    UIAlertController *a = [UIAlertController alertControllerWithTitle:nil
        message:@"Copied to clipboard" preferredStyle:UIAlertControllerStyleAlert];
    [self presentViewController:a animated:YES completion:^{
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.8 * NSEC_PER_SEC)),
            dispatch_get_main_queue(), ^{ [a dismissViewControllerAnimated:YES completion:nil]; });
    }];
}

- (void)clearLog {
    UIAlertController *a = [UIAlertController alertControllerWithTitle:@"Clear Log"
        message:@"Wipe all captured entries from memory?" preferredStyle:UIAlertControllerStyleAlert];
    [a addAction:[UIAlertAction actionWithTitle:@"Clear" style:UIAlertActionStyleDestructive handler:^(UIAlertAction *_) {
        [self clearShm];
        [self reloadLog];
    }]];
    [a addAction:[UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:nil]];
    [self presentViewController:a animated:YES completion:nil];
}
@end

// ─────────────────────────────────────────────────────────────────────────────

@interface DOSettingsController ()

@end

@implementation DOSettingsController

- (void)viewDidLoad
{
    _lastKnownTheme = [[DOThemeManager sharedInstance] enabledTheme].key;
    [super viewDidLoad];
}

- (void)viewWillAppear:(BOOL)arg1
{
    [super viewWillAppear:arg1];
    if (_lastKnownTheme != [[DOThemeManager sharedInstance] enabledTheme].key)
    {
        [DOSceneDelegate relaunch];
        NSString *icon = [[DOThemeManager sharedInstance] enabledTheme].icon;
        [[UIApplication sharedApplication] setAlternateIconName:icon completionHandler:^(NSError * _Nullable error) {
            if (error)
                NSLog(@"Error changing app icon: %@", error);
        }];

        if ([DOEnvironmentManager sharedManager].isJailbroken) {
            dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                [[DOEnvironmentManager sharedManager] updateBootLogo];
            });
        }
    }
}

- (NSArray *)availableKernelExploitIdentifiers
{
    NSMutableArray *identifiers = [NSMutableArray new];
    for (DOExploit *exploit in _availableKernelExploits) {
        [identifiers addObject:exploit.identifier];
    }
    return identifiers;
}

- (NSArray *)availableKernelExploitNames
{
    NSMutableArray *names = [NSMutableArray new];
    for (DOExploit *exploit in _availableKernelExploits) {
        [names addObject:exploit.name];
    }
    return names;
}

- (NSArray *)availablePACBypassIdentifiers
{
    NSMutableArray *identifiers = [NSMutableArray new];
    if (![DOEnvironmentManager sharedManager].isPACBypassRequired) {
        [identifiers addObject:@"none"];
    }
    for (DOExploit *exploit in _availablePACBypasses) {
        [identifiers addObject:exploit.identifier];
    }
    return identifiers;
}

- (NSArray *)availablePACBypassNames
{
    NSMutableArray *names = [NSMutableArray new];
    if (![DOEnvironmentManager sharedManager].isPACBypassRequired) {
        [names addObject:DOLocalizedString(@"None")];
    }
    for (DOExploit *exploit in _availablePACBypasses) {
        [names addObject:exploit.name];
    }
    return names;
}

- (NSArray *)availablePPLBypassIdentifiers
{
    NSMutableArray *identifiers = [NSMutableArray new];
    for (DOExploit *exploit in _availablePPLBypasses) {
        [identifiers addObject:exploit.identifier];
    }
    return identifiers;
}

- (NSArray *)availablePPLBypassNames
{
    NSMutableArray *names = [NSMutableArray new];
    for (DOExploit *exploit in _availablePPLBypasses) {
        [names addObject:exploit.name];
    }
    return names;
}

- (NSArray *)themeIdentifiers
{
    return [[DOThemeManager sharedInstance] getAvailableThemeKeys];
}

- (NSArray *)themeNames
{
    return [[DOThemeManager sharedInstance] getAvailableThemeNames];
}

- (NSArray *)jetsamOptionNumbers
{
    return @[
    @2,
    @3,
    @4,
    @5,
    @6,
    @7,
    @8,
    ];
}

- (NSArray *)jetsamOptionTitles
{
    return @[
        @"1x",
        @"1.5x",
        @"2x",
        @"2.5x",
        [NSString stringWithFormat:@"3x (%@)", DOLocalizedString(@"Recommended")],
        @"3.5x",
        @"4x",
    ];
}

- (id)specifiers
{
    if(_specifiers == nil) {
        NSMutableArray *specifiers = [NSMutableArray new];
        DOEnvironmentManager *envManager = [DOEnvironmentManager sharedManager];
        DOExploitManager *exploitManager = [DOExploitManager sharedManager];

        NSNumber *buttonHeight = @(44);
        
        SEL defGetter = @selector(readPreferenceValue:);
        SEL defSetter = @selector(setPreferenceValue:specifier:);
        
        NSSortDescriptor *prioritySortDescriptor = [NSSortDescriptor sortDescriptorWithKey:@"priority" ascending:NO];
        
        _availableKernelExploits = [[exploitManager availableExploitsForType:EXPLOIT_TYPE_KERNEL] sortedArrayUsingDescriptors:@[prioritySortDescriptor]];
        if (envManager.isArm64e) {
            _availablePACBypasses = [[exploitManager availableExploitsForType:EXPLOIT_TYPE_PAC] sortedArrayUsingDescriptors:@[prioritySortDescriptor]];
            _availablePPLBypasses = [[exploitManager availableExploitsForType:EXPLOIT_TYPE_PPL] sortedArrayUsingDescriptors:@[prioritySortDescriptor]];
        }
        
        PSSpecifier *headerSpecifier = [PSSpecifier emptyGroupSpecifier];
        [headerSpecifier setProperty:@"DOHeaderCell" forKey:@"headerCellClass"];
        [headerSpecifier setProperty:[NSString stringWithFormat:@"Settings"] forKey:@"title"];
        [specifiers addObject:headerSpecifier];
        
        if (envManager.isSupported) {
            if (!envManager.isJailbroken) {
                PSSpecifier *exploitGroupSpecifier = [PSSpecifier emptyGroupSpecifier];
                exploitGroupSpecifier.name = DOLocalizedString(@"Section_Exploits");
                [specifiers addObject:exploitGroupSpecifier];
                
                PSSpecifier *kernelExploitSpecifier = [PSSpecifier preferenceSpecifierNamed:DOLocalizedString(@"Kernel Exploit") target:self set:defSetter get:defGetter detail:nil cell:PSLinkListCell edit:nil];
                [kernelExploitSpecifier setProperty:@YES forKey:@"enabled"];
                [kernelExploitSpecifier setProperty:exploitManager.preferredKernelExploit.identifier forKey:@"default"];
                kernelExploitSpecifier.detailControllerClass = [DOPSExploitListItemsController class];
                [kernelExploitSpecifier setProperty:@"availableKernelExploitIdentifiers" forKey:@"valuesDataSource"];
                [kernelExploitSpecifier setProperty:@"availableKernelExploitNames" forKey:@"titlesDataSource"];
                [kernelExploitSpecifier setProperty:@"selectedKernelExploit" forKey:@"key"];
                [kernelExploitSpecifier setProperty:(_availableKernelExploits.firstObject.identifier ?: @"none") forKey:@"recommendedExploitIdentifier"];
                [specifiers addObject:kernelExploitSpecifier];
                
                if (envManager.isArm64e) {
                    PSSpecifier *pacBypassSpecifier = [PSSpecifier preferenceSpecifierNamed:DOLocalizedString(@"PAC Bypass") target:self set:defSetter get:defGetter detail:nil cell:PSLinkListCell edit:nil];
                    [pacBypassSpecifier setProperty:@YES forKey:@"enabled"];
                    DOExploit *preferredPACBypass = exploitManager.preferredPACBypass;
                    if (!preferredPACBypass) {
                        [pacBypassSpecifier setProperty:@"none" forKey:@"default"];
                    }
                    else {
                        [pacBypassSpecifier setProperty:preferredPACBypass.identifier forKey:@"default"];
                    }
                    pacBypassSpecifier.detailControllerClass = [DOPSExploitListItemsController class];
                    [pacBypassSpecifier setProperty:@"availablePACBypassIdentifiers" forKey:@"valuesDataSource"];
                    [pacBypassSpecifier setProperty:@"availablePACBypassNames" forKey:@"titlesDataSource"];
                    [pacBypassSpecifier setProperty:@"selectedPACBypass" forKey:@"key"];
                    [pacBypassSpecifier setProperty:([envManager isPACBypassRequired] ? _availablePACBypasses.firstObject.identifier : @"none") forKey:@"recommendedExploitIdentifier"];
                    [specifiers addObject:pacBypassSpecifier];
                    
                    PSSpecifier *pplBypassSpecifier = [PSSpecifier preferenceSpecifierNamed:DOLocalizedString(@"PPL Bypass") target:self set:defSetter get:defGetter detail:nil cell:PSLinkListCell edit:nil];
                    [pplBypassSpecifier setProperty:@YES forKey:@"enabled"];
                    [pplBypassSpecifier setProperty:exploitManager.preferredPPLBypass.identifier forKey:@"default"];
                    pplBypassSpecifier.detailControllerClass = [DOPSExploitListItemsController class];
                    [pplBypassSpecifier setProperty:@"availablePPLBypassIdentifiers" forKey:@"valuesDataSource"];
                    [pplBypassSpecifier setProperty:@"availablePPLBypassNames" forKey:@"titlesDataSource"];
                    [pplBypassSpecifier setProperty:@"selectedPPLBypass" forKey:@"key"];
                    [pplBypassSpecifier setProperty:(_availablePPLBypasses.firstObject.identifier ?: @"none") forKey:@"recommendedExploitIdentifier"];
                    [specifiers addObject:pplBypassSpecifier];
                }
            }
            
            PSSpecifier *settingsGroupSpecifier = [PSSpecifier emptyGroupSpecifier];
            settingsGroupSpecifier.name = DOLocalizedString(@"Section_Jailbreak_Settings");
            [specifiers addObject:settingsGroupSpecifier];
            
            PSSpecifier *tweakInjectionSpecifier = [PSSpecifier preferenceSpecifierNamed:DOLocalizedString(@"Settings_Tweak_Injection") target:self set:@selector(setTweakInjectionEnabled:specifier:) get:@selector(readTweakInjectionEnabled:) detail:nil cell:PSSwitchCell edit:nil];
            [tweakInjectionSpecifier setProperty:@YES forKey:@"enabled"];
            [tweakInjectionSpecifier setProperty:@"tweakInjectionEnabled" forKey:@"key"];
            [tweakInjectionSpecifier setProperty:@YES forKey:@"default"];
            [specifiers addObject:tweakInjectionSpecifier];
            
            if (!envManager.isJailbroken) {
                PSSpecifier *verboseLogSpecifier = [PSSpecifier preferenceSpecifierNamed:DOLocalizedString(@"Settings_Verbose_Logs") target:self set:defSetter get:defGetter detail:nil cell:PSSwitchCell edit:nil];
                [verboseLogSpecifier setProperty:@YES forKey:@"enabled"];
                [verboseLogSpecifier setProperty:@"verboseLogsEnabled" forKey:@"key"];
                [verboseLogSpecifier setProperty:@NO forKey:@"default"];
                [specifiers addObject:verboseLogSpecifier];
            }
            
            PSSpecifier *idownloadSpecifier = [PSSpecifier preferenceSpecifierNamed:DOLocalizedString(@"Settings_iDownload") target:self set:@selector(setIDownloadEnabled:specifier:) get:@selector(readIDownloadEnabled:) detail:nil cell:PSSwitchCell edit:nil];
            [idownloadSpecifier setProperty:@YES forKey:@"enabled"];
            [idownloadSpecifier setProperty:@"idownloadEnabled" forKey:@"key"];
            [idownloadSpecifier setProperty:@NO forKey:@"default"];
            [specifiers addObject:idownloadSpecifier];
            
            PSSpecifier *appJitSpecifier = [PSSpecifier preferenceSpecifierNamed:DOLocalizedString(@"Settings_Apps_JIT") target:self set:@selector(setAppJITEnabled:specifier:) get:@selector(readAppJITEnabled:) detail:nil cell:PSSwitchCell edit:nil];
            [appJitSpecifier setProperty:@YES forKey:@"enabled"];
            [appJitSpecifier setProperty:@"appJITEnabled" forKey:@"key"];
            [appJitSpecifier setProperty:@YES forKey:@"default"];
            [specifiers addObject:appJitSpecifier];
            
            
            /**************************** roothide specfic *********************************/
            NSString* namedesc = DOLocalizedString(@"Enable dyld patch");
            if(envManager.isArm64e && NSProcessInfo.processInfo.operatingSystemVersion.majorVersion==15) {
                namedesc = DOLocalizedString(@"Dyld Patch(Spinlock Fix)");
            }
            PSSpecifier *dyldPatchSpecifier = [PSSpecifier preferenceSpecifierNamed:namedesc target:self set:@selector(setDyldPatchEnabled:specifier:) get:@selector(readDyldPatchEnabled:) detail:nil cell:PSSwitchCell edit:nil];
            [dyldPatchSpecifier setProperty:@YES forKey:@"enabled"];
            [dyldPatchSpecifier setProperty:@"dyldPatchEnabled" forKey:@"key"];
            [dyldPatchSpecifier setProperty:@NO forKey:@"default"];
            [specifiers addObject:dyldPatchSpecifier];
            /**************************** roothide specfic *********************************/
            
            
            PSSpecifier *jetsamSpecifier = [PSSpecifier preferenceSpecifierNamed:DOLocalizedString(@"Settings_Jetsam_Multiplier") target:self set:@selector(setJetsamMultiplier:specifier:) get:@selector(readJetsamMultiplier:) detail:nil cell:PSLinkListCell edit:nil];
            [jetsamSpecifier setProperty:@YES forKey:@"enabled"];
            [jetsamSpecifier setProperty:@"jetsamMultiplier" forKey:@"key"];
            [jetsamSpecifier setProperty:@6 forKey:@"default"];
            jetsamSpecifier.detailControllerClass = [DOPSJetsamListItemsController class];
            [jetsamSpecifier setProperty:@"jetsamOptionNumbers" forKey:@"valuesDataSource"];
            [jetsamSpecifier setProperty:@"jetsamOptionTitles" forKey:@"titlesDataSource"];
            [specifiers addObject:jetsamSpecifier];
            
            if (!envManager.isJailbroken && !envManager.isInstalledThroughTrollStore) {
                PSSpecifier *removeJailbreakSwitchSpecifier = [PSSpecifier preferenceSpecifierNamed:DOLocalizedString(@"Button_Remove_Jailbreak") target:self set:@selector(setRemoveJailbreakEnabled:specifier:) get:defGetter detail:nil cell:PSSwitchCell edit:nil];
                [removeJailbreakSwitchSpecifier setProperty:@YES forKey:@"enabled"];
                [removeJailbreakSwitchSpecifier setProperty:@"removeJailbreakEnabled" forKey:@"key"];
                [specifiers addObject:removeJailbreakSwitchSpecifier];
            }
            
            if (envManager.isJailbroken || (envManager.isInstalledThroughTrollStore && envManager.isBootstrapped)) {
                PSSpecifier *actionsGroupSpecifier = [PSSpecifier emptyGroupSpecifier];
                actionsGroupSpecifier.name = DOLocalizedString(@"Section_Actions");
                [specifiers addObject:actionsGroupSpecifier];
                
                if (envManager.isJailbroken) {
                    PSSpecifier *refreshAppsSpecifier = [PSSpecifier preferenceSpecifierNamed:@"" target:self set:defSetter get:defGetter detail:nil cell:PSStaticTextCell edit:nil];
                    [refreshAppsSpecifier setProperty:@"Button_Refresh_Jailbreak_Apps" forKey:@"title"];
                    [refreshAppsSpecifier setProperty:[DOButtonCell class] forKey:@"cellClass"];
                    [refreshAppsSpecifier setProperty:buttonHeight forKey:@"height"];
                    [refreshAppsSpecifier setProperty:@"arrow.triangle.2.circlepath" forKey:@"image"];
                    [refreshAppsSpecifier setProperty:@"refreshJailbreakAppsPressed" forKey:@"action"];
                    [specifiers addObject:refreshAppsSpecifier];
                    
                    PSSpecifier *changeMobilePasswordSpecifier = [PSSpecifier preferenceSpecifierNamed:@"" target:self set:defSetter get:defGetter detail:nil cell:PSStaticTextCell edit:nil];
                    [changeMobilePasswordSpecifier setProperty:@"Button_Change_Mobile_Password" forKey:@"title"];
                    [changeMobilePasswordSpecifier setProperty:[DOButtonCell class] forKey:@"cellClass"];
                    [changeMobilePasswordSpecifier setProperty:buttonHeight forKey:@"height"];
                    [changeMobilePasswordSpecifier setProperty:@"key" forKey:@"image"];
                    [changeMobilePasswordSpecifier setProperty:@"changeMobilePasswordWithAuthenticationPressed" forKey:@"action"];
                    [specifiers addObject:changeMobilePasswordSpecifier];
                    
                    PSSpecifier *reinstallPackageManagersSpecifier = [PSSpecifier preferenceSpecifierNamed:@"" target:self set:defSetter get:defGetter detail:nil cell:PSStaticTextCell edit:nil];
                    [reinstallPackageManagersSpecifier setProperty:@"Button_Reinstall_Package_Managers" forKey:@"title"];
                    [reinstallPackageManagersSpecifier setProperty:[DOButtonCell class] forKey:@"cellClass"];
                    [reinstallPackageManagersSpecifier setProperty:buttonHeight forKey:@"height"];
                    if (@available(iOS 16.0, *))
                        [reinstallPackageManagersSpecifier setProperty:@"shippingbox.and.arrow.backward" forKey:@"image"];
                    else
                        [reinstallPackageManagersSpecifier setProperty:@"shippingbox" forKey:@"image"];
                    [reinstallPackageManagersSpecifier setProperty:@"reinstallPackageManagersPressed" forKey:@"action"];
                    [specifiers addObject:reinstallPackageManagersSpecifier];
                }
                if ((envManager.isJailbroken || envManager.isInstalledThroughTrollStore) && envManager.isBootstrapped) {
/*
                    PSSpecifier *hideUnhideJailbreakSpecifier = [PSSpecifier preferenceSpecifierNamed:@"" target:self set:defSetter get:defGetter detail:nil cell:PSStaticTextCell edit:nil];
                    [hideUnhideJailbreakSpecifier setProperty:[DOButtonCell class] forKey:@"cellClass"];
                    [hideUnhideJailbreakSpecifier setProperty:buttonHeight forKey:@"height"];
                    if (envManager.isJailbreakHidden) {
                        [hideUnhideJailbreakSpecifier setProperty:@"Button_Unhide_Jailbreak" forKey:@"title"];
                        [hideUnhideJailbreakSpecifier setProperty:@"eye" forKey:@"image"];
                    }
                    else {
                        [hideUnhideJailbreakSpecifier setProperty:@"Button_Hide_Jailbreak" forKey:@"title"];
                        [hideUnhideJailbreakSpecifier setProperty:@"eye.slash" forKey:@"image"];
                    }
                    [hideUnhideJailbreakSpecifier setProperty:@"hideUnhideJailbreakPressed" forKey:@"action"];
                    BOOL hideJailbreakButtonShown = (envManager.isJailbroken || (envManager.isInstalledThroughTrollStore && envManager.isBootstrapped && !envManager.isJailbreakHidden));
                    if (hideJailbreakButtonShown) {
                        [specifiers addObject:hideUnhideJailbreakSpecifier];
                    }
*/
                    
                    PSSpecifier *removeJailbreakSpecifier = [PSSpecifier preferenceSpecifierNamed:@"" target:self set:defSetter get:defGetter detail:nil cell:PSStaticTextCell edit:nil];
                    [removeJailbreakSpecifier setProperty:@"Button_Remove_Jailbreak" forKey:@"title"];
                    [removeJailbreakSpecifier setProperty:[DOButtonCell class] forKey:@"cellClass"];
                    [removeJailbreakSpecifier setProperty:buttonHeight forKey:@"height"];
                    [removeJailbreakSpecifier setProperty:@"trash" forKey:@"image"];
                    [removeJailbreakSpecifier setProperty:@"removeJailbreakPressed" forKey:@"action"];
/*
                    if (hideJailbreakButtonShown) {
                        if (envManager.isJailbroken) {
                            [removeJailbreakSpecifier setProperty:DOLocalizedString(@"Hint_Hide_Jailbreak_Jailbroken") forKey:@"footerText"];
                        }
                        else {
                            [removeJailbreakSpecifier setProperty:DOLocalizedString(@"Hint_Hide_Jailbreak") forKey:@"footerText"];
                        }
                    }
*/
                    [specifiers addObject:removeJailbreakSpecifier];
                }
            }
        }
        
        // ── Revohide diagnostic log ──────────────────────────────────────────
        PSSpecifier *revohideGroupSpecifier = [PSSpecifier emptyGroupSpecifier];
        revohideGroupSpecifier.name = @"Revohide";
        [specifiers addObject:revohideGroupSpecifier];

        PSSpecifier *loggingToggle = [PSSpecifier preferenceSpecifierNamed:@"Hook Logging"
            target:self
            set:@selector(setRhLoggingEnabled:specifier:)
            get:@selector(getRhLoggingEnabled:)
            detail:nil
            cell:PSSwitchCell
            edit:nil];
        [loggingToggle setProperty:@"waveform" forKey:@"image"];
        [specifiers addObject:loggingToggle];

        PSSpecifier *viewLogSpecifier = [PSSpecifier preferenceSpecifierNamed:@"" target:self set:defSetter get:defGetter detail:nil cell:PSStaticTextCell edit:nil];
        [viewLogSpecifier setProperty:@"View Hook Log" forKey:@"title"];
        [viewLogSpecifier setProperty:[DOButtonCell class] forKey:@"cellClass"];
        [viewLogSpecifier setProperty:buttonHeight forKey:@"height"];
        [viewLogSpecifier setProperty:@"doc.text.magnifyingglass" forKey:@"image"];
        [viewLogSpecifier setProperty:@"viewRevohideLogPressed" forKey:@"action"];
        [specifiers addObject:viewLogSpecifier];
        // ────────────────────────────────────────────────────────────────────

        PSSpecifier *themingGroupSpecifier = [PSSpecifier emptyGroupSpecifier];
        themingGroupSpecifier.name = DOLocalizedString(@"Section_Customization");
        [specifiers addObject:themingGroupSpecifier];
        
        PSSpecifier *themeSpecifier = [PSSpecifier preferenceSpecifierNamed:DOLocalizedString(@"Theme") target:self set:defSetter get:defGetter detail:nil cell:PSLinkListCell edit:nil];
        themeSpecifier.detailControllerClass = [DOPSListItemsController class];
        [themeSpecifier setProperty:@YES forKey:@"enabled"];
        [themeSpecifier setProperty:@"theme" forKey:@"key"];
        [themeSpecifier setProperty:[[self themeIdentifiers] firstObject] forKey:@"default"];
        [themeSpecifier setProperty:@"themeIdentifiers" forKey:@"valuesDataSource"];
        [themeSpecifier setProperty:@"themeNames" forKey:@"titlesDataSource"];
        [specifiers addObject:themeSpecifier];

        PSSpecifier *bootlogoGropSpecifier = [PSSpecifier emptyGroupSpecifier];
        bootlogoGropSpecifier.name = DOLocalizedString(@"Section_Boot_Logo");
        [specifiers addObject:bootlogoGropSpecifier];

        PSSpecifier *bootlogoEnabledSpecifier = [PSSpecifier preferenceSpecifierNamed:DOLocalizedString(@"Enabled") target:self set:@selector(setBootlogoEnabled:specifier:) get:defGetter detail:nil cell:PSSwitchCell edit:nil];
        [bootlogoEnabledSpecifier setProperty:@YES forKey:@"enabled"];
        [bootlogoEnabledSpecifier setProperty:@"bootlogoEnabled" forKey:@"key"];
        [bootlogoEnabledSpecifier setProperty:@YES forKey:@"default"];
        bootlogoEnabledSpecifier.identifier = @"bootlogoEnabled";
        [specifiers addObject:bootlogoEnabledSpecifier];

        _customBootlogoEnabledSpecifier = [PSSpecifier preferenceSpecifierNamed:DOLocalizedString(@"Custom_Boot_Logo") target:self set:@selector(setCustomBootlogoEnabled:specifier:) get:defGetter detail:nil cell:PSSwitchCell edit:nil];
        [_customBootlogoEnabledSpecifier setProperty:@YES forKey:@"enabled"];
        [_customBootlogoEnabledSpecifier setProperty:@"customBootlogoEnabled" forKey:@"key"];
        [_customBootlogoEnabledSpecifier setProperty:@NO forKey:@"default"];
        _customBootlogoEnabledSpecifier.identifier = @"customBootlogoEnabled";

        _customBootlogoSpecifier = [PSSpecifier preferenceSpecifierNamed:DOLocalizedString(@"Select_Image") target:self set:defSetter get:defGetter detail:nil cell:PSButtonCell edit:nil];
        _customBootlogoSpecifier.buttonAction = @selector(selectCustomBootlogoPressed);
        [_customBootlogoSpecifier setProperty:@YES forKey:@"enabled"];
        [_customBootlogoSpecifier setProperty:@"customBootlogo" forKey:@"key"];
        _customBootlogoSpecifier.identifier = @"customBootlogo";

        if ([[DOPreferenceManager sharedManager] boolPreferenceValueForKey:@"bootlogoEnabled" fallback:YES]) {
            [specifiers addObject:_customBootlogoEnabledSpecifier];

            if ([[DOPreferenceManager sharedManager] boolPreferenceValueForKey:@"customBootlogoEnabled" fallback:NO]) {
                [specifiers addObject:_customBootlogoSpecifier];
            }
        }

        _specifiers = specifiers;
    }
    return _specifiers;
}

#pragma mark - Getters & Setters

- (void)setPreferenceValue:(id)value specifier:(PSSpecifier *)specifier
{
    NSString *key = [specifier propertyForKey:@"key"];
    [[DOPreferenceManager sharedManager] setPreferenceValue:value forKey:key];
}

- (id)readPreferenceValue:(PSSpecifier*)specifier
{
    NSString *key = [specifier propertyForKey:@"key"];
    id value = [[DOPreferenceManager sharedManager] preferenceValueForKey:key];
    if (!value) {
        return [specifier propertyForKey:@"default"];
    }
    return value;
}

- (id)readIDownloadEnabled:(PSSpecifier *)specifier
{
    DOEnvironmentManager *envManager = [DOEnvironmentManager sharedManager];
    if (envManager.isJailbroken) {
        return @([DOEnvironmentManager sharedManager].isIDownloadEnabled);
    }
    return [self readPreferenceValue:specifier];
}

- (void)setIDownloadEnabled:(id)value specifier:(PSSpecifier *)specifier
{
    [self setPreferenceValue:value specifier:specifier];
    DOEnvironmentManager *envManager = [DOEnvironmentManager sharedManager];
    if (envManager.isJailbroken) {
        [[DOEnvironmentManager sharedManager] setIDownloadLoaded:((NSNumber *)value).boolValue needsUnsandbox:YES];
    }
}

- (id)readTweakInjectionEnabled:(PSSpecifier *)specifier
{
    DOEnvironmentManager *envManager = [DOEnvironmentManager sharedManager];
    if (envManager.isJailbroken) {
        return @([DOEnvironmentManager sharedManager].isTweakInjectionEnabled);
    }
    return [self readPreferenceValue:specifier];
}

- (void)setTweakInjectionEnabled:(id)value specifier:(PSSpecifier *)specifier
{
    [self setPreferenceValue:value specifier:specifier];
    DOEnvironmentManager *envManager = [DOEnvironmentManager sharedManager];
    if (envManager.isJailbroken) {
        [[DOEnvironmentManager sharedManager] setTweakInjectionEnabled:((NSNumber *)value).boolValue];
        UIAlertController *userspaceRebootAlertController = [UIAlertController alertControllerWithTitle:DOLocalizedString(@"Alert_Tweak_Injection_Toggled_Title") message:DOLocalizedString(@"Alert_Tweak_Injection_Toggled_Body") preferredStyle:UIAlertControllerStyleAlert];
        UIAlertAction *rebootNowAction = [UIAlertAction actionWithTitle:DOLocalizedString(@"Alert_Tweak_Injection_Toggled_Reboot_Now") style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
            [[DOEnvironmentManager sharedManager] rebootUserspace];
        }];
        UIAlertAction *rebootLaterAction = [UIAlertAction actionWithTitle:DOLocalizedString(@"Alert_Tweak_Injection_Toggled_Reboot_Later") style:UIAlertActionStyleCancel handler:nil];
        
        [userspaceRebootAlertController addAction:rebootNowAction];
        [userspaceRebootAlertController addAction:rebootLaterAction];
        [self presentViewController:userspaceRebootAlertController animated:YES completion:nil];
    }
}

- (id)readAppJITEnabled:(PSSpecifier *)specifier
{
    DOEnvironmentManager *envManager = [DOEnvironmentManager sharedManager];
    if (envManager.isJailbroken) {
        bool v = jbclient_jbsettings_get_bool("markAppsAsDebugged");
        return @(v);
    }
    return [self readPreferenceValue:specifier];
}

- (void)setAppJITEnabled:(id)value specifier:(PSSpecifier *)specifier
{
    [self setPreferenceValue:value specifier:specifier];
    DOEnvironmentManager *envManager = [DOEnvironmentManager sharedManager];
    if (envManager.isJailbroken) {
        jbclient_platform_jbsettings_set_bool("markAppsAsDebugged", ((NSNumber *)value).boolValue);
    }
}

- (id)readJetsamMultiplier:(PSSpecifier *)specifier
{
    DOEnvironmentManager *envManager = [DOEnvironmentManager sharedManager];
    if (envManager.isJailbroken) {
        double v = jbclient_jbsettings_get_double("jetsamMultiplier");
        return @((v < 1 || isnan(v)) ? 6 : ceil(v * 2));
    }
    return [self readPreferenceValue:specifier];
}

- (void)setJetsamMultiplier:(id)value specifier:(PSSpecifier *)specifier
{
    [self setPreferenceValue:value specifier:specifier];
    DOEnvironmentManager *envManager = [DOEnvironmentManager sharedManager];
    if (envManager.isJailbroken) {
        jbclient_platform_jbsettings_set_double("jetsamMultiplier", ((NSNumber *)value).doubleValue / 2);
    }
}

- (void)setRemoveJailbreakEnabled:(id)value specifier:(PSSpecifier *)specifier
{
    [self setPreferenceValue:value specifier:specifier];
    if (((NSNumber *)value).boolValue) {
        UIAlertController *confirmationAlertController = [UIAlertController alertControllerWithTitle:DOLocalizedString(@"Alert_Remove_Jailbreak_Title") message:DOLocalizedString(@"Alert_Remove_Jailbreak_Enabled_Body") preferredStyle:UIAlertControllerStyleAlert];
        UIAlertAction *uninstallAction = [UIAlertAction actionWithTitle:DOLocalizedString(@"Button_Continue") style:UIAlertActionStyleDestructive handler:nil];
        UIAlertAction *cancelAction = [UIAlertAction actionWithTitle:DOLocalizedString(@"Button_Cancel") style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
            [self setPreferenceValue:@NO specifier:specifier];
            [self reloadSpecifiers];
        }];
        [confirmationAlertController addAction:uninstallAction];
        [confirmationAlertController addAction:cancelAction];
        [self presentViewController:confirmationAlertController animated:YES completion:nil];
    }
}

- (void)setBootlogoEnabled:(id)value specifier:(PSSpecifier *)specifier
{
    bool prevValueBool = ((NSNumber *)[self readPreferenceValue:specifier]).boolValue;
    [self setPreferenceValue:value specifier:specifier];
    bool valueBool = ((NSNumber *)value).boolValue;

    if (prevValueBool != valueBool) {
        NSMutableArray *affectedSpecifiers = [NSMutableArray new];
        [affectedSpecifiers addObject:_customBootlogoEnabledSpecifier];

        if (valueBool == ![self containsSpecifier:_customBootlogoSpecifier]) {
            [affectedSpecifiers addObject:_customBootlogoSpecifier];
        }

        if (valueBool) {
            [self insertContiguousSpecifiers:affectedSpecifiers afterSpecifier:specifier animated:YES];
        }
        else {
            [self removeContiguousSpecifiers:affectedSpecifiers animated:YES];
        }
    }

    if ([DOEnvironmentManager sharedManager].isJailbroken) {
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            [[DOEnvironmentManager sharedManager] updateBootLogo];
        });
    }
}

- (void)setCustomBootlogoEnabled:(id)value specifier:(PSSpecifier *)specifier
{
    bool prevValueBool = ((NSNumber *)[self readPreferenceValue:specifier]).boolValue;
    [self setPreferenceValue:value specifier:specifier];
    bool valueBool = ((NSNumber *)value).boolValue;

    if (prevValueBool != valueBool) {
        if (valueBool) {
            [self insertSpecifier:_customBootlogoSpecifier afterSpecifier:specifier animated:YES];
        }
        else {
            [self removeSpecifier:_customBootlogoSpecifier animated:YES];
        }
    }

    if ([DOEnvironmentManager sharedManager].isJailbroken) {
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            [[DOEnvironmentManager sharedManager] updateBootLogo];
        });
    }
}

- (void)selectCustomBootlogoPressed
{
    PHAuthorizationStatus status = [PHPhotoLibrary authorizationStatus];
    if (status == PHAuthorizationStatusDenied || status == PHAuthorizationStatusRestricted) {
        return;
    } else if (status == PHAuthorizationStatusNotDetermined) {
        [PHPhotoLibrary requestAuthorization:^(PHAuthorizationStatus status) {
            if (status == PHAuthorizationStatusAuthorized) {
                dispatch_async(dispatch_get_main_queue(), ^{
                    [self selectCustomBootlogoPressed];
                });
            }
        }];
        return;
    }

    UIImagePickerController *picker = [[UIImagePickerController alloc] init];
    picker.delegate = self;
    picker.sourceType = UIImagePickerControllerSourceTypePhotoLibrary;
    [self presentViewController:picker animated:YES completion:nil];
}

#pragma mark - Boot Logo Picker

- (void)imagePickerController:(UIImagePickerController *)picker didFinishPickingMediaWithInfo:(NSDictionary<NSString *,id> *)info {
    UIImage *chosenImage = info[UIImagePickerControllerEditedImage];
    if (!chosenImage) {
        chosenImage = info[UIImagePickerControllerOriginalImage];
    }

    // Force correct the orientation
    // For some reason without rerendering the image, the stored file will have a wrong orientation for photos taken with the camera‚
    UIGraphicsBeginImageContextWithOptions(chosenImage.size, NO, 1.0);
    [chosenImage drawInRect:CGRectMake(0,0, chosenImage.size.width, chosenImage.size.height)];
    chosenImage = UIGraphicsGetImageFromCurrentImageContext();
    UIGraphicsEndImageContext();

    [UIImagePNGRepresentation(chosenImage) writeToFile:[DOUIManager sharedInstance].bootlogoPath atomically:YES];

    if ([DOEnvironmentManager sharedManager].isJailbroken) {
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            [[DOEnvironmentManager sharedManager] updateBootLogo];
        });
    }

    [picker dismissViewControllerAnimated:YES completion:nil];
}

- (void)imagePickerControllerDidCancel:(UIImagePickerController *)picker {
    [picker dismissViewControllerAnimated:YES completion:nil];
}

#pragma mark - Button Actions

- (void)refreshJailbreakAppsPressed
{
    [[DOEnvironmentManager sharedManager] refreshJailbreakApps];
}

- (void)reinstallPackageManagersPressed
{
    [self.navigationController pushViewController:[[DOPkgManagerPickerViewController alloc] init] animated:YES];
}

- (void)changeMobilePasswordWithAuthenticationPressed
{
	LAContext *context = [[LAContext alloc] init];
	NSError *authError = nil;
	NSString *reason = DOLocalizedString(@"Password_Auth_Required");
	
	if ([context canEvaluatePolicy:LAPolicyDeviceOwnerAuthentication error:&authError]) {
		[context evaluatePolicy:LAPolicyDeviceOwnerAuthentication
			localizedReason:reason
			reply:^(BOOL success, NSError * _Nullable error) {
			dispatch_async(dispatch_get_main_queue(), ^{
				if (success) {
					[self changeMobilePassword];
				}
			});
		}];
	}
	else {
		[self changeMobilePassword];
	}
}

- (void)changeMobilePassword
{
    UIAlertController *changeMobilePasswordAlert = [UIAlertController alertControllerWithTitle:DOLocalizedString(@"Button_Change_Mobile_Password") message:DOLocalizedString(@"Alert_Change_Mobile_Password_Body") preferredStyle:UIAlertControllerStyleAlert];
    
    [changeMobilePasswordAlert addTextFieldWithConfigurationHandler:^(UITextField * _Nonnull textField) {
        textField.placeholder = DOLocalizedString(@"Password_Placeholder");
        textField.secureTextEntry = YES;
    }];
    
    [changeMobilePasswordAlert addTextFieldWithConfigurationHandler:^(UITextField * _Nonnull textField) {
        textField.placeholder = DOLocalizedString(@"Repeat_Password_Placeholder");
        textField.secureTextEntry = YES;
    }];
    
    UIAlertAction *changeButton = [UIAlertAction actionWithTitle:DOLocalizedString(@"Button_Change") style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action){
        NSString *password = changeMobilePasswordAlert.textFields[0].text;
        NSString *repeatPassword = changeMobilePasswordAlert.textFields[1].text;
        if (![password isEqualToString:repeatPassword]) {
            dispatch_async(dispatch_get_main_queue(), ^{
                [self changeMobilePassword];
            });
        }
        else {
            [[DOEnvironmentManager sharedManager] changeMobilePassword:password];
        }
    }];
    UIAlertAction *cancelAction = [UIAlertAction actionWithTitle:DOLocalizedString(@"Button_Cancel") style:UIAlertActionStyleCancel handler:nil];
    [changeMobilePasswordAlert addAction:changeButton];
    [changeMobilePasswordAlert addAction:cancelAction];
    [self presentViewController:changeMobilePasswordAlert animated:YES completion:nil];
}

/*
- (void)hideUnhideJailbreakPressed
{
    DOEnvironmentManager *envManager = [DOEnvironmentManager sharedManager];
    [envManager setJailbreakHidden:!envManager.isJailbreakHidden];
    [self reloadSpecifiers];
}
*/

- (void)removeJailbreakPressed
{
    UIAlertController *confirmationAlertController = [UIAlertController alertControllerWithTitle:DOLocalizedString(@"Alert_Remove_Jailbreak_Title") message:DOLocalizedString(@"Alert_Remove_Jailbreak_Pressed_Body") preferredStyle:UIAlertControllerStyleAlert];
    UIAlertAction *uninstallAction = [UIAlertAction actionWithTitle:DOLocalizedString(@"Button_Continue") style:UIAlertActionStyleDestructive handler:^(UIAlertAction * _Nonnull action) {
        [[DOEnvironmentManager sharedManager] deleteBootstrap];
        if ([DOEnvironmentManager sharedManager].isJailbroken) {
            [[DOEnvironmentManager sharedManager] reboot];
        }
        else {
            if (gSystemInfo.jailbreakInfo.rootPath) {
                free(gSystemInfo.jailbreakInfo.rootPath);
                gSystemInfo.jailbreakInfo.rootPath = NULL;
                [[DOEnvironmentManager sharedManager] locateJailbreakRoot];
            }
            [self reloadSpecifiers];
        }
    }];
    UIAlertAction *cancelAction = [UIAlertAction actionWithTitle:DOLocalizedString(@"Button_Cancel") style:UIAlertActionStyleDefault handler:nil];
    [confirmationAlertController addAction:uninstallAction];
    [confirmationAlertController addAction:cancelAction];
    [self presentViewController:confirmationAlertController animated:YES completion:nil];
}

- (void)resetSettingsPressed
{
    [[DOUIManager sharedInstance] resetSettings];
    [self.navigationController popToRootViewControllerAnimated:YES];
    [self reloadSpecifiers];
}

- (id)getRhLoggingEnabled:(PSSpecifier *)specifier {
    return @([DORevohideLogViewController isLoggingEnabled]);
}

- (void)setRhLoggingEnabled:(id)value specifier:(PSSpecifier *)specifier {
    [DORevohideLogViewController setLoggingEnabled:[value boolValue]];
}

- (void)viewRevohideLogPressed
{
    [self.navigationController pushViewController:[[DORevohideLogViewController alloc] init] animated:YES];
}


- (id)readDyldPatchEnabled:(PSSpecifier *)specifier
{
    DOEnvironmentManager *envManager = [DOEnvironmentManager sharedManager];
    if (envManager.isJailbroken) {
        return @(jbclient_dyld_patch_enabled());
    }
    return [self readPreferenceValue:specifier];
}

- (void)setDyldPatchEnabled:(id)value specifier:(PSSpecifier *)specifier
{
    DOEnvironmentManager *envManager = [DOEnvironmentManager sharedManager];
    
    bool enable = ((NSNumber *)value).boolValue;
    
    void (^confirmAction)(void) = ^{
        
        if (!envManager.isJailbroken) {
            
            [self setPreferenceValue:value specifier:specifier];
            return;
        }
    
        UIAlertController *userspaceRebootAlertController = [UIAlertController alertControllerWithTitle:DOLocalizedString(@"Alert_Tweak_Injection_Toggled_Title") message:DOLocalizedString(@"Alert_Tweak_Injection_Toggled_Body") preferredStyle:UIAlertControllerStyleAlert];
        UIAlertAction *rebootNowAction = [UIAlertAction actionWithTitle:DOLocalizedString(@"Menu_Reboot_Userspace_Title") style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
            if(jbclient_set_dyld_patch(enable) == 0) {
                [self setPreferenceValue:value specifier:specifier];
                [[DOEnvironmentManager sharedManager] rebootUserspace];
            } else {
                [self reloadSpecifiers];
            }
        }];
        UIAlertAction *cancelAction = [UIAlertAction actionWithTitle:DOLocalizedString(@"Button_Cancel") style:UIAlertActionStyleCancel handler:^(UIAlertAction * _Nonnull action) {
            [self reloadSpecifiers];
        }];
        
        [userspaceRebootAlertController addAction:cancelAction];
        [userspaceRebootAlertController addAction:rebootNowAction];
        [self presentViewController:userspaceRebootAlertController animated:YES completion:nil];
    };
    
    
    if(enable && envManager.isArm64e && NSProcessInfo.processInfo.operatingSystemVersion.majorVersion==15) {
        UIAlertController* alert = [UIAlertController alertControllerWithTitle:DOLocalizedString(@"Warning") message:DOLocalizedString(@"When spinlock fix is ​​enabled, app extensions of blacklisted apps will be disabled and may also cause spinlock panics when the blacklisted app is in foreground/background.\n\nYou can first try disabling tweak injection for the app in Choicy (spinlock fix still works), and only blacklist the app if that doesn't work.") preferredStyle:UIAlertControllerStyleAlert];
        UIAlertAction *continueAction = [UIAlertAction actionWithTitle:DOLocalizedString(@"Button_Continue") style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
            confirmAction();
        }];
        UIAlertAction *cancelAction = [UIAlertAction actionWithTitle:DOLocalizedString(@"Button_Cancel") style:UIAlertActionStyleCancel handler:^(UIAlertAction * _Nonnull action) {
            [self reloadSpecifiers];
        }];
        
        [alert addAction:cancelAction];
        [alert addAction:continueAction];
        [self presentViewController:alert animated:YES completion:nil];
    } else {
        confirmAction();
    }
}

@end
