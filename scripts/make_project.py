#!/usr/bin/env python3
"""Generate the small Xcode project without XcodeGen or package dependencies."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
project = ROOT / 'app/AppAttestLab.xcodeproj'
project.mkdir(exist_ok=True)
pbx = '''// !$*UTF8*$!
{
 archiveVersion = 1;
 classes = {};
 objectVersion = 56;
 objects = {
  A00000000000000000000001 = {isa = PBXProject; buildConfigurationList = A00000000000000000000002; compatibilityVersion = "Xcode 14.0"; developmentRegion = en; hasScannedForEncodings = 0; knownRegions = (en, Base); mainGroup = A00000000000000000000003; productRefGroup = A00000000000000000000004; projectDirPath = ""; projectRoot = ""; targets = (A00000000000000000000005, A00000000000000000000020); attributes = {TargetAttributes = {A00000000000000000000020 = {TestTargetID = A00000000000000000000005;};};}; };
  A00000000000000000000002 = {isa = XCConfigurationList; buildConfigurations = (A00000000000000000000010, A00000000000000000000011); defaultConfigurationIsVisible = 0; defaultConfigurationName = Release; };
  A00000000000000000000003 = {isa = PBXGroup; children = (A00000000000000000000006, A00000000000000000000022, A00000000000000000000004); sourceTree = "<group>"; };
  A00000000000000000000004 = {isa = PBXGroup; children = (A00000000000000000000007, A00000000000000000000021); name = Products; sourceTree = "<group>"; };
  A00000000000000000000005 = {isa = PBXNativeTarget; buildConfigurationList = A00000000000000000000008; buildPhases = (A00000000000000000000009, A0000000000000000000000A); buildRules = (); dependencies = (); name = AppAttestLab; productName = AppAttestLab; productReference = A00000000000000000000007; productType = "com.apple.product-type.application"; };
  A00000000000000000000006 = {isa = PBXFileReference; lastKnownFileType = sourcecode.swift; path = AppAttestLab.swift; sourceTree = "<group>"; };
  A00000000000000000000007 = {isa = PBXFileReference; explicitFileType = wrapper.application; includeInIndex = 0; path = AppAttestLab.app; sourceTree = BUILT_PRODUCTS_DIR; };
  A00000000000000000000008 = {isa = XCConfigurationList; buildConfigurations = (A00000000000000000000012, A00000000000000000000013); defaultConfigurationIsVisible = 0; defaultConfigurationName = Release; };
  A00000000000000000000009 = {isa = PBXSourcesBuildPhase; buildActionMask = 2147483647; files = (A0000000000000000000000B); runOnlyForDeploymentPostprocessing = 0; };
  A0000000000000000000000A = {isa = PBXFrameworksBuildPhase; buildActionMask = 2147483647; files = (); runOnlyForDeploymentPostprocessing = 0; };
  A0000000000000000000000B = {isa = PBXBuildFile; fileRef = A00000000000000000000006; };
  A00000000000000000000010 = {isa = XCBuildConfiguration; buildSettings = {SDKROOT = iphoneos; IPHONEOS_DEPLOYMENT_TARGET = 16.0;}; name = Debug; };
  A00000000000000000000011 = {isa = XCBuildConfiguration; buildSettings = {SDKROOT = iphoneos; IPHONEOS_DEPLOYMENT_TARGET = 16.0;}; name = Release; };
  A00000000000000000000012 = {isa = XCBuildConfiguration; buildSettings = {SETTINGS SWIFT_OPTIMIZATION_LEVEL = "-Onone";}; name = Debug; };
  A00000000000000000000013 = {isa = XCBuildConfiguration; buildSettings = {SETTINGS SWIFT_OPTIMIZATION_LEVEL = "-O";}; name = Release; };
  A00000000000000000000020 = {isa = PBXNativeTarget; buildConfigurationList = A00000000000000000000023; buildPhases = (A00000000000000000000026, A00000000000000000000027); buildRules = (); dependencies = (A00000000000000000000029); name = LabUITests; productName = LabUITests; productReference = A00000000000000000000021; productType = "com.apple.product-type.bundle.ui-testing"; };
  A00000000000000000000021 = {isa = PBXFileReference; explicitFileType = wrapper.cfbundle; includeInIndex = 0; path = LabUITests.xctest; sourceTree = BUILT_PRODUCTS_DIR; };
  A00000000000000000000022 = {isa = PBXFileReference; lastKnownFileType = sourcecode.swift; path = UITests/LabUITests.swift; sourceTree = "<group>"; };
  A00000000000000000000023 = {isa = XCConfigurationList; buildConfigurations = (A00000000000000000000024, A00000000000000000000025); defaultConfigurationIsVisible = 0; defaultConfigurationName = Release; };
  A00000000000000000000024 = {isa = XCBuildConfiguration; buildSettings = {TESTSETTINGS}; name = Debug; };
  A00000000000000000000025 = {isa = XCBuildConfiguration; buildSettings = {TESTSETTINGS}; name = Release; };
  A00000000000000000000026 = {isa = PBXSourcesBuildPhase; buildActionMask = 2147483647; files = (A00000000000000000000028); runOnlyForDeploymentPostprocessing = 0; };
  A00000000000000000000027 = {isa = PBXFrameworksBuildPhase; buildActionMask = 2147483647; files = (); runOnlyForDeploymentPostprocessing = 0; };
  A00000000000000000000028 = {isa = PBXBuildFile; fileRef = A00000000000000000000022; };
  A00000000000000000000029 = {isa = PBXTargetDependency; target = A00000000000000000000005; targetProxy = A0000000000000000000002A; };
  A0000000000000000000002A = {isa = PBXContainerItemProxy; containerPortal = A00000000000000000000001; proxyType = 1; remoteGlobalIDString = A00000000000000000000005; remoteInfo = AppAttestLab; };
 };
 rootObject = A00000000000000000000001;
}
'''
settings = '''CODE_SIGN_ENTITLEMENTS = AppAttestLab.entitlements;
ALWAYS_SEARCH_USER_PATHS = NO;
CODE_SIGN_STYLE = Manual; CURRENT_PROJECT_VERSION = 1;
APP_ATTEST_ENVIRONMENT = development; LAB_DEFAULT_ENDPOINT = "https://mini.local:8443"; GENERATE_INFOPLIST_FILE = NO;
INFOPLIST_FILE = Info.plist; PRODUCT_BUNDLE_IDENTIFIER = org.example.AppAttestLab;
PRODUCT_NAME = "$(TARGET_NAME)"; SWIFT_VERSION = 5.0; TARGETED_DEVICE_FAMILY = "1,2";
SUPPORTED_PLATFORMS = "iphoneos iphonesimulator"; SUPPORTS_MACCATALYST = NO;
'''
test_settings = '''ALWAYS_SEARCH_USER_PATHS = NO; CODE_SIGN_STYLE = Automatic;
GENERATE_INFOPLIST_FILE = YES; PRODUCT_BUNDLE_IDENTIFIER = org.example.AppAttestLabUITests;
PRODUCT_NAME = "$(TARGET_NAME)"; SWIFT_VERSION = 5.0; TARGETED_DEVICE_FAMILY = "1,2";
TEST_TARGET_NAME = AppAttestLab; SUPPORTED_PLATFORMS = "iphoneos iphonesimulator";
'''
(project / 'project.pbxproj').write_text(pbx.replace('TESTSETTINGS', test_settings).replace('SETTINGS', settings))
schemes = project / 'xcshareddata/xcschemes'
schemes.mkdir(parents=True, exist_ok=True)
(schemes / 'AppAttestLab.xcscheme').write_text('''<?xml version="1.0" encoding="UTF-8"?>
<Scheme LastUpgradeVersion="1600" version="1.3">
<BuildAction parallelizeBuildables="YES" buildImplicitDependencies="YES"><BuildActionEntries>
<BuildActionEntry buildForTesting="YES" buildForRunning="YES" buildForProfiling="YES" buildForArchiving="YES" buildForAnalyzing="YES">
<BuildableReference BuildableIdentifier="primary" BlueprintIdentifier="A00000000000000000000005" BuildableName="AppAttestLab.app" BlueprintName="AppAttestLab" ReferencedContainer="container:AppAttestLab.xcodeproj"/>
</BuildActionEntry></BuildActionEntries></BuildAction>
<TestAction buildConfiguration="Debug" selectedDebuggerIdentifier="Xcode.DebuggerFoundation.Debugger.LLDB" selectedLauncherIdentifier="Xcode.IDEFoundation.Launcher.LLDB" shouldUseLaunchSchemeArgsEnv="YES">
<Testables><TestableReference skipped="NO"><BuildableReference BuildableIdentifier="primary" BlueprintIdentifier="A00000000000000000000020" BuildableName="LabUITests.xctest" BlueprintName="LabUITests" ReferencedContainer="container:AppAttestLab.xcodeproj"/></TestableReference></Testables>
</TestAction>
<LaunchAction buildConfiguration="Debug" selectedDebuggerIdentifier="Xcode.DebuggerFoundation.Debugger.LLDB" selectedLauncherIdentifier="Xcode.IDEFoundation.Launcher.LLDB" launchStyle="0" useCustomWorkingDirectory="NO" ignoresPersistentStateOnLaunch="NO" debugDocumentVersioning="YES" debugServiceExtension="internal" allowLocationSimulation="YES">
<BuildableProductRunnable runnableDebuggingMode="0"><BuildableReference BuildableIdentifier="primary" BlueprintIdentifier="A00000000000000000000005" BuildableName="AppAttestLab.app" BlueprintName="AppAttestLab" ReferencedContainer="container:AppAttestLab.xcodeproj"/></BuildableProductRunnable>
</LaunchAction>
<ArchiveAction buildConfiguration="Release" revealArchiveInOrganizer="YES"/>
</Scheme>
''')
print(project)
