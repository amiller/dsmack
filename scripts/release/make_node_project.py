#!/usr/bin/env python3
"""Generate the iOS peer Xcode project using only Python's standard library."""
import json
from pathlib import Path
import plistlib

ROOT = Path(__file__).resolve().parents[2]
DEST = ROOT / 'node/ios'


def main():
    sources = ['../shared/Protocol.swift', '../shared/PersonalAccount.swift', '../shared/BadgeClaim.swift', '../shared/Upgrade.swift', '../shared/Chain.swift', '../shared/NativeAttestation.swift', '../shared/Node.swift', 'NetworkConfig.swift', 'CodeEvidence.swift', 'NodeApp.swift']
    objects = []
    def oid(n):
        return f'{n:024X}'
    def add(n, body):
        objects.append(f'{oid(n)} = {{{body}}};')
    def refs(ns):
        return '(' + ','.join(oid(n) for n in ns) + ')'
    source_refs = list(range(100, 100 + len(sources)))
    build_refs = list(range(200, 200 + len(sources)))
    for n, b, source in zip(source_refs, build_refs, sources):
        add(n, f'isa = PBXFileReference; lastKnownFileType = sourcecode.swift; path = {json.dumps(source)}; sourceTree = "<group>";')
        add(b, f'isa = PBXBuildFile; fileRef = {oid(n)};')
    add(1, f'isa = PBXProject; buildConfigurationList = {oid(2)}; compatibilityVersion = "Xcode 14.0"; developmentRegion = en; knownRegions = (en,Base); mainGroup = {oid(3)}; productRefGroup = {oid(4)}; projectDirPath = ""; projectRoot = ""; targets = ({oid(5)},{oid(42)});')
    add(2, f'isa = XCConfigurationList; buildConfigurations = {refs([10,11])}; defaultConfigurationIsVisible = 0; defaultConfigurationName = Release;')
    add(3, f'isa = PBXGroup; children = {refs(source_refs + [30,40,4])}; sourceTree = "<group>";')
    add(4, f'isa = PBXGroup; children = ({oid(7)},{oid(47)}); name = Products; sourceTree = "<group>";')
    add(5, f'isa = PBXNativeTarget; buildConfigurationList = {oid(8)}; buildPhases = {refs([9,20,21])}; buildRules = (); dependencies = (); name = AttestNode; productName = AttestNode; productReference = {oid(7)}; productType = "com.apple.product-type.application";')
    add(7, 'isa = PBXFileReference; explicitFileType = wrapper.application; includeInIndex = 0; path = AttestNode.app; sourceTree = BUILT_PRODUCTS_DIR;')
    add(8, f'isa = XCConfigurationList; buildConfigurations = {refs([12,13])}; defaultConfigurationIsVisible = 0; defaultConfigurationName = Release;')
    add(9, f'isa = PBXSourcesBuildPhase; buildActionMask = 2147483647; files = {refs(build_refs)}; runOnlyForDeploymentPostprocessing = 0;')
    add(20, 'isa = PBXFrameworksBuildPhase; buildActionMask = 2147483647; files = (); runOnlyForDeploymentPostprocessing = 0;')
    add(21, f'isa = PBXResourcesBuildPhase; buildActionMask = 2147483647; files = ({oid(31)}); runOnlyForDeploymentPostprocessing = 0;')
    add(30, 'isa = PBXFileReference; lastKnownFileType = folder.assetcatalog; path = Assets.xcassets; sourceTree = "<group>";')
    add(31, f'isa = PBXBuildFile; fileRef = {oid(30)};')
    add(40, 'isa = PBXFileReference; lastKnownFileType = sourcecode.swift; path = NodeUITests.swift; sourceTree = "<group>";')
    add(41, f'isa = PBXBuildFile; fileRef = {oid(40)};')
    add(42, f'isa = PBXNativeTarget; buildConfigurationList = {oid(43)}; buildPhases = {refs([46,50,51])}; buildRules = (); dependencies = ({oid(48)}); name = AttestNodeUITests; productName = AttestNodeUITests; productReference = {oid(47)}; productType = "com.apple.product-type.bundle.ui-testing";')
    add(43, f'isa = XCConfigurationList; buildConfigurations = {refs([44,45])}; defaultConfigurationIsVisible = 0; defaultConfigurationName = Release;')
    for n, name in [(44,'Debug'), (45,'Release')]:
        add(n, f'isa = XCBuildConfiguration; buildSettings = {{ GENERATE_INFOPLIST_FILE = YES; PRODUCT_BUNDLE_IDENTIFIER = dev.dsmack.attestnode.uitests; PRODUCT_NAME = "$(TARGET_NAME)"; TEST_TARGET_NAME = AttestNode; SWIFT_VERSION = 5.0; TARGETED_DEVICE_FAMILY = 1; CODE_SIGN_STYLE = Automatic; }}; name = {name};')
    add(46, f'isa = PBXSourcesBuildPhase; buildActionMask = 2147483647; files = ({oid(41)}); runOnlyForDeploymentPostprocessing = 0;')
    add(47, 'isa = PBXFileReference; explicitFileType = wrapper.cfbundle; path = AttestNodeUITests.xctest; sourceTree = BUILT_PRODUCTS_DIR;')
    add(48, f'isa = PBXTargetDependency; target = {oid(5)}; targetProxy = {oid(49)};')
    add(49, f'isa = PBXContainerItemProxy; containerPortal = {oid(1)}; proxyType = 1; remoteGlobalIDString = {oid(5)}; remoteInfo = AttestNode;')
    add(50, 'isa = PBXFrameworksBuildPhase; buildActionMask = 2147483647; files = (); runOnlyForDeploymentPostprocessing = 0;')
    add(51, 'isa = PBXResourcesBuildPhase; buildActionMask = 2147483647; files = (); runOnlyForDeploymentPostprocessing = 0;')
    for n, name in [(10,'Debug'), (11,'Release')]:
        add(n, f'isa = XCBuildConfiguration; buildSettings = {{ SDKROOT = iphoneos; IPHONEOS_DEPLOYMENT_TARGET = 27.0; }}; name = {name};')
    settings = '''ALWAYS_SEARCH_USER_PATHS = NO; CODE_SIGN_STYLE = Automatic;
CODE_SIGN_ENTITLEMENTS = Node.entitlements; GENERATE_INFOPLIST_FILE = NO;
INFOPLIST_FILE = Node-Release.plist; PRODUCT_BUNDLE_IDENTIFIER = dev.dsmack.provider;
PRODUCT_NAME = "$(TARGET_NAME)"; SWIFT_VERSION = 5.0; TARGETED_DEVICE_FAMILY = 1;
SUPPORTED_PLATFORMS = "iphoneos iphonesimulator"; SUPPORTS_MACCATALYST = NO;
CURRENT_PROJECT_VERSION = 3; MARKETING_VERSION = 0.1.0;
ASSETCATALOG_COMPILER_APPICON_NAME = AppIcon;
'''
    for n, name, opt in [(12,'Debug','-Onone'), (13,'Release','-O')]:
        add(n, f'isa = XCBuildConfiguration; buildSettings = {{{settings} SWIFT_OPTIMIZATION_LEVEL = "{opt}"; }}; name = {name};')
    project = DEST / 'AttestNode.xcodeproj'
    project.mkdir(exist_ok=True)
    (project / 'project.pbxproj').write_text('// !$*UTF8*$!\n{archiveVersion = 1; classes = {}; objectVersion = 56; objects = {\n' + '\n'.join(objects) + f'\n}}; rootObject = {oid(1)}; }}\n')
    info = plistlib.loads((DEST / 'Info.plist').read_bytes())
    info.update(CFBundleIdentifier='$(PRODUCT_BUNDLE_IDENTIFIER)', CFBundleExecutable='$(EXECUTABLE_NAME)',
                CFBundleName='$(PRODUCT_NAME)', CFBundleVersion='$(CURRENT_PROJECT_VERSION)',
                CFBundleShortVersionString='$(MARKETING_VERSION)', MinimumOSVersion='$(IPHONEOS_DEPLOYMENT_TARGET)', ITSAppUsesNonExemptEncryption=False)
    # Encryption is supplied by Apple CryptoKit/system TLS; no bundled encryption
    # implementation. Reassess this declaration if that changes in a fork.
    (DEST / 'Node-Release.plist').write_bytes(plistlib.dumps(info))
    (DEST / 'Node.entitlements').write_bytes(plistlib.dumps({
        'com.apple.developer.devicecheck.appattest-environment': 'production',
        'com.apple.developer.devicecheck.app-attest-opt-in': ['CDhash']}))
    schemes = project / 'xcshareddata/xcschemes'
    schemes.mkdir(parents=True, exist_ok=True)
    buildable = f'<BuildableReference BuildableIdentifier="primary" BlueprintIdentifier="{oid(5)}" BuildableName="AttestNode.app" BlueprintName="AttestNode" ReferencedContainer="container:AttestNode.xcodeproj"/>'
    (schemes / 'AttestNode.xcscheme').write_text(f'''<?xml version="1.0" encoding="UTF-8"?>
<Scheme LastUpgradeVersion="2700" version="1.3">
<BuildAction parallelizeBuildables="YES" buildImplicitDependencies="YES"><BuildActionEntries><BuildActionEntry buildForTesting="YES" buildForRunning="YES" buildForProfiling="YES" buildForArchiving="YES" buildForAnalyzing="YES">{buildable}</BuildActionEntry></BuildActionEntries></BuildAction>
<TestAction buildConfiguration="Debug" shouldUseLaunchSchemeArgsEnv="YES"><Testables><TestableReference skipped="NO"><BuildableReference BuildableIdentifier="primary" BlueprintIdentifier="{oid(42)}" BuildableName="AttestNodeUITests.xctest" BlueprintName="AttestNodeUITests" ReferencedContainer="container:AttestNode.xcodeproj"/></TestableReference></Testables></TestAction>
<LaunchAction buildConfiguration="Debug" launchStyle="0" useCustomWorkingDirectory="NO"><BuildableProductRunnable runnableDebuggingMode="0">{buildable}</BuildableProductRunnable></LaunchAction>
<ArchiveAction buildConfiguration="Release" revealArchiveInOrganizer="YES"/>
</Scheme>
''')
    print(project)


if __name__ == '__main__':
    main()
