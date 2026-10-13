// Runner measurements M_runner (CodeMeasurement of the runner executable, the node's own M definition, hex) admitted to
// the dsmack-sdk port. Compiled in, so the node's measurement M covers them; any team's signing of an admitted runner
// build has the same M_runner. Empty in source, which leaves the SDK off: the release build (scripts/release/build_mac.py
// --sdk-runner) compiles a generated copy naming the runner's M. docs/protocols/runner.md.
let compiledSDKRunnerMeasurements: [String] = []
