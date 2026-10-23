/* C entrypoint for the statically linked Rust public-data topology control. */
extern int dsmack_probe_main(void);
int main(void) { return dsmack_probe_main(); }
