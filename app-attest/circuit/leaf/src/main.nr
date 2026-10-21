fn main(leaf: [u8;4096], leaf_len: u32, intermediate_x: [u8;48], intermediate_y: [u8;48],
    auth: [u8;1024], auth_len: u32, client_hash: [u8;32], public: pub [Field;24]) {
    app_attest::leaf_only::check(leaf,leaf_len,intermediate_x,intermediate_y,auth,auth_len,client_hash,public);
}
