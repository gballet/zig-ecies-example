const std = @import("std");
const openssl = @cImport({
    @cInclude("openssl/crypto.h");
    @cInclude("openssl/obj_mac.h");
    @cInclude("openssl/ec.h");
    @cInclude("openssl/err.h");
});

pub fn main() anyerror!void {
    var err = openssl.OPENSSL_init_crypto(openssl.OPENSSL_INIT_LOAD_CONFIG, null);
    if (err == 0) {
        std.log.info("error initializing openssl: {}", .{openssl.ERR_get_error()});
    }
    defer openssl.OPENSSL_cleanup();
    std.log.info("initialized", .{});

    var key_opt : ?*openssl.struct_ec_key_st = openssl.EC_KEY_new_by_curve_name(openssl.NID_secp256k1);
    if (key_opt == null) {
        std.log.info("could not create key: {}", .{openssl.ERR_get_error()});
        return error.CouldNotCreateKey;
    }
    const key = key_opt.?;

    if (openssl.EC_KEY_generate_key(key_opt) != 1) {
        std.log.info("could not generate random key: {}", .{openssl.ERR_get_error()});
        return error.CouldNotGenerateKey;
    }

    var pkey_opt = openssl.EC_KEY_get0_public_key(key);
    if (pkey_opt == null) {
        std.log.info("could not get public key: {}", .{openssl.ERR_get_error()});
        return error.CouldNotGetPublicKey;
    }
    const pkey = pkey_opt.?;
    
    var skey_opt = openssl.EC_KEY_get0_private_key(key_opt.?);
    if (skey_opt == null) {
        std.log.info("could not get private key: {}", .{openssl.ERR_get_error()});
        return error.CouldNotGetPrivateKey;
    }
    const skey = skey_opt.?;
    std.log.info("secret key: {}", .{@ptrCast([*:0]u8, openssl.BN_bn2hex(skey))});

    const group = openssl.EC_KEY_get0_group(key);

    // Create R
    const rpoint_opt = openssl.EC_POINT_new(group);
    if (rpoint_opt == null) {
        std.log.info("could not create r: {}", .{openssl.ERR_get_error()});
        return error.CouldNotCreateR;
    }
    var rpoint = rpoint_opt.?;

    // S = 0*generator + Kb*r
    const spoint_opt = openssl.EC_POINT_new(group);
    if (spoint_opt == null) {
        std.log.info("could not create r: {}", .{openssl.ERR_get_error()});
        return error.CouldNotCreateS;
    }
    var spoint = spoint_opt.?;
    // TODO use keybob instead of rpoint
    if (openssl.EC_POINT_mul(group, spoint, null, rpoint, skey, null) != 1) {
        std.log.info("could not compute S: {}", .{openssl.ERR_get_error()});
        return error.CouldNotComputeS;
    }
}
