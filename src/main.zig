const std = @import("std");
const openssl = @cImport({
    @cInclude("openssl/crypto.h");
    @cInclude("openssl/obj_mac.h");
    @cInclude("openssl/ec.h");
    @cInclude("openssl/err.h");
});

fn generate_key(key : *?*openssl.EC_KEY, skey : *?*const openssl.BIGNUM) !void {
    std.log.info("NID: {}", .{openssl.NID_secp256k1});
    key.* = openssl.EC_KEY_new_by_curve_name(openssl.NID_secp256k1);
    if (key.* == null) {
        std.log.info("could not create key: {}", .{openssl.ERR_get_error()});
        return error.CouldNotCreateKey;
    }
    errdefer openssl.EC_KEY_free(key.*);

    if (openssl.EC_KEY_generate_key(key.*) != 1) {
        std.log.info("could not generate random key: {}", .{openssl.ERR_get_error()});
        return error.CouldNotGenerateKey;
    }

    if (openssl.EC_KEY_check_key(key.*) != 1) {
        return error.GeneratedKeyIsNotValid;
    }

    skey.* = openssl.EC_KEY_get0_private_key(key.*);
    if (skey.* == null) {
        std.log.info("could not get private key: {}", .{openssl.ERR_get_error()});
        return error.CouldNotGetPrivateKey;
    }
    std.log.info("secret key: {}", .{@ptrCast([*:0]u8, openssl.BN_bn2hex(skey.*))});
}

fn get_pkey(key : ?*openssl.EC_KEY) !*const openssl.EC_POINT {
    var pkey = openssl.EC_KEY_get0_public_key(key);
    if (pkey == null) {
        std.log.info("could not get public key: {}", .{openssl.ERR_get_error()});
        return error.CouldNotGetPublicKey;
    }
    return pkey.?;
}

fn get_bobs_key() !*openssl.EC_KEY {
    var keybob = openssl.EC_KEY_new_by_curve_name(openssl.NID_secp256k1);
    if (keybob == null) {
        std.log.info("could not create Bob's public key: {}", .{@ptrCast([*:0]const u8, openssl.ERR_reason_error_string(openssl.ERR_get_error()))});
        return error.CouldNotCreateBobsPublicKey;
    }
    errdefer openssl.EC_KEY_free(keybob);

    var x_bob = openssl.BN_new();
    if (openssl.BN_hex2bn(&x_bob, "ed5253cbb93b61511c27b3417d063843b9ccdd884ed00944ff3d10d1abc3b794") == 1) {
        return error.InvalidXCoordinate;
    }
    defer openssl.BN_clear_free(x_bob);
    var y_bob = openssl.BN_new();
    if (openssl.BN_hex2bn(&y_bob, "98de555c716c1683e82107c990c7cc9fbf80c68ca8e82c25b34cf0d267d1383e") == 1) {
        return error.InvalidYCoordinate;
    }
    defer openssl.BN_clear_free(y_bob);
    if (openssl.EC_KEY_set_public_key_affine_coordinates(keybob, x_bob, y_bob) == 0) {
        std.log.info("could not set Bob's public key: {}", .{@ptrCast([*:0]const u8, openssl.ERR_reason_error_string(openssl.ERR_get_error()))});
        return error.CouldNotSetBobsPublicKey;
    }

    if (openssl.EC_KEY_check_key(keybob) != 1) {
        return error.BobsKeyIsNotValid;
    }

    return keybob.?;
}

        std.log.info("could not create r: {}", .{openssl.ERR_get_error()});
        return error.CouldNotCreateS;
    }
        std.log.info("could not compute S: {}", .{openssl.ERR_get_error()});
        return error.CouldNotComputeS;
    }
pub fn main() anyerror!void {
    var err = openssl.OPENSSL_init_crypto(openssl.OPENSSL_INIT_LOAD_CONFIG, null);
    if (err == 0) {
        std.log.info("error initializing openssl: {}", .{openssl.ERR_get_error()});
    }
    defer openssl.OPENSSL_cleanup();
    std.log.info("initialized", .{});

    var key : ?*openssl.EC_KEY = undefined;
    var skey : ?*openssl.BIGNUM = undefined;
    try generate_key(&key, &skey);
    defer openssl.EC_KEY_free(key);

    var pkey = try get_pkey(key);
    
    const group = openssl.EC_KEY_get0_group(key);

    // Prepare Kb 
    var keybob = try get_bobs_key();
    defer openssl.EC_KEY_free(keybob);
    const bob_pkey = try get_pkey(keybob);
}
