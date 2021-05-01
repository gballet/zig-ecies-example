const std = @import("std");
const openssl = @cImport({
    @cInclude("openssl/crypto.h");
    @cInclude("openssl/obj_mac.h");
    @cInclude("openssl/ec.h");
    @cInclude("openssl/err.h");
    @cInclude("openssl/evp.h");
});
const crypto = std.crypto;
const builtin = std.builtin;
const aes = crypto.core.aes;
const hmac = crypto.auth.hmac;

const Key = struct {
    key: ?*openssl.EC_KEY,
    skey: ?*const openssl.BIGNUM,

    // Generate a new key
    pub fn generate() !Key {
        var this = Key{ .key = null, .skey = null };

        std.log.info("NID: {}", .{openssl.NID_secp256k1});
        this.key = openssl.EC_KEY_new_by_curve_name(openssl.NID_secp256k1);
        if (this.key == null) {
            std.log.info("could not create key: {}", .{openssl.ERR_get_error()});
            return error.CouldNotCreateKey;
        }
        errdefer openssl.EC_KEY_free(this.key.?);

        if (openssl.EC_KEY_generate_key(this.key.?) != 1) {
            std.log.info("could not generate random key: {}", .{openssl.ERR_get_error()});
            return error.CouldNotGenerateKey;
        }

        if (openssl.EC_KEY_check_key(this.key.?) != 1) {
            return error.GeneratedKeyIsNotValid;
        }

        this.skey = openssl.EC_KEY_get0_private_key(this.key);
        if (this.skey == null) {
            std.log.info("could not get private key: {}", .{openssl.ERR_get_error()});
            return error.CouldNotGetPrivateKey;
        }
        std.log.info("secret key: {}", .{@ptrCast([*:0]u8, openssl.BN_bn2hex(this.skey.?))});
        return this;
    }

    // a helper function to serialize the other party's key in these tests.
    pub fn from_coordinates(x_str: [*c]const u8, y_str: [*c]const u8) !Key {
        var newkey = openssl.EC_KEY_new_by_curve_name(openssl.NID_secp256k1);
        if (newkey == null) {
            std.log.info("could not create the public key: {}", .{@ptrCast([*:0]const u8, openssl.ERR_reason_error_string(openssl.ERR_get_error()))});
            return error.CouldNotCreateBobsPublicKey;
        }
        errdefer openssl.EC_KEY_free(newkey);

        var x_bob = openssl.BN_new();
        if (openssl.BN_hex2bn(&x_bob, x_str) == 1) {
            return error.InvalidXCoordinate;
        }
        defer openssl.BN_clear_free(x_bob);
        var y_bob = openssl.BN_new();
        if (openssl.BN_hex2bn(&y_bob, y_str) == 1) {
            return error.InvalidYCoordinate;
        }
        defer openssl.BN_clear_free(y_bob);
        if (openssl.EC_KEY_set_public_key_affine_coordinates(newkey, x_bob, y_bob) == 0) {
            std.log.info("could not set public key: {}", .{@ptrCast([*:0]const u8, openssl.ERR_reason_error_string(openssl.ERR_get_error()))});
            return error.CouldNotSetBobsPublicKey;
        }

        if (openssl.EC_KEY_check_key(newkey) != 1) {
            return error.BobsKeyIsNotValid;
        }

        return Key{
            .key = newkey,
            .skey = null,
        };
    }

    pub fn generate_shared(self: Key, other: Key) !*openssl.EC_POINT {
        const grp = self.group();

        // S = Kb*r
        var spoint = openssl.EC_POINT_new(grp.?);
        if (spoint == null) {
            std.log.info("could not create r: {}", .{openssl.ERR_get_error()});
            return error.CouldNotCreateS;
        }

        var one = openssl.BN_new();
        if (openssl.BN_one(one) != 1) {
            return error.CouldNotSetOne;
        }
        var zero = openssl.BN_new();
        if (openssl.BN_zero(zero) != 1) {
            return error.CouldNotSetZero;
        }

        // S = 0*G + r*Kb
        if (openssl.EC_POINT_mul(grp, spoint, one, try other.pubkey(), self.skey.?, null) != 1) {
            std.log.info("could not compute S: {}", .{openssl.ERR_get_error()});
            return error.CouldNotComputeS;
        }
        // check S != 0
        if (openssl.EC_POINT_is_at_infinity(grp, spoint) == 1) {
            return error.SAtInfinity;
        }

        return spoint.?;
    }

    pub fn pubkey(self: Key) !*const openssl.EC_POINT {
        var pkey = openssl.EC_KEY_get0_public_key(self.key.?);
        if (pkey == null) {
            std.log.info("could not get public key: {}", .{openssl.ERR_get_error()});
            return error.CouldNotGetPublicKey;
        }
        return pkey.?;
    }

    pub fn group(self: Key) ?*const openssl.EC_GROUP {
        return openssl.EC_KEY_get0_group(self.key.?);
    }

    pub fn free(self: Key) void {
        openssl.EC_KEY_free(self.key.?);
    }
};

const PubKey = struct {
    point: *openssl.EC_POINT,

    fn x(self: PubKey, *[32]u8) !void {
        var x = openssl.BN_new();
        defer openssl.BN_clear_free(x);
        if (openssl.EC_POINT_get_affine_coordinates_GFp(group, sekf.point, x, null, null) != 1) {
            std.log.info("could not compute S: {}", .{@ptrCast([*:0]const u8, openssl.ERR_reason_error_string(openssl.ERR_get_error()))});
            return error.CouldNotGetXCoordinate;
        }

        if (openssl.BN_bn2bin(x, out) != 32) {
            std.log.info("could not get bytes: {}", .{@ptrCast([*:0]const u8, openssl.ERR_reason_error_string(openssl.ERR_get_error()))});
            return error.CouldNotGetBytes;
        }
    }

    fn y(self: PubKey, *[32]u8) !void {
        var y = openssl.BN_new();
        defer openssl.BN_clear_free(y);
        if (openssl.EC_POINT_get_affine_coordinates_GFp(group, self.point, null, y, null) != 1) {
            std.log.info("could not compute S: {}", .{@ptrCast([*:0]const u8, openssl.ERR_reason_error_string(openssl.ERR_get_error()))});
            return error.CouldNotGetXCoordinate;
        }

        if (openssl.BN_bn2bin(y, out) != 32) {
            std.log.info("could not get bytes: {}", .{@ptrCast([*:0]const u8, openssl.ERR_reason_error_string(openssl.ERR_get_error()))});
            return error.CouldNotGetBytes;
        }
    }
};

fn get_x_coordinate(point: *const openssl.EC_POINT, group: *const openssl.EC_GROUP, out: *[32]u8) !void {
    var x = openssl.BN_new();
    defer openssl.BN_clear_free(x);
    if (openssl.EC_POINT_get_affine_coordinates_GFp(group, point, x, null, null) != 1) {
        std.log.info("could not compute S: {}", .{@ptrCast([*:0]const u8, openssl.ERR_reason_error_string(openssl.ERR_get_error()))});
        return error.CouldNotGetXCoordinate;
    }

    if (openssl.BN_bn2bin(x, out) != 32) {
        std.log.info("could not get bytes: {}", .{@ptrCast([*:0]const u8, openssl.ERR_reason_error_string(openssl.ERR_get_error()))});
        return error.CouldNotGetBytes;
    }
}

fn kdf(key: *std.ArrayList(u8), len: usize, z: []const u8, s1: ?[]const u8) !void {
    const digest_length = crypto.hash.sha3.Sha3_256.digest_length;
    var counter: u32 = 1;
    var counter_bytes = [4]u8{ 0, 0, 0, 0 };
    const aligned_len = len + (digest_length - len % digest_length) % digest_length;

    while (key.items.len < aligned_len) : (counter += 1) {
        var hasher = crypto.hash.sha3.Sha3_256.init(crypto.hash.sha3.Sha3_256.Options{});
        std.mem.writeIntBig(u32, counter_bytes[0..], counter);
        hasher.update(counter_bytes[0..]);
        hasher.update(z);
        if (s1 != null)
            hasher.update(s1.?);
        var k: [32]u8 = undefined;
        hasher.final(&k);
        _ = try key.writer().write(k[0..]);
    }
}

pub fn main() anyerror!void {
    var err = openssl.OPENSSL_init_crypto(openssl.OPENSSL_INIT_LOAD_CONFIG, null);
    if (err == 0) {
        std.log.info("error initializing openssl: {}", .{openssl.ERR_get_error()});
    }
    defer openssl.OPENSSL_cleanup();
    std.log.info("initialized", .{});

    const r = try Key.generate();
    defer r.free();

    // Prepare Kb
    var keybob = try Key.from_coordinates("ed5253cbb93b61511c27b3417d063843b9ccdd884ed00944ff3d10d1abc3b794", "98de555c716c1683e82107c990c7cc9fbf80c68ca8e82c25b34cf0d267d1383e");
    defer keybob.free();

    // Shared secret
    var spoint = try r.generate_shared(keybob);
    defer openssl.EC_POINT_clear_free(spoint);

    var s: [32]u8 = undefined;
    try get_x_coordinate(spoint, keybob.group().?, &s);

    std.log.info("s={x}", .{s});

    // KDF
    var buffer = std.ArrayList(u8).init(std.testing.allocator);
    defer buffer.deinit();
    try kdf(&buffer, 32, s[0..], null);

    const ke = buffer.items[0..16];
    const km = buffer.items[16..];

    std.log.info("ke={x} km={x} {} {}", .{ ke, km, ke.len, km.len });

    // AES encryption
    const iv = [_]u8{ 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff };
    var in = "I love croissants very, very much";
    var out: [in.len]u8 = undefined;

    var ctx = aes.Aes128.initEnc(ke.*);
    crypto.core.modes.ctr(aes.AesEncryptCtx(aes.Aes128), ctx, out[0..], in[0..], iv, builtin.Endian.Big);

    std.log.info("encrypted payload: {x} len={}", .{ out, out.len });

    // Compute the MAC
    var d: [hmac.sha2.HmacSha256.mac_length]u8 = undefined;
    var hmac256 = hmac.sha2.HmacSha256.init(km);
    hmac.sha2.HmacSha256.update(&hmac256, out[0..]);
    //crypto.auth.hmac.Hmac.update(hmac, s2);
    hmac.sha2.HmacSha256.final(&hmac256, d[0..]);

    std.log.info("d={x}", .{d});
}
