// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/// @notice NIST P-384 / secp384r1 ECDSA signature verification.
///
/// Ported 2026-05-20 from LogvinovLeon/estid-sig (GPL/MIT, 0.4.24) — the
/// Estonian e-ID verifier. Originally three contracts (LibMath / FieldP384 /
/// FieldO384 / Curve384) flattened into one library, with hi/lo 128+256-bit
/// representations preserved. Scalar multiplication uses Jacobian coordinates
/// with joint multiplication for the fixed Apple CA key and generator.
/// Formulas: https://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html
/// Enrollment must be gas-tested using current chain precompile pricing.
///
/// All field/curve constants:
///   p (prime field):    0xff..ff 0000..00 ff..ff   ← 384 bits as (phi||plo)
///   n (generator order): NIST recommended
library P384 {
    // ---- Field modulo p (the prime) ----
    uint256 constant phi = 0xffffffffffffffffffffffffffffffff;
    uint256 constant plo =
        0xfffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff;
    // Carmichael (p - 2 for inversion via Fermat)
    uint256 constant chi = 0xffffffffffffffffffffffffffffffff;
    uint256 constant clo =
        0xfffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffd;

    // ---- Field modulo n (generator order) ----
    uint256 constant ohi = 0xffffffffffffffffffffffffffffffff;
    uint256 constant olo =
        0xffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973;
    // n - 2 for inversion
    uint256 constant ochi = 0xffffffffffffffffffffffffffffffff;
    uint256 constant oclo =
        0xffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52971;

    // ---- Curve coefficient a (a = -3 mod p) ----
    uint256 constant cahi = 0xffffffffffffffffffffffffffffffff;
    uint256 constant calo =
        0xfffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc;

    // ---- Generator G ----
    uint256 constant gxhi = 0xaa87ca22be8b05378eb1c71ef320ad74;
    uint256 constant gxlo =
        0x6e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7;
    uint256 constant gyhi = 0x3617de4a96262c6f5d9e98bf9292dc29;
    uint256 constant gylo =
        0xf8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f;

    struct C384Elm {
        uint256 xhi;
        uint256 xlo;
        uint256 yhi;
        uint256 ylo;
    }

    // =================== Low-level multi-precision math ===================

    function mul512(uint256 a, uint256 b) internal pure returns (uint256 hi, uint256 lo) {
        assembly {
            let mm := mulmod(a, b, not(0))
            lo := mul(a, b)
            hi := sub(sub(mm, lo), lt(mm, lo))
        }
    }

    function mod768x384(uint256 a2, uint256 a1, uint256 a0, uint256 mhi, uint256 mlo)
        internal
        view
        returns (uint256 hi, uint256 lo)
    {
        assembly {
            let o := mload(0x40)
            mstore(add(o, 0x000), 0x60)
            mstore(add(o, 0x020), 0x01)
            mstore(add(o, 0x040), 0x30)
            mstore(add(o, 0x060), a2)
            mstore(add(o, 0x080), a1)
            mstore(add(o, 0x0A0), a0)
            mstore8(add(o, 0x0C0), 1)
            mstore(add(o, 0x0C1), mul(mhi, 0x100000000000000000000000000000000))
            mstore(add(o, 0x0D1), mlo)
            if iszero(staticcall(gas(), 0x5, o, 0xF1, o, 0x30)) { revert(0, 0) }
            hi := mload(sub(o, 0x010))
            hi := and(hi, 0xffffffffffffffffffffffffffffffff)
            lo := mload(add(o, 0x010))
        }
    }

    function sqrmod384(uint256 bhi, uint256 blo, uint256 mhi, uint256 mlo)
        internal
        view
        returns (uint256 hi, uint256 lo)
    {
        assembly {
            let o := mload(0x40)
            mstore(add(o, 0x000), 0x30)
            mstore(add(o, 0x020), 0x01)
            mstore(add(o, 0x040), 0x30)
            mstore(add(o, 0x060), mul(bhi, 0x100000000000000000000000000000000))
            mstore(add(o, 0x070), blo)
            mstore8(add(o, 0x090), 2)
            mstore(add(o, 0x091), mul(mhi, 0x100000000000000000000000000000000))
            mstore(add(o, 0x0A1), mlo)
            if iszero(staticcall(gas(), 0x5, o, 0x0C1, o, 0x30)) { revert(0, 0) }
            hi := mload(sub(o, 0x010))
            hi := and(hi, 0xffffffffffffffffffffffffffffffff)
            lo := mload(add(o, 0x010))
        }
    }

    function powmod384(
        uint256 bhi,
        uint256 blo,
        uint256 ehi,
        uint256 elo,
        uint256 mhi,
        uint256 mlo
    ) internal view returns (uint256 hi, uint256 lo) {
        assembly {
            let o := mload(0x40)
            mstore(add(o, 0x000), 0x30)
            mstore(add(o, 0x020), 0x30)
            mstore(add(o, 0x040), 0x30)
            mstore(add(o, 0x060), mul(bhi, 0x100000000000000000000000000000000))
            mstore(add(o, 0x070), blo)
            mstore(add(o, 0x090), mul(ehi, 0x100000000000000000000000000000000))
            mstore(add(o, 0x0A0), elo)
            mstore(add(o, 0x0C0), mul(mhi, 0x100000000000000000000000000000000))
            mstore(add(o, 0x0D0), mlo)
            if iszero(staticcall(gas(), 0x5, o, 0x0F0, o, 0x30)) { revert(0, 0) }
            hi := mload(sub(o, 0x010))
            hi := and(hi, 0xffffffffffffffffffffffffffffffff)
            lo := mload(add(o, 0x010))
        }
    }

    // =================== Field arithmetic mod p ===================

    function fadd(uint256 ahi, uint256 alo, uint256 bhi, uint256 blo)
        internal
        pure
        returns (uint256 hi, uint256 lo)
    {
        assembly {
            hi := add(ahi, bhi)
            lo := add(alo, blo)
            hi := add(hi, lt(lo, alo))
        }
        if (hi > phi || (hi == phi && lo >= plo)) {
            assembly {
                hi := sub(hi, gt(0xfffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff, lo))
                hi := sub(hi, 0xffffffffffffffffffffffffffffffff)
                lo := sub(lo, 0xfffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff)
            }
        }
    }

    function fsub(uint256 ahi, uint256 alo, uint256 bhi, uint256 blo)
        internal
        pure
        returns (uint256 hi, uint256 lo)
    {
        assembly {
            hi := sub(ahi, bhi)
            lo := sub(alo, blo)
            hi := sub(hi, gt(lo, alo))
        }
        if (hi > 2 ** 255) {
            assembly {
                hi := add(hi, 0xffffffffffffffffffffffffffffffff)
                lo := add(lo, 0xfffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff)
                hi := add(hi, lt(lo, 0xfffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff))
            }
        }
    }

    function fsqr(uint256 ahi, uint256 alo) internal view returns (uint256 hi, uint256 lo) {
        return sqrmod384(ahi, alo, phi, plo);
    }

    function fmul(uint256 ahi, uint256 alo, uint256 bhi, uint256 blo)
        internal
        view
        returns (uint256 hi, uint256 lo)
    {
        uint256 r0;
        uint256 r1;
        uint256 r2;
        (r1, r0) = mul512(alo, blo);
        r2 = ahi * bhi;

        uint256 t1;
        uint256 t2;
        (t2, t1) = mul512(alo, bhi);
        assembly {
            r1 := add(r1, t1)
            r2 := add(r2, t2)
            r2 := add(r2, lt(r1, t1))
        }
        (t2, t1) = mul512(ahi, blo);
        assembly {
            r1 := add(r1, t1)
            r2 := add(r2, t2)
            r2 := add(r2, lt(r1, t1))
        }
        (hi, lo) = mod768x384(r2, r1, r0, phi, plo);
    }

    function finv(uint256 ahi, uint256 alo) internal view returns (uint256 hi, uint256 lo) {
        return powmod384(ahi, alo, chi, clo, phi, plo);
    }

    // =================== Field arithmetic mod n (order) ===================

    function omul(uint256 ahi, uint256 alo, uint256 bhi, uint256 blo)
        internal
        view
        returns (uint256 hi, uint256 lo)
    {
        uint256 r0;
        uint256 r1;
        uint256 r2;
        (r1, r0) = mul512(alo, blo);
        r2 = ahi * bhi;

        uint256 t1;
        uint256 t2;
        (t2, t1) = mul512(alo, bhi);
        assembly {
            r1 := add(r1, t1)
            r2 := add(r2, t2)
            r2 := add(r2, lt(r1, t1))
        }
        (t2, t1) = mul512(ahi, blo);
        assembly {
            r1 := add(r1, t1)
            r2 := add(r2, t2)
            r2 := add(r2, lt(r1, t1))
        }
        (hi, lo) = mod768x384(r2, r1, r0, ohi, olo);
    }

    function oinv(uint256 ahi, uint256 alo) internal view returns (uint256 hi, uint256 lo) {
        return powmod384(ahi, alo, ochi, oclo, ohi, olo);
    }

    // =================== Curve operations ===================

    function cset(C384Elm memory a, C384Elm memory b) internal pure {
        a.xhi = b.xhi;
        a.xlo = b.xlo;
        a.yhi = b.yhi;
        a.ylo = b.ylo;
    }

    function cadd(C384Elm memory a, C384Elm memory b) internal view {
        uint256 lhi;
        uint256 llo;
        uint256 thi;
        uint256 tlo;

        (lhi, llo) = fsub(a.yhi, a.ylo, b.yhi, b.ylo);
        (thi, tlo) = fsub(a.xhi, a.xlo, b.xhi, b.xlo);
        (thi, tlo) = finv(thi, tlo);
        (lhi, llo) = fmul(lhi, llo, thi, tlo);

        (thi, tlo) = fsqr(lhi, llo);
        (thi, tlo) = fsub(thi, tlo, a.xhi, a.xlo);
        (thi, tlo) = fsub(thi, tlo, b.xhi, b.xlo);
        a.xhi = thi;
        a.xlo = tlo;

        (thi, tlo) = fsub(b.xhi, b.xlo, a.xhi, a.xlo);
        (thi, tlo) = fmul(thi, tlo, lhi, llo);
        (thi, tlo) = fsub(thi, tlo, b.yhi, b.ylo);
        a.yhi = thi;
        a.ylo = tlo;
    }

    function cdbl(C384Elm memory a) internal view {
        uint256 lhi;
        uint256 llo;
        uint256 thi;
        uint256 tlo;
        uint256 xhi;
        uint256 xlo;

        (lhi, llo) = fmul(0, 3, a.xhi, a.xlo);
        (lhi, llo) = fmul(lhi, llo, a.xhi, a.xlo);
        (lhi, llo) = fadd(lhi, llo, cahi, calo);

        (thi, tlo) = fadd(a.yhi, a.ylo, a.yhi, a.ylo);
        (thi, tlo) = finv(thi, tlo);
        (lhi, llo) = fmul(lhi, llo, thi, tlo);

        (thi, tlo) = fsqr(lhi, llo);
        (thi, tlo) = fsub(thi, tlo, a.xhi, a.xlo);
        (thi, tlo) = fsub(thi, tlo, a.xhi, a.xlo);
        xhi = thi;
        xlo = tlo;

        (thi, tlo) = fsub(a.xhi, a.xlo, xhi, xlo);
        (thi, tlo) = fmul(thi, tlo, lhi, llo);
        (thi, tlo) = fsub(thi, tlo, a.yhi, a.ylo);
        a.xhi = xhi;
        a.xlo = xlo;
        a.yhi = thi;
        a.ylo = tlo;
    }

    function cmul(C384Elm memory a, uint256 rhi, uint256 rlo) internal view {
        bool running = false;
        C384Elm memory r;
        while (rhi != 0 || rlo != 0) {
            if (rlo & 1 == 1) {
                if (running) {
                    cadd(r, a);
                } else {
                    cset(r, a);
                    running = true;
                }
            }
            cdbl(a);
            assembly {
                rlo := div(rlo, 2)
                rlo := or(rlo, mul(rhi, 0x8000000000000000000000000000000000000000000000000000000000000000))
                rhi := div(rhi, 2)
            }
        }
        cset(a, r);
    }

    // Jacobian coordinates keep scalar multiplication free of field inversions.
    // dbl-2001-b and madd-2007-bl, EFD short Weierstrass a=-3 formulas.
    struct F { uint256 hi; uint256 lo; }
    struct J { F x; F y; F z; }
    function add(F memory a,F memory b) internal pure returns(F memory r){(r.hi,r.lo)=fadd(a.hi,a.lo,b.hi,b.lo);}
    function sub(F memory a,F memory b) internal pure returns(F memory r){(r.hi,r.lo)=fsub(a.hi,a.lo,b.hi,b.lo);}
    function mul(F memory a,F memory b) internal view returns(F memory r){(r.hi,r.lo)=fmul(a.hi,a.lo,b.hi,b.lo);}
    function sqr(F memory a) internal view returns(F memory r){(r.hi,r.lo)=fsqr(a.hi,a.lo);}
    function zero(F memory a) internal pure returns(bool){return a.hi==0&&a.lo==0;}
    function twice(F memory a) internal pure returns(F memory){return add(a,a);}
    function jdbl(J memory p) internal view returns(J memory r){
        if(zero(p.z)||zero(p.y))return r;
        F memory delta=sqr(p.z);F memory gamma=sqr(p.y);F memory beta=mul(p.x,gamma);
        F memory alpha=mul(sub(p.x,delta),add(p.x,delta));alpha=add(twice(alpha),alpha);
        r.x=sub(sqr(alpha),twice(twice(twice(beta))));
        r.z=sub(sub(sqr(add(p.y,p.z)),gamma),delta);
        r.y=sub(mul(alpha,sub(twice(twice(beta)),r.x)),twice(twice(twice(sqr(gamma)))));
    }
    function jadd(J memory p,C384Elm memory q) internal view returns(J memory r){
        F memory qx=F(q.xhi,q.xlo);F memory qy=F(q.yhi,q.ylo);
        if(zero(p.z))return J(qx,qy,F(0,1));
        F memory zz=sqr(p.z);F memory u=mul(qx,zz);F memory s=mul(qy,mul(p.z,zz));
        F memory h=sub(u,p.x);F memory rr=twice(sub(s,p.y));
        if(zero(h)){if(zero(rr))return jdbl(p);return r;}
        F memory hh=sqr(h);F memory i=twice(twice(hh));F memory j=mul(h,i);F memory v=mul(p.x,i);
        r.x=sub(sub(sqr(rr),j),twice(v));
        r.y=sub(mul(rr,sub(v,r.x)),twice(mul(p.y,j)));
        r.z=sub(sub(sqr(add(p.z,h)),zz),hh);
    }
    function joint(C384Elm memory g,C384Elm memory q,uint256 uh,uint256 ul,uint256 vh,uint256 vl) internal view returns(C384Elm memory out){
        // Both points are fixed, distinct nonzero trusted public constants.
        C384Elm memory sum=C384Elm(g.xhi,g.xlo,g.yhi,g.ylo);cadd(sum,q);
        J memory acc;
        for(uint256 i=384;i>0;){unchecked{--i;}
            uint256 scratch;assembly { scratch := mload(0x40) }
            J memory next=jdbl(acc);
            uint256 b=i>=256?((uh>>(i-256))&1):((ul>>i)&1);
            uint256 c=i>=256?((vh>>(i-256))&1):((vl>>i)&1);
            if(b!=0||c!=0)next=jadd(next,b!=0?(c!=0?sum:g):q);
            acc.x.hi=next.x.hi;acc.x.lo=next.x.lo;
            acc.y.hi=next.y.hi;acc.y.lo=next.y.lo;
            acc.z.hi=next.z.hi;acc.z.lo=next.z.lo;
            // All temporaries are dead; retain only the six copied limbs.
            assembly { mstore(0x40,scratch) }
        }
        if(zero(acc.z))return out;
        F memory zi;(zi.hi,zi.lo)=finv(acc.z.hi,acc.z.lo);
        F memory zz=sqr(zi);F memory x=mul(acc.x,zz);F memory y=mul(acc.y,mul(zz,zi));
        out=C384Elm(x.hi,x.lo,y.hi,y.lo);
    }

    // =================== ECDSA verify ===================

    /// @notice Verify an ECDSA P-384 signature.
    /// @param pubXhi  pubkey X high 128 bits
    /// @param pubXlo  pubkey X low 256 bits
    /// @param pubYhi  pubkey Y high 128 bits
    /// @param pubYlo  pubkey Y low 256 bits
    /// @param msgHash hashed message as uint256 (caller pre-hashes to fit). For
    ///                ecdsa-with-SHA256, that's the SHA-256 digest in the
    ///                low 256 bits.
    /// @param rhi     signature r high 128 bits
    /// @param rlo     signature r low 256 bits
    /// @param shi     signature s high 128 bits
    /// @param slo     signature s low 256 bits
    function verify(
        uint256 pubXhi,
        uint256 pubXlo,
        uint256 pubYhi,
        uint256 pubYlo,
        uint256 msgHash,
        uint256 rhi,
        uint256 rlo,
        uint256 shi,
        uint256 slo
    ) internal view returns (bool) {
        C384Elm memory pub = C384Elm({xhi: pubXhi, xlo: pubXlo, yhi: pubYhi, ylo: pubYlo});
        C384Elm memory g = C384Elm({xhi: gxhi, xlo: gxlo, yhi: gyhi, ylo: gylo});
        (shi, slo) = oinv(shi, slo);
        uint256 uhi;
        uint256 ulo;
        uint256 vhi;
        uint256 vlo;
        (uhi, ulo) = omul(0, msgHash, shi, slo);
        (vhi, vlo) = omul(rhi, rlo, shi, slo);
        g = joint(g, pub, uhi, ulo, vhi, vlo);
        // ECDSA compares x mod n (p < 2n).
        if (g.xhi > ohi || (g.xhi == ohi && g.xlo >= olo)) {
            uint256 old = g.xlo;
            unchecked { g.xlo -= olo; g.xhi = g.xhi - ohi - (old < olo ? 1 : 0); }
        }
        return g.xhi == rhi && g.xlo == rlo;
    }
}
