from typing import Optional
import ida_hexrays

from .helpers import visit_call_insns_post_order


def _rotl(nbits: int, x: int, s: int) -> int:
    assert nbits > 0
    assert s > 0
    return ((x << s) | (x >> (nbits - s))) & ((1 << nbits) - 1)


def _rotr(nbits: int, x: int, s: int) -> int:
    assert nbits > 0
    assert s > 0
    return ((x >> s) | (x << (nbits - s))) & ((1 << nbits) - 1)


def _bswap(nbytes: int, x: int) -> int:
    assert nbytes > 0
    y = 0
    for i in range(nbytes):
        y |= ((x >> i * 8) & 0xFF) << ((nbytes - 1 - i) * 8)
    return y


def _fold_rot(insn: ida_hexrays.minsn_t, eval) -> Optional[int]:
    args = insn.d.f.args
    assert len(args) == 2
    l, r = args[0], args[1]
    if l.t == ida_hexrays.mop_n and r.t == ida_hexrays.mop_n:
        return eval(l.size * 8, l.value(False), r.value(False))
    return None


def _fold_bswap(insn: ida_hexrays.minsn_t) -> Optional[int]:
    args = insn.d.f.args
    assert len(args) == 1
    l = args[0]
    if l.t == ida_hexrays.mop_n:
        return _bswap(l.size, l.value(False))
    return None


def _fold(insn: ida_hexrays.minsn_t) -> Optional[int]:
    match insn.get_role():
        case ida_hexrays.ROLE_ROL:
            return _fold_rot(insn, _rotl)
        case ida_hexrays.ROLE_ROR:
            return _fold_rot(insn, _rotr)
        case ida_hexrays.ROLE_BSWAP:
            return _fold_bswap(insn)
    return None


class ConstantFold(ida_hexrays.optinsn_t):
    def func(self, blk, ins, optflags):
        def visitor(insn: ida_hexrays.minsn_t, op: Optional[ida_hexrays.mop_t]) -> int:
            # The intrinsics we're intrested in
            # are always used as an operand of something
            if op is None:
                return 0

            v = _fold(insn)
            if v is not None:
                op.make_number(v, op.size)
                return 1

            return 0

        modified = visit_call_insns_post_order(ins, visitor)
        if blk is not None and modified != 0:
            blk.mark_lists_dirty()
            blk.mba.verify(True)

        return modified
