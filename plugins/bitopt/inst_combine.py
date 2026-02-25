from typing import Optional
import ida_hexrays

from .helpers import visit_call_insns_post_order


def _combine_bswap(outer: ida_hexrays.minsn_t, op: ida_hexrays.mop_t) -> int:
    outer_args = outer.d.f.args

    # bswapN(bswapN(x)) -> x
    if (
        outer_args[0].t == ida_hexrays.mop_d
        and outer_args[0].d.opcode == ida_hexrays.m_call
    ):
        inner = outer_args[0].d
        if (
            inner.get_role() == ida_hexrays.ROLE_BSWAP
            and outer.l.helper == inner.l.helper
        ):
            inner_args = inner.d.f.args
            assert inner_args[0].size == outer_args[0].size

            new_op = ida_hexrays.mop_t(inner_args[0])
            op.erase()
            op.swap(new_op)
            return 1

    return 0


def _combine_rot(outer: ida_hexrays.minsn_t, op: ida_hexrays.mop_t) -> int:
    outer_args = outer.d.f.args

    # Si, So = const
    # rotrN(rotrN(x, Si), So) -> rotrN(x, (So + Si) % N)
    # rotrN(rotlN(x, Si), So) -> rotrN(x, (So + (N - Si)) % N)
    if (
        outer_args[0].t == ida_hexrays.mop_d
        and outer_args[0].d.opcode == ida_hexrays.m_call
    ):
        inner = outer_args[0].d
        if inner.get_role() in [ida_hexrays.ROLE_ROL, ida_hexrays.ROLE_ROR]:
            inner_args = inner.d.f.args
            if (
                outer_args[1].t == ida_hexrays.mop_n
                and inner_args[1].t == ida_hexrays.mop_n
            ):
                assert inner_args[0].size == outer_args[0].size
                assert inner_args[1].size == outer_args[1].size

                N = outer_args[0].size * 8
                So = outer_args[1].value(False)
                Si = inner_args[1].value(False)

                is_same = outer.get_role() == inner.get_role()
                So += Si if is_same else N - Si
                So %= N

                new_op = ida_hexrays.mop_t(inner_args[0])
                if So == 0:
                    op.erase()
                    op.swap(new_op)
                else:
                    outer_args[0].erase()
                    outer_args[0].swap(new_op)
                    outer_args[1].make_number(So, outer_args[1].size)

                return 1

    # rotrN(x, N) -> x
    # rotlN(x, N) -> x
    if (
        outer_args[1].t == ida_hexrays.mop_n
        and outer_args[1].value(False) == outer_args[0].size * 8
    ):
        new_op = ida_hexrays.mop_t(outer_args[0])
        op.erase()
        op.swap(new_op)
        return 1

    return 0


class InstCombine(ida_hexrays.optinsn_t):
    def func(self, blk, ins, optflags):
        def visitor(insn: ida_hexrays.minsn_t, op: Optional[ida_hexrays.mop_t]) -> int:
            if op is None:
                return 0

            match insn.get_role():
                case ida_hexrays.ROLE_ROL | ida_hexrays.ROLE_ROR:
                    return _combine_rot(insn, op)
                case ida_hexrays.ROLE_BSWAP:
                    return _combine_bswap(insn, op)

            return 0

        modified = visit_call_insns_post_order(ins, visitor)
        if blk is not None and modified != 0:
            blk.mark_lists_dirty()
            blk.mba.verify(True)

        return modified
