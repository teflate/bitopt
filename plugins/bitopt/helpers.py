from typing import Callable, Optional
import ida_hexrays

type CallInsnVisitor = Callable[
    [ida_hexrays.minsn_t, Optional[ida_hexrays.mop_t]], int
]


def _visit_call_insns(
    insn: ida_hexrays.minsn_t,
    insn_op: Optional[ida_hexrays.mop_t] = None,
    pre_order: Optional[CallInsnVisitor] = None,
    post_order: Optional[CallInsnVisitor] = None,
) -> int:
    modified = 0

    if insn.opcode == ida_hexrays.m_call:
        if pre_order is not None:
            modified += pre_order(insn, insn_op)

        d = insn.d
        if d.t == ida_hexrays.mop_f:
            for arg in d.f.args:
                if arg.t == ida_hexrays.mop_d:
                    modified += _visit_call_insns(arg.d, arg, pre_order, post_order)

        if post_order is not None:
            modified += post_order(insn, insn_op)
    else:

        def try_visit_op(op):
            if op is not None and op.t == ida_hexrays.mop_d:
                return _visit_call_insns(op.d, op, pre_order, post_order)
            return 0

        modified += try_visit_op(insn.l)
        modified += try_visit_op(insn.r)
        modified += try_visit_op(insn.d)

    return modified


def visit_call_insns_pre_order(
    insn: ida_hexrays.minsn_t, visitor: CallInsnVisitor
) -> int:
    return _visit_call_insns(insn, pre_order=visitor)


def visit_call_insns_post_order(
    insn: ida_hexrays.minsn_t, visitor: CallInsnVisitor
) -> int:
    return _visit_call_insns(insn, post_order=visitor)
