import ida_idaapi
import ida_hexrays

from bitopt import ConstantFold, InstCombine


class BitoptPlugmod(ida_idaapi.plugmod_t):
    def __init__(self):
        super().__init__()

        self._passes = [
            ConstantFold(),
            InstCombine(),
        ]
        for p in self._passes:
            p.install()

    def __del__(self):
        for p in reversed(self._passes):
            p.remove()

    def run(self, _):
        pass


class BitoptPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_MULTI | ida_idaapi.PLUGIN_HIDE
    wanted_name = "bitopt"

    def init(self):
        if ida_hexrays.init_hexrays_plugin():
            return BitoptPlugmod()


def PLUGIN_ENTRY():
    return BitoptPlugin()
