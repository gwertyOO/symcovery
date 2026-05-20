"""Experimental Volatility3 plugin for Linux task_struct symbol recovery."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from volatility3.framework import exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces.plugins import PluginInterface


@dataclass(frozen=True)
class RecoveredField:
    """Represents a recovered task_struct field offset."""

    name: str
    offset: int
    details: str


class LinuxSymbolRecovery(PluginInterface):
    """Recovers initial Linux task_struct offsets from a provided init_task address."""

    _version = (0, 1, 0)
    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> list[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel module",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.IntRequirement(
                name="init_task",
                description=(
                    "Virtual address of init_task. Automatic init_task recovery "
                    "is not implemented yet"
                ),
                optional=True,
            ),
            requirements.IntRequirement(
                name="max_scan_size",
                description="Maximum bytes to scan within task_struct candidates",
                default=0x1000,
                optional=True,
            ),
        ]

    def _ensure_init_task(self) -> int:
        init_task = self.config.get("init_task", None)
        if init_task is None:
            raise exceptions.VolatilityException(
                "Automatic init_task discovery is not implemented yet. "
                "Please provide --init-task."
            )
        return int(init_task)

    def _recover_comm_offset(self, layer_name: str, init_task: int, max_scan_size: int) -> RecoveredField:
        layer = self.context.layers[layer_name]
        swapper_signature = b"swapper\x00"
        data = layer.read(init_task, max_scan_size, pad=True)

        offset = data.find(swapper_signature)
        if offset < 0:
            raise exceptions.VolatilityException(
                "Unable to locate 'swapper' string within scan window from init_task"
            )

        return RecoveredField(
            name="comm",
            offset=offset,
            details=f"Matched 'swapper' signature at +0x{offset:x}",
        )

    def _iter_pointer_candidates(
        self, layer_name: str, init_task: int, max_scan_size: int, pointer_size: int
    ) -> Iterable[int]:
        layer = self.context.layers[layer_name]
        data = layer.read(init_task, max_scan_size, pad=True)

        for offset in range(0, max_scan_size - pointer_size + 1, pointer_size):
            value = int.from_bytes(data[offset : offset + pointer_size], byteorder="little", signed=False)
            if value == init_task:
                yield offset

    def _recover_parent_offset(
        self, layer_name: str, init_task: int, max_scan_size: int, pointer_size: int
    ) -> RecoveredField:
        candidates = list(
            self._iter_pointer_candidates(layer_name, init_task, max_scan_size, pointer_size)
        )
        if not candidates:
            raise exceptions.VolatilityException(
                "Unable to identify pointer-sized fields that self-reference init_task"
            )

        # For init_task, real_parent/parent are expected to self-reference.
        parent_offset = min(candidates)
        return RecoveredField(
            name="parent",
            offset=parent_offset,
            details=(
                f"Detected self-referential pointer at +0x{parent_offset:x}; "
                f"all candidates: {', '.join(hex(candidate) for candidate in candidates)}"
            ),
        )

    def _recover_initial_fields(self, module_name: str, init_task: int, max_scan_size: int) -> list[RecoveredField]:
        kernel = self.context.modules[module_name]
        layer_name = kernel.layer_name
        pointer_size = self.context.layers[layer_name].address_mask.bit_length() // 8
        if pointer_size not in (4, 8):
            pointer_size = 8

        comm = self._recover_comm_offset(layer_name, init_task, max_scan_size)
        parent = self._recover_parent_offset(layer_name, init_task, max_scan_size, pointer_size)

        return [comm, parent]

    def _generator(self):
        module_name = self.config["kernel"]
        init_task = self._ensure_init_task()
        max_scan_size = int(self.config.get("max_scan_size", 0x1000))

        recovered_fields = self._recover_initial_fields(module_name, init_task, max_scan_size)

        for recovered in recovered_fields:
            yield (0, (recovered.name, hex(recovered.offset), recovered.details))

    def run(self) -> renderers.TreeGrid:
        return renderers.TreeGrid(
            [("Field", str), ("Offset", str), ("Details", str)],
            self._generator(),
        )


__all__ = ["LinuxSymbolRecovery"]
