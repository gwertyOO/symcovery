"""Experimental Volatility3 plugin for Linux task_struct symbol recovery."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Sequence

from volatility3.framework import exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces.plugins import PluginInterface


@dataclass(frozen=True)
class RecoveredField:
    """Represents a recovered task_struct field offset."""

    name: str
    offset: int
    details: str


@dataclass(frozen=True)
class CandidateField:
    """Represents a field with multiple possible offsets."""

    name: str
    offsets: tuple[int, ...]
    details: str


class LinuxSymbolRecovery(PluginInterface):
    """Recovers initial Linux task_struct offsets from a provided init_task address."""

    _version = (0, 2, 0)
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

    def _find_comm_signature_offset(self, data: bytes, signatures: Sequence[bytes]) -> tuple[int, bytes]:
        for signature in signatures:
            offset = data.find(signature)
            if offset >= 0:
                return offset, signature

        raise exceptions.VolatilityException(
            "Unable to locate a supported init task comm signature within scan window from init_task"
        )

    def _recover_comm_offset(self, layer_name: str, init_task: int, max_scan_size: int) -> RecoveredField:
        layer = self.context.layers[layer_name]
        data = layer.read(init_task, max_scan_size, pad=True)

        signatures: Sequence[bytes] = (
            b"swapper\x00",
            b"swapper/0\x00",
            b"swapper/",
        )
        offset, matched_signature = self._find_comm_signature_offset(data, signatures)

        return RecoveredField(
            name="comm",
            offset=offset,
            details=(
                "Matched init task comm signature "
                f"{matched_signature!r} at +0x{offset:x}"
            ),
        )

    def _iter_pointer_candidates(
        self, layer_name: str, init_task: int, max_scan_size: int, pointer_size: int
    ) -> Iterable[tuple[int, int]]:
        layer = self.context.layers[layer_name]
        data = layer.read(init_task, max_scan_size, pad=True)

        for offset in range(0, max_scan_size - pointer_size + 1, pointer_size):
            value = int.from_bytes(data[offset : offset + pointer_size], byteorder="little", signed=False)
            yield offset, value

    def _recover_parent_candidates(
        self, layer_name: str, init_task: int, max_scan_size: int, pointer_size: int
    ) -> CandidateField:
        candidates = [
            offset
            for offset, value in self._iter_pointer_candidates(layer_name, init_task, max_scan_size, pointer_size)
            if value == init_task
        ]
        if not candidates:
            raise exceptions.VolatilityException(
                "Unable to identify pointer-sized fields that self-reference init_task"
            )

        return CandidateField(
            name="parent_or_real_parent_or_group_leader",
            offsets=tuple(candidates),
            details=(
                "Self-referential pointer candidates in init_task; these commonly include "
                "real_parent, parent, and group_leader"
            ),
        )

    def _recover_children_candidates(
        self,
        layer_name: str,
        init_task: int,
        max_scan_size: int,
        pointer_size: int,
        comm_offset: int,
    ) -> CandidateField:
        layer = self.context.layers[layer_name]
        candidates: list[int] = []

        for offset, value in self._iter_pointer_candidates(layer_name, init_task, max_scan_size, pointer_size):
            if value == init_task:
                continue

            # Heuristic: children list head points to first child's sibling list_head.
            # If so, nearby memory around that pointer should contain a parent-like pointer to init_task.
            try:
                neighbor = layer.read(value - (pointer_size * 8), pointer_size * 16, pad=True)
            except exceptions.InvalidAddressException:
                continue

            has_backref = False
            for scan_offset in range(0, len(neighbor) - pointer_size + 1, pointer_size):
                ptr = int.from_bytes(
                    neighbor[scan_offset : scan_offset + pointer_size],
                    byteorder="little",
                    signed=False,
                )
                if ptr == init_task:
                    has_backref = True
                    break

            if not has_backref:
                continue

            # Optional consistency check: infer a possible task start from an "init" comm nearby.
            # This is only used as an additional filter and does not hardcode field ordering.
            inferred_ok = False
            try:
                scan_blob = layer.read(value - 0x600, 0xC00, pad=True)
            except exceptions.InvalidAddressException:
                scan_blob = b""

            init_name_hits = [scan_blob.find(b"init\x00"), scan_blob.find(b"init/")]
            for hit in init_name_hits:
                if hit < 0:
                    continue
                inferred_task_start = (value - 0x600) + hit - comm_offset
                if inferred_task_start <= 0:
                    continue
                try:
                    marker = layer.read(inferred_task_start + comm_offset, 5, pad=True)
                except exceptions.InvalidAddressException:
                    continue
                if marker.startswith(b"init"):
                    inferred_ok = True
                    break

            if inferred_ok:
                candidates.append(offset)

        if not candidates:
            return CandidateField(
                name="children_candidate",
                offsets=tuple(),
                details=(
                    "No strong children candidates found yet; need broader cross-task checks "
                    "in later recovery stages"
                ),
            )

        return CandidateField(
            name="children_candidate",
            offsets=tuple(sorted(set(candidates))),
            details=(
                "Pointer candidates whose targets look like child sibling-list nodes with "
                "an init_task back-reference nearby"
            ),
        )

    def _recover_initial_fields(self, module_name: str, init_task: int, max_scan_size: int) -> list[RecoveredField]:
        kernel = self.context.modules[module_name]
        layer_name = kernel.layer_name
        pointer_size = max(4, (self.context.layers[layer_name].address_mask.bit_length() + 1) // 8)
        if pointer_size not in (4, 8):
            pointer_size = 8

        comm = self._recover_comm_offset(layer_name, init_task, max_scan_size)
        parent_candidates = self._recover_parent_candidates(
            layer_name, init_task, max_scan_size, pointer_size
        )
        children_candidates = self._recover_children_candidates(
            layer_name, init_task, max_scan_size, pointer_size, comm.offset
        )

        return [
            comm,
            RecoveredField(
                name=parent_candidates.name,
                offset=parent_candidates.offsets[0],
                details=(
                    f"candidate offsets: {', '.join(hex(o) for o in parent_candidates.offsets)}; "
                    f"{parent_candidates.details}"
                ),
            ),
            RecoveredField(
                name=children_candidates.name,
                offset=children_candidates.offsets[0] if children_candidates.offsets else -1,
                details=(
                    (
                        f"candidate offsets: {', '.join(hex(o) for o in children_candidates.offsets)}; "
                        if children_candidates.offsets
                        else "candidate offsets: none; "
                    )
                    + children_candidates.details
                ),
            ),
        ]

    def _generator(self):
        module_name = self.config["kernel"]
        init_task = self._ensure_init_task()
        max_scan_size = int(self.config.get("max_scan_size", 0x1000))

        recovered_fields = self._recover_initial_fields(module_name, init_task, max_scan_size)

        for recovered in recovered_fields:
            offset_repr = "n/a" if recovered.offset < 0 else hex(recovered.offset)
            yield (0, (recovered.name, offset_repr, recovered.details))

    def run(self) -> renderers.TreeGrid:
        return renderers.TreeGrid(
            [("Field", str), ("Offset", str), ("Details", str)],
            self._generator(),
        )


__all__ = ["LinuxSymbolRecovery"]
