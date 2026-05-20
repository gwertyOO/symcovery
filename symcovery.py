"""Experimental Volatility3 plugin for Linux task_struct symbol recovery."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Sequence

from volatility3.framework import exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces.plugins import PluginInterface


@dataclass(frozen=True)
class RecoveredField:
    name: str
    offset: int
    details: str


@dataclass(frozen=True)
class CandidateField:
    name: str
    offsets: tuple[int, ...]
    details: str


class LinuxSymbolRecovery(PluginInterface):
    """Recovers initial Linux task_struct offsets from a provided init_task address."""

    _version = (0, 3, 0)
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
                "Automatic init_task discovery is not implemented yet. Please provide --init-task."
            )
        return int(init_task)

    def _find_comm_signature_offset(self, data: bytes, signatures: Sequence[bytes]) -> tuple[int, bytes]:
        for signature in signatures:
            offset = data.find(signature)
            if offset >= 0:
                return offset, signature
        raise exceptions.VolatilityException("Unable to locate a supported init_task comm signature")

    def _iter_pointer_candidates(self, layer_name: str, init_task: int, max_scan_size: int, pointer_size: int) -> Iterable[tuple[int, int]]:
        layer = self.context.layers[layer_name]
        data = layer.read(init_task, max_scan_size, pad=True)
        for offset in range(0, max_scan_size - pointer_size + 1, pointer_size):
            value = int.from_bytes(data[offset : offset + pointer_size], byteorder="little", signed=False)
            yield offset, value

    def _recover_comm_offset(self, layer_name: str, init_task: int, max_scan_size: int) -> RecoveredField:
        layer = self.context.layers[layer_name]
        data = layer.read(init_task, max_scan_size, pad=True)
        offset, sig = self._find_comm_signature_offset(data, (b"swapper\x00", b"swapper/0\x00", b"swapper/"))
        return RecoveredField("comm", offset, f"Matched init task comm signature {sig!r} at +0x{offset:x}")

    def _recover_parent_candidates(self, layer_name: str, init_task: int, max_scan_size: int, pointer_size: int) -> CandidateField:
        offsets = tuple(
            off for off, value in self._iter_pointer_candidates(layer_name, init_task, max_scan_size, pointer_size)
            if value == init_task
        )
        if not offsets:
            raise exceptions.VolatilityException("Unable to identify self-referential pointer candidates")
        return CandidateField(
            "parent_or_real_parent_or_group_leader",
            offsets,
            "Self-referential pointer candidates in init_task",
        )

    def _recover_children_candidates(self, layer_name: str, init_task: int, max_scan_size: int, pointer_size: int) -> CandidateField:
        layer = self.context.layers[layer_name]
        candidates: list[int] = []
        for off, value in self._iter_pointer_candidates(layer_name, init_task, max_scan_size, pointer_size):
            if value == init_task:
                continue
            try:
                around = layer.read(value - pointer_size * 8, pointer_size * 16, pad=True)
            except exceptions.InvalidAddressException:
                continue
            if any(
                int.from_bytes(around[i:i+pointer_size], 'little', signed=False) == init_task
                for i in range(0, len(around) - pointer_size + 1, pointer_size)
            ):
                candidates.append(off)
        return CandidateField(
            "children_candidate",
            tuple(sorted(set(candidates))),
            "Candidates whose target neighborhood contains back-references to init_task",
        )

    def _task_start_from_link(self, link: int, sibling_offset: int) -> int:
        return link - sibling_offset

    def _validate_relation_candidates(
        self,
        layer_name: str,
        init_task: int,
        max_scan_size: int,
        pointer_size: int,
        parent_candidates: CandidateField,
        children_candidates: CandidateField,
    ) -> list[RecoveredField]:
        layer = self.context.layers[layer_name]
        findings: list[RecoveredField] = []

        for children_offset in children_candidates.offsets:
            children_next = int.from_bytes(
                layer.read(init_task + children_offset, pointer_size, pad=True), "little", signed=False
            )
            for sibling_offset in range(0, max_scan_size - pointer_size + 1, pointer_size):
                child_task = self._task_start_from_link(children_next, sibling_offset)
                if child_task <= 0:
                    continue
                for parent_offset in parent_candidates.offsets:
                    try:
                        parent_ptr = int.from_bytes(
                            layer.read(child_task + parent_offset, pointer_size, pad=True),
                            "little",
                            signed=False,
                        )
                    except exceptions.InvalidAddressException:
                        continue
                    if parent_ptr != init_task:
                        continue
                    findings.append(
                        RecoveredField(
                            "children_sibling_parent_relation",
                            children_offset,
                            (
                                f"children=0x{children_offset:x}, sibling=0x{sibling_offset:x}, "
                                f"parent-like=0x{parent_offset:x} validates first child back-reference"
                            ),
                        )
                    )
        return findings

    def _recover_pid_candidates(
        self,
        layer_name: str,
        init_task: int,
        max_scan_size: int,
        pointer_size: int,
        relation_findings: list[RecoveredField],
    ) -> CandidateField:
        if not relation_findings:
            return CandidateField("pid_candidate", tuple(), "No relation-validated child task available yet")

        layer = self.context.layers[layer_name]
        # Use first validated relation tuple.
        detail = relation_findings[0].details
        parts = {x.split('=')[0]: int(x.split('=')[1], 16) for x in detail.replace(',', '').split() if '=' in x and x.split('=')[1].startswith('0x')}
        children_offset = parts["children"]
        sibling_offset = parts["sibling"]

        child_link = int.from_bytes(layer.read(init_task + children_offset, pointer_size, pad=True), "little", signed=False)
        child_task = child_link - sibling_offset

        init_blob = layer.read(init_task, max_scan_size, pad=True)
        child_blob = layer.read(child_task, max_scan_size, pad=True)

        candidates: list[int] = []
        for off in range(0, max_scan_size - 4 + 1, 4):
            init_u32 = int.from_bytes(init_blob[off:off+4], 'little', signed=False)
            child_u32 = int.from_bytes(child_blob[off:off+4], 'little', signed=False)
            if init_u32 == 0 and child_u32 == 1:
                candidates.append(off)

        return CandidateField("pid_candidate", tuple(candidates), "u32 offsets where init_task==0 and first child==1")

    def _recover_initial_fields(self, module_name: str, init_task: int, max_scan_size: int) -> list[RecoveredField]:
        kernel = self.context.modules[module_name]
        layer_name = kernel.layer_name
        pointer_size = max(4, (self.context.layers[layer_name].address_mask.bit_length() + 1) // 8)
        if pointer_size not in (4, 8):
            pointer_size = 8

        comm = self._recover_comm_offset(layer_name, init_task, max_scan_size)
        parent_candidates = self._recover_parent_candidates(layer_name, init_task, max_scan_size, pointer_size)
        children_candidates = self._recover_children_candidates(layer_name, init_task, max_scan_size, pointer_size)
        relation_findings = self._validate_relation_candidates(
            layer_name, init_task, max_scan_size, pointer_size, parent_candidates, children_candidates
        )
        pid_candidates = self._recover_pid_candidates(
            layer_name, init_task, max_scan_size, pointer_size, relation_findings
        )

        rows = [
            comm,
            RecoveredField(parent_candidates.name, parent_candidates.offsets[0], f"candidate offsets: {', '.join(hex(o) for o in parent_candidates.offsets)}"),
            RecoveredField(
                children_candidates.name,
                children_candidates.offsets[0] if children_candidates.offsets else -1,
                (
                    f"candidate offsets: {', '.join(hex(o) for o in children_candidates.offsets)}"
                    if children_candidates.offsets else "candidate offsets: none"
                ),
            ),
            RecoveredField(
                pid_candidates.name,
                pid_candidates.offsets[0] if pid_candidates.offsets else -1,
                (
                    f"candidate offsets: {', '.join(hex(o) for o in pid_candidates.offsets)}; {pid_candidates.details}"
                    if pid_candidates.offsets else f"candidate offsets: none; {pid_candidates.details}"
                ),
            ),
        ]
        rows.extend(relation_findings)
        return rows

    def _generator(self):
        module_name = self.config["kernel"]
        init_task = self._ensure_init_task()
        max_scan_size = int(self.config.get("max_scan_size", 0x1000))
        for recovered in self._recover_initial_fields(module_name, init_task, max_scan_size):
            yield (0, (recovered.name, "n/a" if recovered.offset < 0 else hex(recovered.offset), recovered.details))

    def run(self) -> renderers.TreeGrid:
        return renderers.TreeGrid([("Field", str), ("Offset", str), ("Details", str)], self._generator())


__all__ = ["LinuxSymbolRecovery"]
