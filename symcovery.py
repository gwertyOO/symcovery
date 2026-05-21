"""Experimental Volatility3 plugin for Linux task_struct symbol recovery."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional, Sequence

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
    _version = (0, 4, 0)
    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> list[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(name="kernel", description="Linux kernel module", architectures=["Intel32", "Intel64"]),
            requirements.IntRequirement(name="init_task", description="Virtual address of init_task", optional=True),
            requirements.IntRequirement(name="max_scan_size", description="Maximum bytes to scan", default=0x1000, optional=True),
        ]

    def _ensure_init_task(self) -> int:
        init_task = self.config.get("init_task", None)
        if init_task is None:
            raise exceptions.VolatilityException("Automatic init_task discovery is not implemented yet. Please provide --init-task.")
        return int(init_task)

    def _find_comm_signature_offset(self, data: bytes, signatures: Sequence[bytes]) -> tuple[int, bytes]:
        for signature in signatures:
            offset = data.find(signature)
            if offset >= 0:
                return offset, signature
        raise exceptions.VolatilityException("Unable to locate a supported init_task comm signature")

    def _iter_pointer_candidates(self, layer_name: str, init_task: int, max_scan_size: int, pointer_size: int) -> Iterable[tuple[int, int]]:
        layer = self.context.layers[layer_name]
        blob = layer.read(init_task, max_scan_size, pad=True)
        for off in range(0, max_scan_size - pointer_size + 1, pointer_size):
            yield off, int.from_bytes(blob[off:off + pointer_size], "little", signed=False)

    def _read_pointer(self, layer_name: str, address: int, pointer_size: int) -> Optional[int]:
        try:
            return int.from_bytes(self.context.layers[layer_name].read(address, pointer_size, pad=True), "little", signed=False)
        except exceptions.InvalidAddressException:
            return None

    def _looks_like_kernel_pointer(self, value: int) -> bool:
        return value >= 0xFFFF000000000000

    def _recover_comm_offset(self, layer_name: str, init_task: int, max_scan_size: int) -> RecoveredField:
        blob = self.context.layers[layer_name].read(init_task, max_scan_size, pad=True)
        off, sig = self._find_comm_signature_offset(blob, (b"swapper\x00", b"swapper/0\x00", b"swapper/"))
        return RecoveredField("comm", off, f"Matched init task comm signature {sig!r} at +0x{off:x}")

    def _recover_parent_candidates(self, layer_name: str, init_task: int, max_scan_size: int, pointer_size: int) -> CandidateField:
        offsets = tuple(off for off, value in self._iter_pointer_candidates(layer_name, init_task, max_scan_size, pointer_size) if value == init_task)
        return CandidateField("parent_or_real_parent_or_group_leader", offsets, "Self-referential pointer candidates in init_task")

    def _recover_children_candidates(self, layer_name: str, init_task: int, max_scan_size: int, pointer_size: int) -> CandidateField:
        candidates: list[int] = []
        for off, value in self._iter_pointer_candidates(layer_name, init_task, max_scan_size, pointer_size):
            if value == init_task or not self._looks_like_kernel_pointer(value):
                continue
            around = self.context.layers[layer_name].read(value - pointer_size * 8, pointer_size * 16, pad=True)
            if any(int.from_bytes(around[i:i+pointer_size], "little", signed=False) == init_task for i in range(0, len(around) - pointer_size + 1, pointer_size)):
                candidates.append(off)
        return CandidateField("children_candidate", tuple(sorted(set(candidates))), "Candidates whose target neighborhood contains back-references to init_task")

    def _validate_relation_candidates(self, layer_name: str, init_task: int, max_scan_size: int, pointer_size: int, parent: CandidateField, children: CandidateField) -> list[RecoveredField]:
        out: dict[str, RecoveredField] = {}
        head_candidates = {init_task + off for off in children.offsets}
        for children_off in children.offsets:
            child_link = self._read_pointer(layer_name, init_task + children_off, pointer_size)
            if child_link is None or not self._looks_like_kernel_pointer(child_link):
                continue
            for sibling_off in range(0, min(max_scan_size, 0x400), pointer_size):
                child_task = child_link - sibling_off
                if child_task <= 0:
                    continue
                sib_next = self._read_pointer(layer_name, child_task + sibling_off, pointer_size)
                sib_prev = self._read_pointer(layer_name, child_task + sibling_off + pointer_size, pointer_size)
                if sib_next is None or sib_prev is None:
                    continue
                if sib_next not in head_candidates and not self._looks_like_kernel_pointer(sib_next):
                    continue
                if sib_prev not in head_candidates and not self._looks_like_kernel_pointer(sib_prev):
                    continue
                for parent_off in parent.offsets:
                    if self._read_pointer(layer_name, child_task + parent_off, pointer_size) != init_task:
                        continue
                    d = f"children=0x{children_off:x}, sibling=0x{sibling_off:x}, parent-like=0x{parent_off:x} validates child relation"
                    out[d] = RecoveredField("children_sibling_parent_relation", children_off, d)
        return list(out.values())

    def _recover_id_candidates(self, layer_name: str, init_task: int, max_scan_size: int, pointer_size: int, relations: list[RecoveredField]) -> tuple[CandidateField, CandidateField]:
        if not relations:
            return CandidateField("pid_candidate", tuple(), "No validated child relation"), CandidateField("tgid_candidate", tuple(), "No validated child relation")
        parts = {x.split('=')[0]: int(x.split('=')[1], 16) for x in relations[0].details.replace(',', '').split() if '=' in x and x.split('=')[1].startswith('0x')}
        children_off, sibling_off = parts['children'], parts['sibling']
        child_link = self._read_pointer(layer_name, init_task + children_off, pointer_size)
        if child_link is None:
            return CandidateField("pid_candidate", tuple(), "Could not follow child link"), CandidateField("tgid_candidate", tuple(), "Could not follow child link")
        child_task = child_link - sibling_off
        init_blob = self.context.layers[layer_name].read(init_task, max_scan_size, pad=True)
        child_blob = self.context.layers[layer_name].read(child_task, max_scan_size, pad=True)

        pid, tgid = [], []
        for off in range(0, max_scan_size - 4 + 1, 4):
            i = int.from_bytes(init_blob[off:off+4], "little", signed=False)
            c = int.from_bytes(child_blob[off:off+4], "little", signed=False)
            if i == 0 and 0 < c < 0x100000:
                pid.append(off)
                tgid.append(off)
        return CandidateField("pid_candidate", tuple(pid), "u32 offsets where init=0 and child>0"), CandidateField("tgid_candidate", tuple(tgid), "u32 offsets where init=0 and child>0")

    def _recover_initial_fields(self, module_name: str, init_task: int, max_scan_size: int) -> list[RecoveredField]:
        layer_name = self.context.modules[module_name].layer_name
        pointer_size = 8 if self.context.layers[layer_name].address_mask > 0xFFFFFFFF else 4
        comm = self._recover_comm_offset(layer_name, init_task, max_scan_size)
        parent = self._recover_parent_candidates(layer_name, init_task, max_scan_size, pointer_size)
        children = self._recover_children_candidates(layer_name, init_task, max_scan_size, pointer_size)
        relations = self._validate_relation_candidates(layer_name, init_task, max_scan_size, pointer_size, parent, children)
        pid, tgid = self._recover_id_candidates(layer_name, init_task, max_scan_size, pointer_size, relations)
        rows = [
            comm,
            RecoveredField(parent.name, parent.offsets[0] if parent.offsets else -1, f"candidate offsets: {', '.join(hex(o) for o in parent.offsets) if parent.offsets else 'none'}"),
            RecoveredField(children.name, children.offsets[0] if children.offsets else -1, f"candidate offsets: {', '.join(hex(o) for o in children.offsets) if children.offsets else 'none'}"),
            RecoveredField(pid.name, pid.offsets[0] if pid.offsets else -1, f"candidate offsets: {', '.join(hex(o) for o in pid.offsets) if pid.offsets else 'none'}; {pid.details}"),
            RecoveredField(tgid.name, tgid.offsets[0] if tgid.offsets else -1, f"candidate offsets: {', '.join(hex(o) for o in tgid.offsets) if tgid.offsets else 'none'}; {tgid.details}"),
        ]
        rows.extend(relations)
        return rows

    def _generator(self):
        for field in self._recover_initial_fields(self.config["kernel"], self._ensure_init_task(), int(self.config.get("max_scan_size", 0x1000))):
            yield (0, (field.name, "n/a" if field.offset < 0 else hex(field.offset), field.details))

    def run(self) -> renderers.TreeGrid:
        return renderers.TreeGrid([("Field", str), ("Offset", str), ("Details", str)], self._generator())


__all__ = ["LinuxSymbolRecovery"]
