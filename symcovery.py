"""Experimental Volatility3 plugin for Linux task_struct symbol recovery."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, Optional, Sequence

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
    _version = (0, 5, 0)
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

    def _read_pointer(self, layer_name: str, address: int, pointer_size: int) -> Optional[int]:
        try:
            return int.from_bytes(self.context.layers[layer_name].read(address, pointer_size, pad=True), "little", signed=False)
        except exceptions.InvalidAddressException:
            return None

    def _read_u32(self, layer_name: str, address: int) -> Optional[int]:
        try:
            return int.from_bytes(self.context.layers[layer_name].read(address, 4, pad=True), "little", signed=False)
        except exceptions.InvalidAddressException:
            return None

    def _read_comm(self, layer_name: str, task_start: int, comm_offset: int, max_len: int = 16) -> str:
        try:
            data = self.context.layers[layer_name].read(task_start + comm_offset, max_len, pad=True)
        except exceptions.InvalidAddressException:
            return "<invalid>"
        raw = data.split(b"\x00", 1)[0]
        try:
            return raw.decode("ascii", errors="replace")
        except Exception:
            return "<decode-error>"

    def _looks_like_kernel_pointer(self, value: int) -> bool:
        return value >= 0xFFFF000000000000

    def _find_comm_signature_offset(self, data: bytes, signatures: Sequence[bytes]) -> tuple[int, bytes]:
        for signature in signatures:
            offset = data.find(signature)
            if offset >= 0:
                return offset, signature
        raise exceptions.VolatilityException("Unable to locate a supported init_task comm signature")

    def _iter_pointer_candidates(self, layer_name: str, init_task: int, max_scan_size: int, pointer_size: int) -> Iterable[tuple[int, int]]:
        blob = self.context.layers[layer_name].read(init_task, max_scan_size, pad=True)
        for off in range(0, max_scan_size - pointer_size + 1, pointer_size):
            yield off, int.from_bytes(blob[off : off + pointer_size], "little", signed=False)

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
            if any(int.from_bytes(around[i : i + pointer_size], "little", signed=False) == init_task for i in range(0, len(around) - pointer_size + 1, pointer_size)):
                candidates.append(off)
        return CandidateField("children_candidate", tuple(sorted(set(candidates))), "Candidates whose target neighborhood contains back-references to init_task")

    def _relation_tuples(
        self,
        layer_name: str,
        init_task: int,
        max_scan_size: int,
        pointer_size: int,
        parent: CandidateField,
        children: CandidateField,
    ) -> list[tuple[int, int, int]]:
        tuples: list[tuple[int, int, int]] = []
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
                    if self._read_pointer(layer_name, child_task + parent_off, pointer_size) == init_task:
                        tuples.append((children_off, sibling_off, parent_off))
        return sorted(set(tuples))

    def _walk_children_chain(
        self,
        layer_name: str,
        init_task: int,
        pointer_size: int,
        children_offset: int,
        sibling_offset: int,
        max_tasks: int = 256,
    ) -> list[int]:
        tasks: list[int] = []
        head = init_task + children_offset
        link = self._read_pointer(layer_name, head, pointer_size)
        seen_links: set[int] = set()

        while link is not None and link not in seen_links and link != head and len(tasks) < max_tasks:
            seen_links.add(link)
            task = link - sibling_offset
            if task <= 0:
                break
            tasks.append(task)
            link = self._read_pointer(layer_name, link, pointer_size)
        return tasks

    def _score_candidates_across_tasks(
        self,
        layer_name: str,
        init_task: int,
        max_scan_size: int,
        tasks: list[int],
    ) -> tuple[Dict[int, int], Dict[int, int]]:
        pid_scores: Dict[int, int] = {}
        tgid_scores: Dict[int, int] = {}
        all_tasks = [init_task] + tasks
        for off in range(0, max_scan_size - 4 + 1, 4):
            values = [self._read_u32(layer_name, task + off) for task in all_tasks]
            if any(v is None for v in values):
                continue
            vals = [v for v in values if v is not None]
            if vals[0] != 0:
                continue
            score = 0
            if len(vals) >= 2 and vals[1] == 1:
                score += 10
            if all(v < 0x100000 for v in vals):
                score += 3
            if len(set(vals)) > 1:
                score += 2
            if score > 0:
                pid_scores[off] = score
            # TGID: often equals PID for kernel threads, still score separately
            if score >= 3:
                tgid_scores[off] = score - 1
        return pid_scores, tgid_scores

    def _recover_initial_fields(self, module_name: str, init_task: int, max_scan_size: int) -> list[RecoveredField]:
        layer_name = self.context.modules[module_name].layer_name
        pointer_size = 8 if self.context.layers[layer_name].address_mask > 0xFFFFFFFF else 4

        comm = self._recover_comm_offset(layer_name, init_task, max_scan_size)
        parent = self._recover_parent_candidates(layer_name, init_task, max_scan_size, pointer_size)
        children = self._recover_children_candidates(layer_name, init_task, max_scan_size, pointer_size)

        relation_tuples = self._relation_tuples(layer_name, init_task, max_scan_size, pointer_size, parent, children)
        relation_rows = [
            RecoveredField(
                "children_sibling_parent_relation",
                c,
                f"children=0x{c:x}, sibling=0x{s:x}, parent-like=0x{p:x} validates child relation",
            )
            for c, s, p in relation_tuples
        ]

        # scored selection: choose tuple that yields most tasks in children walk
        best_tuple: Optional[tuple[int, int, int]] = None
        best_tasks: list[int] = []
        for c, s, p in relation_tuples:
            walked = self._walk_children_chain(layer_name, init_task, pointer_size, c, s)
            if len(walked) > len(best_tasks):
                best_tasks = walked
                best_tuple = (c, s, p)

        pid_scores: Dict[int, int] = {}
        tgid_scores: Dict[int, int] = {}
        if best_tuple is not None:
            pid_scores, tgid_scores = self._score_candidates_across_tasks(layer_name, init_task, max_scan_size, best_tasks)

        pid_sorted = tuple(sorted(pid_scores, key=lambda x: pid_scores[x], reverse=True))
        tgid_sorted = tuple(sorted(tgid_scores, key=lambda x: tgid_scores[x], reverse=True))

        rows = [
            comm,
            RecoveredField(parent.name, parent.offsets[0] if parent.offsets else -1, f"candidate offsets: {', '.join(hex(o) for o in parent.offsets) if parent.offsets else 'none'}"),
            RecoveredField(children.name, children.offsets[0] if children.offsets else -1, f"candidate offsets: {', '.join(hex(o) for o in children.offsets) if children.offsets else 'none'}"),
            RecoveredField(
                "selected_relation",
                best_tuple[0] if best_tuple else -1,
                (
                    f"selected by max walked tasks: children=0x{best_tuple[0]:x}, sibling=0x{best_tuple[1]:x}, parent-like=0x{best_tuple[2]:x}, walked={len(best_tasks)}"
                    if best_tuple else "no validated relation tuple"
                ),
            ),
            RecoveredField(
                "pid_candidate",
                pid_sorted[0] if pid_sorted else -1,
                (
                    "scored offsets: " + ", ".join(f"0x{o:x}(score={pid_scores[o]})" for o in pid_sorted)
                    if pid_sorted else "scored offsets: none"
                ),
            ),
            RecoveredField(
                "tgid_candidate",
                tgid_sorted[0] if tgid_sorted else -1,
                (
                    "scored offsets: " + ", ".join(f"0x{o:x}(score={tgid_scores[o]})" for o in tgid_sorted)
                    if tgid_sorted else "scored offsets: none"
                ),
            ),
        ]

        for idx, task in enumerate(best_tasks):
            name = self._read_comm(layer_name, task, comm.offset)
            pid_val = self._read_u32(layer_name, task + (pid_sorted[0] if pid_sorted else 0)) if pid_sorted else None
            rows.append(
                RecoveredField(
                    "task_debug",
                    task,
                    f"index={idx} task=0x{task:x} comm={name} pid_guess={pid_val if pid_val is not None else 'n/a'}",
                )
            )

        rows.extend(relation_rows)
        return rows

    def _generator(self):
        for field in self._recover_initial_fields(self.config["kernel"], self._ensure_init_task(), int(self.config.get("max_scan_size", 0x1000))):
            yield (0, (field.name, "n/a" if field.offset < 0 else hex(field.offset), field.details))

    def run(self) -> renderers.TreeGrid:
        return renderers.TreeGrid([("Field", str), ("Offset", str), ("Details", str)], self._generator())


__all__ = ["LinuxSymbolRecovery"]
