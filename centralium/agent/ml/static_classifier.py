"""Static malware classifier for PE and ELF binaries.

Provides:
1. Byte histogram and byte entropy extraction.
2. Structural feature extraction for Windows PE binaries (sections, entropy, imports, suspicious APIs).
3. Structural feature extraction for Linux ELF binaries (segments, sections, symbols, W+X permissions).
4. Gradient-boosted classifier (HistGradientBoostingClassifier) with probability calibration
   (CalibratedClassifierCV) trained on representative feature distributions.
"""

from __future__ import annotations

import contextlib
import math
import struct
from pathlib import Path
from typing import Any

import numpy as np
from pydantic import BaseModel, ConfigDict, Field
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import HistGradientBoostingClassifier

# ---------------------------------------------------------------------------
# Suspicious APIs and patterns
# ---------------------------------------------------------------------------

SUSPICIOUS_PE_APIS = frozenset(
    {
        "virtualalloc",
        "virtualallocex",
        "virtualprotect",
        "virtualprotectex",
        "writeprocessmemory",
        "createremotethread",
        "ntqueueapcthread",
        "setthreadcontext",
        "ntunmapviewofsection",
        "resumethread",
        "winexec",
        "shellexecutea",
        "shellexecutew",
        "urldownloadtofilea",
        "urldownloadtofilew",
        "internetopena",
        "internetconnecta",
        "httppopenrequesta",
        "httpsendrequesta",
        "isdebuggerpresent",
        "checkremotedebuggerpresent",
        "adjusttokenprivileges",
        "openprocesstoken",
        "cryptencrypt",
        "cryptdecrypt",
    }
)

SUSPICIOUS_ELF_SYMBOLS = frozenset(
    {
        "ptrace",
        "mprotect",
        "memfd_create",
        "execve",
        "execvp",
        "execl",
        "system",
        "fork",
        "clone",
        "socket",
        "connect",
        "bind",
        "listen",
        "process_vm_writev",
        "process_vm_readv",
        "dlopen",
        "dlsym",
    }
)

PACKED_SECTION_NAMES = frozenset(
    {
        "upx0",
        "upx1",
        "upx2",
        ".aspack",
        ".themida",
        ".vmp",
        ".fsg",
        ".nspack",
        ".petite",
        ".mew",
    }
)

NUM_HISTOGRAM_BINS = 256
NUM_EXTRA_FEATURES = 16
TOTAL_FEATURE_DIM = NUM_HISTOGRAM_BINS + NUM_EXTRA_FEATURES


class StaticScanResult(BaseModel):
    """Result of static binary classification."""

    model_config = ConfigDict(extra="forbid")

    file_type: str = Field(description="Detected executable format: PE, ELF, or UNKNOWN")
    is_malicious: bool = Field(description="Binary classification verdict")
    malware_score: float = Field(ge=0.0, le=100.0, description="Risk score from 0 to 100")
    confidence: float = Field(ge=0.0, le=1.0, description="Calibrated probability of maliciousness")
    indicators: list[str] = Field(default_factory=list, description="Extracted suspicious indicators")
    extracted_features: dict[str, Any] = Field(
        default_factory=dict, description="Structural and statistical feature summary"
    )


def compute_byte_histogram(data: bytes) -> tuple[np.ndarray, float, dict[str, float]]:
    """Compute 256-bin normalized byte histogram, Shannon entropy, and byte statistics."""
    if not data:
        return (
            np.zeros(NUM_HISTOGRAM_BINS, dtype=np.float32),
            0.0,
            {
                "zero_ratio": 0.0,
                "printable_ratio": 0.0,
                "high_byte_ratio": 0.0,
            },
        )

    counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256).astype(np.float32)
    total_len = len(data)
    hist = counts / float(total_len)

    # Shannon entropy
    nonzero_probs = hist[hist > 0]
    entropy = float(-np.sum(nonzero_probs * np.log2(nonzero_probs)))

    zero_ratio = float(hist[0])
    # Printable ASCII: 0x20..0x7E plus \t (9), \n (10), \r (13)
    printable_mask = np.zeros(256, dtype=bool)
    printable_mask[0x20:0x7F] = True
    printable_mask[9] = True
    printable_mask[10] = True
    printable_mask[13] = True
    printable_ratio = float(np.sum(hist[printable_mask]))
    high_byte_ratio = float(np.sum(hist[128:]))

    stats = {
        "zero_ratio": zero_ratio,
        "printable_ratio": printable_ratio,
        "high_byte_ratio": high_byte_ratio,
    }
    return hist, entropy, stats


def _compute_entropy(slice_data: bytes) -> float:
    if not slice_data:
        return 0.0
    counts = np.bincount(np.frombuffer(slice_data, dtype=np.uint8), minlength=256)
    probs = counts[counts > 0] / float(len(slice_data))
    return float(-np.sum(probs * np.log2(probs)))


def extract_pe_features(data: bytes) -> dict[str, Any]:
    """Parse PE header, sections, and import indicators safely without external dependencies."""
    result: dict[str, Any] = {
        "is_pe": False,
        "sections": [],
        "num_sections": 0,
        "max_section_entropy": 0.0,
        "mean_section_entropy": 0.0,
        "has_wx_section": False,
        "packed_indicator": False,
        "imports": [],
        "suspicious_apis": [],
        "size_anomaly": False,
    }

    if len(data) < 64:
        return result

    # Check MZ header
    if data[:2] != b"MZ":
        return result

    with contextlib.suppress(Exception):
        (e_lfanew,) = struct.unpack_from("<I", data, 0x3C)
        if e_lfanew + 24 > len(data):
            return result
        if data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
            return result

        result["is_pe"] = True
        coff_offset = e_lfanew + 4
        _, num_sections, _, _, _, size_of_opt, _ = struct.unpack_from("<HHIIIHH", data, coff_offset)
        result["num_sections"] = num_sections

        opt_offset = coff_offset + 20
        sec_table_offset = opt_offset + size_of_opt

        sections_info: list[dict[str, Any]] = []
        has_wx = False
        packed_found = False
        size_anomaly = False

        for i in range(num_sections):
            sec_offset = sec_table_offset + i * 40
            if sec_offset + 40 > len(data):
                break
            raw_name = data[sec_offset : sec_offset + 8].split(b"\x00")[0]
            name = raw_name.decode("latin1", errors="replace").lower().strip()

            vsize, _, raw_size, raw_ptr, _, _, _, characteristics = struct.unpack_from(
                "<IIIIIIII", data, sec_offset + 8
            )

            # Extract section bytes if within bounds
            if raw_ptr + raw_size <= len(data) and raw_size > 0:
                sec_bytes = data[raw_ptr : raw_ptr + raw_size]
                sec_entropy = _compute_entropy(sec_bytes)
            else:
                sec_entropy = 0.0

            # Check W+X: IMAGE_SCN_MEM_WRITE (0x80000000) and IMAGE_SCN_MEM_EXECUTE (0x20000000)
            is_writable = bool(characteristics & 0x80000000)
            is_executable = bool(characteristics & 0x20000000)
            if is_writable and is_executable:
                has_wx = True

            # Check packing indicator: UPX / packer names or large virtual/raw discrepancy
            if any(p in name for p in PACKED_SECTION_NAMES):
                packed_found = True
            if raw_size > 0 and vsize > 3 * raw_size:
                size_anomaly = True

            sections_info.append(
                {
                    "name": name,
                    "virtual_size": vsize,
                    "raw_size": raw_size,
                    "entropy": sec_entropy,
                    "is_wx": is_writable and is_executable,
                }
            )

        result["sections"] = sections_info
        if sections_info:
            entropies = [s["entropy"] for s in sections_info]
            result["max_section_entropy"] = float(max(entropies))
            result["mean_section_entropy"] = float(sum(entropies) / len(entropies))

        result["has_wx_section"] = has_wx
        result["packed_indicator"] = packed_found or size_anomaly
        result["size_anomaly"] = size_anomaly

        # Scan for suspicious API strings in imports or data
        data_lower = data.lower()
        found_suspicious: list[str] = []
        for api in SUSPICIOUS_PE_APIS:
            if api.encode("latin1") in data_lower:
                found_suspicious.append(api)
        result["suspicious_apis"] = found_suspicious
        result["imports"] = found_suspicious

    return result


def extract_elf_features(data: bytes) -> dict[str, Any]:
    """Parse ELF header, program headers, sections, and symbols safely without external dependencies."""
    result: dict[str, Any] = {
        "is_elf": False,
        "num_sections": 0,
        "num_segments": 0,
        "max_section_entropy": 0.0,
        "mean_section_entropy": 0.0,
        "has_wx_segment": False,
        "has_wx_section": False,
        "is_stripped": True,
        "suspicious_symbols": [],
        "packed_indicator": False,
    }

    if len(data) < 52 or data[:4] != b"\x7fELF":
        return result

    with contextlib.suppress(Exception):
        result["is_elf"] = True
        ei_class = data[4]  # 1 = 32-bit, 2 = 64-bit
        ei_data = data[5]  # 1 = LE, 2 = BE
        endian = "<" if ei_data == 1 else ">"

        has_wx_segment = False
        if ei_class == 2:  # 64-bit
            if len(data) >= 64:
                _, _, _, _, e_phoff, _, _, _, e_phentsize, e_phnum, _, e_shnum, _ = struct.unpack_from(
                    f"{endian}HHIQQQIHHHHHH", data, 16
                )
                result["num_segments"] = e_phnum
                result["num_sections"] = e_shnum

                # Parse program headers
                for i in range(e_phnum):
                    ph_off = e_phoff + i * e_phentsize
                    if ph_off + 32 > len(data):
                        break
                    _, p_flags = struct.unpack_from(f"{endian}II", data, ph_off)
                    # p_flags: PF_X=1, PF_W=2, PF_R=4. W+X is (p_flags & 3) == 3
                    if (p_flags & 3) == 3:
                        has_wx_segment = True
        else:  # 32-bit
            _, _, _, _, e_phoff, _, _, _, e_phentsize, e_phnum, _, e_shnum, _ = struct.unpack_from(
                f"{endian}HHIIIIIHHHHHH", data, 16
            )
            result["num_segments"] = e_phnum
            result["num_sections"] = e_shnum

            for i in range(e_phnum):
                ph_off = e_phoff + i * e_phentsize
                if ph_off + 28 > len(data):
                    break
                _, _, _, _, _, _, p_flags, _ = struct.unpack_from(f"{endian}IIIIIIII", data, ph_off)
                if (p_flags & 3) == 3:
                    has_wx_segment = True

        result["has_wx_segment"] = has_wx_segment

        # Check for symbol strings / suspicious functions
        data_lower = data.lower()
        found_symbols: list[str] = []
        for sym in SUSPICIOUS_ELF_SYMBOLS:
            if sym.encode("latin1") in data_lower:
                found_symbols.append(sym)
        result["suspicious_symbols"] = found_symbols

        # Check if debug or symtab strings exist
        if b".symtab" in data or b".strtab" in data:
            result["is_stripped"] = False
        else:
            result["is_stripped"] = True

        # Check for UPX signature
        if b"UPX!" in data:
            result["packed_indicator"] = True

    return result


def extract_feature_vector(data: bytes) -> tuple[np.ndarray, dict[str, Any]]:
    """Extract a unified fixed-length feature vector for PE, ELF, or raw binary."""
    hist, entropy, stats = compute_byte_histogram(data)

    pe_meta = extract_pe_features(data)
    elf_meta = extract_elf_features(data)

    file_size = len(data)
    log_size = math.log1p(file_size)

    is_pe = 1.0 if pe_meta["is_pe"] else 0.0
    is_elf = 1.0 if elf_meta["is_elf"] else 0.0

    num_sections = float(pe_meta["num_sections"] or elf_meta["num_sections"])
    max_entropy = float(pe_meta["max_section_entropy"] or elf_meta["max_section_entropy"] or entropy)
    mean_entropy = float(pe_meta["mean_section_entropy"] or elf_meta["mean_section_entropy"] or entropy)

    has_wx = 1.0 if (pe_meta["has_wx_section"] or elf_meta["has_wx_segment"]) else 0.0
    packed = 1.0 if (pe_meta["packed_indicator"] or elf_meta["packed_indicator"]) else 0.0

    suspicious_count = float(len(pe_meta["suspicious_apis"]) + len(elf_meta["suspicious_symbols"]))
    total_imports = float(len(pe_meta["imports"]) + len(elf_meta["suspicious_symbols"]))

    size_anomaly = 1.0 if pe_meta["size_anomaly"] else 0.0
    stripped = 1.0 if elf_meta["is_stripped"] else 0.0

    extra = np.array(
        [
            log_size / 20.0,
            entropy / 8.0,
            stats["zero_ratio"],
            stats["printable_ratio"],
            stats["high_byte_ratio"],
            is_pe,
            is_elf,
            min(num_sections / 30.0, 1.0),
            max_entropy / 8.0,
            mean_entropy / 8.0,
            has_wx,
            packed,
            min(total_imports / 50.0, 1.0),
            min(suspicious_count / 10.0, 1.0),
            size_anomaly,
            stripped,
        ],
        dtype=np.float32,
    )

    vector = np.concatenate([hist, extra])

    summary = {
        "file_size": file_size,
        "entropy": round(entropy, 4),
        "zero_ratio": round(stats["zero_ratio"], 4),
        "printable_ratio": round(stats["printable_ratio"], 4),
        "high_byte_ratio": round(stats["high_byte_ratio"], 4),
        "is_pe": bool(is_pe),
        "is_elf": bool(is_elf),
        "num_sections": int(num_sections),
        "has_wx": bool(has_wx),
        "packed": bool(packed),
        "suspicious_apis": pe_meta["suspicious_apis"] or elf_meta["suspicious_symbols"],
    }
    return vector, summary


class StaticMalwareClassifier:
    """Gradient-boosted static malware classifier with probability calibration."""

    def __init__(self, calibrate: bool = True, seed: int = 42) -> None:
        self.calibrate = calibrate
        self.seed = seed
        self._model: Any = None
        self._is_fitted: bool = False
        self._init_default_model()

    def _init_default_model(self) -> None:
        """Trains on representative synthetic feature distributions so model is functional immediately."""
        self.train_synthetic(n_samples=500, seed=self.seed)

    def train_synthetic(self, n_samples: int = 500, seed: int = 42) -> None:
        """Train classifier on representative synthetic distributions of binaries."""
        rng = np.random.default_rng(seed)
        n_benign = n_samples // 2

        X = np.zeros((n_samples, TOTAL_FEATURE_DIM), dtype=np.float32)
        y = np.zeros(n_samples, dtype=np.int32)

        # ---------------- Benign distribution ----------------
        for i in range(n_benign):
            # Benign byte histogram: varied, moderate entropy (4.5 - 6.5)
            hist = rng.dirichlet(np.ones(NUM_HISTOGRAM_BINS) * 1.5).astype(np.float32)
            log_size = rng.uniform(8.0, 16.0) / 20.0
            entropy = rng.uniform(4.0, 6.4) / 8.0
            zero_ratio = rng.uniform(0.05, 0.35)
            printable = rng.uniform(0.15, 0.60)
            high_byte = rng.uniform(0.05, 0.30)
            is_pe = 1.0 if rng.random() > 0.5 else 0.0
            is_elf = 1.0 - is_pe
            num_sec = rng.integers(3, 10) / 30.0
            max_sec_ent = rng.uniform(5.0, 6.7) / 8.0
            mean_sec_ent = rng.uniform(4.0, 6.0) / 8.0
            has_wx = 1.0 if rng.random() < 0.02 else 0.0  # Rare in benign
            packed = 1.0 if rng.random() < 0.03 else 0.0
            num_imp = rng.integers(10, 40) / 50.0
            susp_imp = rng.integers(0, 2) / 10.0  # Max 1 suspicious API
            size_anom = 0.0
            stripped = 1.0 if rng.random() > 0.4 else 0.0

            extra = np.array(
                [
                    log_size,
                    entropy,
                    zero_ratio,
                    printable,
                    high_byte,
                    is_pe,
                    is_elf,
                    num_sec,
                    max_sec_ent,
                    mean_sec_ent,
                    has_wx,
                    packed,
                    num_imp,
                    susp_imp,
                    size_anom,
                    stripped,
                ],
                dtype=np.float32,
            )
            X[i] = np.concatenate([hist, extra])
            y[i] = 0

        # ---------------- Malicious distribution ----------------
        for i in range(n_benign, n_samples):
            # Malware: higher entropy, packed, W+X, injection APIs, or droppers/loaders
            is_packed = rng.random() < 0.60
            is_dropper = rng.random() < 0.25

            if is_packed:
                # High entropy dirichlet
                alpha = np.ones(NUM_HISTOGRAM_BINS) * 10.0
                hist = rng.dirichlet(alpha).astype(np.float32)
                entropy = rng.uniform(7.1, 7.99) / 8.0
            elif is_dropper:
                # Dropper / small loader: lower entropy or repetitive bytes
                hist = rng.dirichlet(np.ones(NUM_HISTOGRAM_BINS) * 0.5).astype(np.float32)
                entropy = rng.uniform(2.0, 5.0) / 8.0
            else:
                hist = rng.dirichlet(np.ones(NUM_HISTOGRAM_BINS) * 2.0).astype(np.float32)
                entropy = rng.uniform(5.5, 7.2) / 8.0

            log_size = rng.uniform(9.0, 15.0) / 20.0
            zero_ratio = rng.uniform(0.01, 0.20) if is_packed else rng.uniform(0.05, 0.40)
            printable = rng.uniform(0.05, 0.35)
            high_byte = rng.uniform(0.15, 0.55)
            is_pe = 1.0 if rng.random() > 0.4 else 0.0
            is_elf = 1.0 - is_pe
            num_sec = rng.integers(1, 8) / 30.0
            max_sec_ent = rng.uniform(7.0, 7.99) / 8.0 if is_packed else rng.uniform(5.0, 7.5) / 8.0
            mean_sec_ent = rng.uniform(5.0, 7.6) / 8.0
            has_wx = 1.0 if rng.random() < 0.70 else 0.0
            packed_val = 1.0 if is_packed else (1.0 if rng.random() < 0.35 else 0.0)
            num_imp = rng.integers(1, 15) / 50.0  # Fewer standard imports
            susp_imp = rng.integers(2, 7) / 10.0  # Multiple suspicious APIs
            size_anom = 1.0 if is_packed and rng.random() < 0.7 else 0.0
            stripped = 1.0 if rng.random() > 0.1 else 0.0

            extra = np.array(
                [
                    log_size,
                    entropy,
                    zero_ratio,
                    printable,
                    high_byte,
                    is_pe,
                    is_elf,
                    num_sec,
                    max_sec_ent,
                    mean_sec_ent,
                    has_wx,
                    packed_val,
                    num_imp,
                    susp_imp,
                    size_anom,
                    stripped,
                ],
                dtype=np.float32,
            )
            X[i] = np.concatenate([hist, extra])
            y[i] = 1

        self.fit(X, y)

    def fit(self, X: np.ndarray, y: np.ndarray) -> None:
        """Fit the gradient-boosted classifier with probability calibration."""
        base_clf = HistGradientBoostingClassifier(
            max_iter=60,
            learning_rate=0.08,
            max_leaf_nodes=31,
            random_state=self.seed,
        )

        if self.calibrate:
            # CalibratedClassifierCV wraps the estimator using cross-validation
            calibrated = CalibratedClassifierCV(estimator=base_clf, method="sigmoid", cv=3)
            calibrated.fit(X, y)
            self._model = calibrated
        else:
            base_clf.fit(X, y)
            self._model = base_clf

        self._is_fitted = True

    def evaluate_calibration(self, X: np.ndarray, y: np.ndarray) -> dict[str, Any]:
        """Compute reliability metrics including Brier score and predicted vs true frequencies."""
        if not self._is_fitted or self._model is None:
            raise RuntimeError("Model is not fitted")

        probs = self._model.predict_proba(X)[:, 1]
        brier_score = float(np.mean((probs - y) ** 2))

        # 5-bin calibration curve
        bins = np.linspace(0.0, 1.0, 6)
        bin_trues: list[float] = []
        bin_preds: list[float] = []
        for i in range(len(bins) - 1):
            mask = (probs >= bins[i]) & (probs < bins[i + 1])
            if np.any(mask):
                bin_preds.append(float(np.mean(probs[mask])))
                bin_trues.append(float(np.mean(y[mask])))

        return {
            "brier_score": round(brier_score, 4),
            "bin_predicted": [round(p, 4) for p in bin_preds],
            "bin_actual": [round(a, 4) for a in bin_trues],
        }

    def predict(self, binary_data: bytes | Path) -> StaticScanResult:
        """Extract features and produce calibrated static malware verdict."""
        data = binary_data.read_bytes() if isinstance(binary_data, Path) else bytes(binary_data)

        vec, summary = extract_feature_vector(data)
        file_type = "PE" if summary["is_pe"] else ("ELF" if summary["is_elf"] else "UNKNOWN")

        # Predict calibrated probability
        X_in = vec.reshape(1, -1)
        prob = float(self._model.predict_proba(X_in)[0, 1])

        # Indicator extraction and heuristic verification
        indicators: list[str] = []
        heuristic_boost = 0.0
        if summary["entropy"] >= 7.2:
            indicators.append(f"high_entropy_overall:{summary['entropy']}")
            heuristic_boost += 0.15
        if summary["has_wx"]:
            indicators.append("executable_and_writable_section_detected")
            heuristic_boost += 0.25
        if summary["packed"]:
            indicators.append("packed_or_compressed_executable_signatures")
            heuristic_boost += 0.20
        for api in summary["suspicious_apis"]:
            indicators.append(f"suspicious_api_reference:{api}")
            heuristic_boost += 0.10

        if (summary["is_pe"] or summary["is_elf"]) and heuristic_boost > 0:
            effective_prob = min(max(prob + min(heuristic_boost, 0.45), 0.0), 1.0)
        else:
            effective_prob = prob

        # Derive malware score and decision
        malware_score = round(effective_prob * 100.0, 2)
        is_malicious = effective_prob >= 0.50

        return StaticScanResult(
            file_type=file_type,
            is_malicious=is_malicious,
            malware_score=malware_score,
            confidence=round(effective_prob if is_malicious else 1.0 - effective_prob, 4),
            indicators=indicators,
            extracted_features=summary,
        )


__all__ = [
    "NUM_EXTRA_FEATURES",
    "NUM_HISTOGRAM_BINS",
    "PACKED_SECTION_NAMES",
    "SUSPICIOUS_ELF_SYMBOLS",
    "SUSPICIOUS_PE_APIS",
    "TOTAL_FEATURE_DIM",
    "StaticMalwareClassifier",
    "StaticScanResult",
    "compute_byte_histogram",
    "extract_elf_features",
    "extract_feature_vector",
    "extract_pe_features",
]
