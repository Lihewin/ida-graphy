"""Ghidra fallback exporter for functions Hex-Rays cannot decompile."""

import logging
import os
import shutil
import subprocess
import tempfile
from typing import Dict, List

from core.models import GraphData, GhidraFallbackItem

from .artifact_utils import artifact_record, sanitize_filename

logger = logging.getLogger(__name__)


def export_ghidra_fallbacks(
    config: Dict,
    output_dir: str,
    binary_path: str,
    graph_data: GraphData,
) -> List[Dict[str, str]]:
    """Run Ghidra only for queued fallback functions and return artifact rows."""
    if not graph_data.ghidra_fallbacks:
        return []

    binary_name = os.path.basename(binary_path)
    queue = [item for item in graph_data.ghidra_fallbacks if item.binary_name == binary_name]
    if not queue:
        return []

    analyze_headless = _resolve_analyze_headless(config)
    if not analyze_headless:
        raise RuntimeError("Ghidra fallback required but analyzeHeadless was not found")

    export_dir = os.path.join(output_dir, "exports", binary_name, "ghidra_decompile")
    os.makedirs(export_dir, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="ghidra_fallback_") as tmp_dir:
        queue_path = os.path.join(tmp_dir, "queue.tsv")
        script_path = os.path.join(tmp_dir, "ExportQueuedFunctions.java")
        project_dir = os.path.join(tmp_dir, "project")
        os.makedirs(project_dir, exist_ok=True)

        _write_queue(queue_path, queue)
        _write_ghidra_script(script_path)

        cmd = [
            analyze_headless,
            project_dir,
            "ida_graphy_fallback",
            "-import",
            binary_path,
            "-scriptPath",
            tmp_dir,
            "-postScript",
            os.path.basename(script_path),
            queue_path,
            export_dir,
            "-deleteProject",
        ]
        logger.info("Running Ghidra fallback for %s queued functions in %s", len(queue), binary_name)
        proc = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        log_path = os.path.join(export_dir, "_ghidra_fallback.log")
        with open(log_path, "w", encoding="utf-8", errors="replace") as f:
            f.write(proc.stdout or "")
        if proc.returncode != 0:
            raise RuntimeError(
                "Ghidra fallback failed for "
                f"{binary_name} with exit code {proc.returncode}:\n{proc.stdout[-4000:]}"
            )

    artifacts: List[Dict[str, str]] = []
    for item in queue:
        filename = f"{item.function_uid}_{sanitize_filename(item.name)}.c"
        filepath = os.path.join(export_dir, filename)
        if not os.path.exists(filepath):
            artifacts.append(
                artifact_record(
                    output_dir,
                    owner_id=item.function_uid,
                    owner_type="Function",
                    artifact_type="ghidra_decompile",
                    filepath=filepath,
                    status="failed",
                    error="Ghidra did not produce output",
                )
            )
            continue
        artifacts.append(
            artifact_record(
                output_dir,
                owner_id=item.function_uid,
                owner_type="Function",
                artifact_type="ghidra_decompile",
                filepath=filepath,
                status="exported",
                error=item.error,
            )
        )

    return artifacts


def _resolve_analyze_headless(config: Dict) -> str:
    ghidra_cfg = _ghidra_fallback_config(config)
    configured = ghidra_cfg.get("analyze_headless") or ghidra_cfg.get("analyzeHeadless")
    if configured and os.path.exists(configured):
        return configured

    ghidra_home = ghidra_cfg.get("path") or os.environ.get("GHIDRA_HOME") or "/opt/ghidra"
    candidate = os.path.join(ghidra_home, "support", "analyzeHeadless")
    if os.path.exists(candidate):
        return candidate

    return shutil.which("analyzeHeadless") or ""


def _ghidra_fallback_config(config: Dict) -> Dict:
    """Return new export-scoped Ghidra fallback config, with legacy fallback."""
    if not config:
        return {}

    export_cfg = config.get("export", {})
    fallback_cfg = export_cfg.get("ghidra_fallback", {})
    if fallback_cfg:
        return fallback_cfg

    return config.get("ghidra", {})


def _write_queue(path: str, queue: List[GhidraFallbackItem]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for item in queue:
            f.write(
                "\t".join(
                    [
                        item.function_uid,
                        str(int(item.rva)),
                        item.name,
                        item.reason,
                        item.error,
                    ]
                )
                + "\n"
            )


def _write_ghidra_script(path: str) -> None:
    script = r'''
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

public class ExportQueuedFunctions extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        String queuePath = args[0];
        String exportDir = args[1];
        File outDir = new File(exportDir);
        outDir.mkdirs();

        DecompInterface ifc = new DecompInterface();
        ifc.openProgram(currentProgram);
        Address base = currentProgram.getImageBase();

        try (BufferedReader reader = new BufferedReader(new FileReader(queuePath))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split("\t", -1);
                if (parts.length < 5) {
                    continue;
                }
                String uid = parts[0];
                long rva = Long.parseLong(parts[1]);
                String name = parts[2];
                String reason = parts[3];
                String error = parts[4];
                File outFile = new File(outDir, uid + "_" + sanitize(name) + ".c");

                Address addr = base.add(rva);
                Function func = getFunctionAt(addr);
                if (func == null) {
                    func = getFunctionContaining(addr);
                }
                if (func == null) {
                    func = findFunctionByName(name);
                }
                if (func == null) {
                    writeFile(new File(outFile.getAbsolutePath() + ".failed"), "Ghidra function not found at RVA 0x" + Long.toHexString(rva) + "\n");
                    continue;
                }

                DecompileResults result = ifc.decompileFunction(func, 0, monitor);
                if (result == null || !result.decompileCompleted()) {
                    String message = result == null ? "decompile returned null" : result.getErrorMessage();
                    writeFile(new File(outFile.getAbsolutePath() + ".failed"), message == null ? "" : message);
                    continue;
                }

                StringBuilder text = new StringBuilder();
                text.append("/*\n");
                text.append(" * Source: Ghidra fallback\n");
                text.append(" * Reason: ").append(reason).append("\n");
                text.append(" * Hex-Rays error: ").append(error).append("\n");
                text.append(" */\n\n");
                text.append(result.getDecompiledFunction().getC());
                writeFile(outFile, text.toString());
            }
        }
    }

    private Function findFunctionByName(String name) {
        FunctionIterator funcs = currentProgram.getFunctionManager().getFunctions(true);
        while (funcs.hasNext()) {
            Function func = funcs.next();
            if (func.getName().equals(name)) {
                return func;
            }
        }
        return null;
    }

    private void writeFile(File file, String text) throws Exception {
        try (FileWriter writer = new FileWriter(file)) {
            writer.write(text);
        }
    }

    private String sanitize(String name) {
        String text = name.replaceAll("[^A-Za-z0-9._-]", "_");
        if (text.length() == 0) {
            text = "function";
        }
        return text.length() > 100 ? text.substring(0, 100) : text;
    }
}
'''
    with open(path, "w", encoding="utf-8") as f:
        f.write(script)
