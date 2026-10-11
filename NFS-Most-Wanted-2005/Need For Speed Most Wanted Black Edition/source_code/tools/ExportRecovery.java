// Export local analysis evidence without changing program bytes.
// @category Recovery
import ghidra.app.util.headless.HeadlessScript;
import ghidra.app.decompiler.*;
import ghidra.framework.Application;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataTypeWriter;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import com.google.gson.GsonBuilder;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.Instant;
import java.util.*;

public class ExportRecovery extends HeadlessScript {
    private Path output;

    private BufferedWriter writer(String name) throws IOException {
        return Files.newBufferedWriter(output.resolve(name), StandardCharsets.UTF_8);
    }

    private String cell(Object value) {
        return String.valueOf(value).replace("\t", " ").replace("\r", " ").replace("\n", "\\n");
    }

    private void row(BufferedWriter writer, Object... values) throws IOException {
        for (int i = 0; i < values.length; i++) {
            if (i != 0) writer.write('\t');
            writer.write(cell(values[i]));
        }
        writer.newLine();
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) throw new IllegalArgumentException("Expected output directory");
        output = Paths.get(args[0]).toAbsolutePath().resolve(currentProgram.getName());
        Files.createDirectories(output.resolve("functions"));
        // A missing summary means the export did not finish. Never retain a stale success marker.
        Files.deleteIfExists(output.resolve("summary.json"));
        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("started_utc", Instant.now().toString());
        summary.put("program", currentProgram.getName());
        summary.put("binary_sha256", currentProgram.getExecutableSHA256());
        summary.put("ghidra_version", Application.getApplicationVersion());
        summary.put("language", currentProgram.getLanguageID().toString());
        summary.put("compiler_spec", currentProgram.getCompilerSpec().getCompilerSpecID().toString());
        summary.put("image_base", currentProgram.getImageBase().toString());
        summary.put("analysis_enabled_this_run", isHeadlessAnalysisEnabled());
        summary.put("analysis_timed_out_this_run", analysisTimeoutOccurred());
        summary.put("status", "automated_static_analysis_not_original_source");
        summary.put("limitation", "Decompiler success and byte coverage do not establish correctness, complete discovery, compilability, or a working port.");

        AddressSet executable = new AddressSet();
        try (BufferedWriter blocks = writer("memory_map.tsv")) {
            row(blocks, "name", "start", "end_inclusive", "size", "read", "write", "execute", "initialized");
            for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
                row(blocks, block.getName(), block.getStart(), block.getEnd(), block.getSize(), block.isRead(), block.isWrite(), block.isExecute(), block.isInitialized());
                if (block.isExecute()) executable.add(block.getStart(), block.getEnd());
            }
        }
        try (BufferedWriter symbols = writer("symbols.tsv")) {
            row(symbols, "address", "name", "type", "source", "namespace");
            SymbolIterator iterator = currentProgram.getSymbolTable().getAllSymbols(true);
            while (iterator.hasNext()) {
                monitor.checkCancelled();
                Symbol symbol = iterator.next();
                row(symbols, symbol.getAddress(), symbol.getName(), symbol.getSymbolType(), symbol.getSource(), symbol.getParentNamespace().getName(true));
            }
        }
        try (BufferedWriter data = writer("defined_data.tsv")) {
            row(data, "address", "bytes", "data_type", "representation");
            DataIterator iterator = currentProgram.getListing().getDefinedData(true);
            while (iterator.hasNext()) {
                monitor.checkCancelled();
                Data item = iterator.next();
                row(data, item.getAddress(), item.getLength(), item.getDataType().getPathName(), item.getDefaultValueRepresentation());
            }
        }
        try (BufferedWriter types = writer("inferred_types.h")) {
            types.write("/* Ghidra inferred/library types. Not the original headers or a portable ABI. */\n");
            new DataTypeWriter(currentProgram.getDataTypeManager(), types).write(currentProgram.getDataTypeManager(), monitor);
        }

        long instructionCount = 0;
        long indirectCount = 0;
        AddressSet instructionBytes = new AddressSet();
        try (BufferedWriter assembly = writer("disassembly.tsv");
             BufferedWriter calls = writer("control_flow.tsv");
             BufferedWriter indirect = writer("indirect_flow.tsv")) {
            row(assembly, "address", "bytes_hex", "instruction", "containing_function");
            row(calls, "from", "to", "reference_type", "source");
            row(indirect, "address", "instruction", "flow_type", "containing_function");
            InstructionIterator iterator = currentProgram.getListing().getInstructions(true);
            while (iterator.hasNext()) {
                monitor.checkCancelled();
                Instruction item = iterator.next();
                Function function = currentProgram.getFunctionManager().getFunctionContaining(item.getAddress());
                String owner = function == null ? "" : function.getEntryPoint().toString();
                row(assembly, item.getAddress(), HexFormat.of().formatHex(item.getBytes()), item, owner);
                instructionCount++;
                instructionBytes.add(item.getMinAddress(), item.getMaxAddress());
                if (item.getFlowType().isComputed()) {
                    indirectCount++;
                    row(indirect, item.getAddress(), item, item.getFlowType(), owner);
                }
                for (Reference reference : item.getReferencesFrom()) {
                    if (reference.getReferenceType().isFlow()) {
                        row(calls, reference.getFromAddress(), reference.getToAddress(), reference.getReferenceType(), reference.getSource());
                    }
                }
            }
        }
        AddressSet gaps = executable.subtract(instructionBytes);
        try (BufferedWriter gapFile = writer("executable_noninstruction_ranges.tsv")) {
            row(gapFile, "start", "end_inclusive", "bytes");
            for (AddressRange range : gaps.getAddressRanges()) {
                row(gapFile, range.getMinAddress(), range.getMaxAddress(), range.getLength());
            }
        }
        summary.put("instructions", instructionCount);
        summary.put("executable_memory_bytes", executable.getNumAddresses());
        summary.put("executable_instruction_bytes", executable.intersect(instructionBytes).getNumAddresses());
        summary.put("executable_bytes_without_instruction", gaps.getNumAddresses());
        summary.put("noninstruction_note", "Ranges may contain data, padding, jump tables, or undiscovered code; not a count of missing source.");
        summary.put("indirect_flow_sites", indirectCount);

        DecompInterface decompiler = new DecompInterface();
        DecompileOptions options = new DecompileOptions();
        options.grabFromProgram(currentProgram);
        decompiler.setOptions(options);
        decompiler.toggleCCode(true);
        decompiler.toggleSyntaxTree(false);
        if (!decompiler.openProgram(currentProgram)) throw new IOException(decompiler.getLastMessage());
        int count = 0, successful = 0, failed = 0, warningFunctions = 0;
        String disclaimer = "/* AUTO-DECOMPILED RECONSTRUCTION: inferred names, types and control flow.\n" +
            " * Not original source. Not validated as buildable or behaviorally equivalent.\n" +
            " * Resolve ABI, globals, indirect calls and warnings against the binary.\n */\n";
        try (BufferedWriter index = writer("functions.tsv");
             BufferedWriter combined = writer("all_functions.c")) {
            row(index, "address", "name", "body_bytes", "signature", "thunk", "status", "diagnostic", "file");
            combined.write(disclaimer);
            FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true);
            while (iterator.hasNext()) {
                monitor.checkCancelled();
                Function function = iterator.next();
                if (function.isExternal()) continue;
                String address = function.getEntryPoint().toString();
                String file = "functions/" + address.replace(':', '_') + ".c";
                DecompileResults result = decompiler.decompileFunction(function, 60, monitor);
                boolean ok = result.decompileCompleted() && result.getDecompiledFunction() != null;
                String diagnostic = result.getErrorMessage();
                String c = ok ? result.getDecompiledFunction().getC() : "/* DECOMPILATION FAILED: " + cell(diagnostic).replace("*/", "* /") + " */\n";
                if (ok) successful++; else failed++;
                if (c.contains("WARNING:") || (diagnostic != null && !diagnostic.isBlank())) warningFunctions++;
                String heading = "\n/* Address: " + address + " | " + cell(function.getName()).replace("*/", "* /") + " */\n";
                Files.writeString(output.resolve(file), disclaimer + heading + c, StandardCharsets.UTF_8);
                combined.write(heading);
                combined.write(c);
                combined.newLine();
                row(index, address, function.getName(), function.getBody().getNumAddresses(), function.getSignature(), function.isThunk(), ok ? "decompiled_unverified" : "failed", diagnostic, file);
                count++;
                if (count % 250 == 0) {
                    index.flush();
                    combined.flush();
                    println("RECOVERY_PROGRESS " + currentProgram.getName() + " " + count + " functions, " + failed + " failures");
                }
            }
        } finally {
            decompiler.dispose();
        }
        summary.put("functions_attempted", count);
        summary.put("functions_decompiled", successful);
        summary.put("functions_failed", failed);
        summary.put("functions_with_warnings_or_diagnostics", warningFunctions);
        summary.put("finished_utc", Instant.now().toString());
        Files.writeString(output.resolve("summary.json"), new GsonBuilder().setPrettyPrinting().create().toJson(summary) + "\n", StandardCharsets.UTF_8);
        println("RECOVERY_COMPLETE " + currentProgram.getName() + " " + count + " functions, " + failed + " failures");
    }
}
