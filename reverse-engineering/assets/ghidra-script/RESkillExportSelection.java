// Bounded, read-only Ghidra selection export for the Reverse Engineering Skill.
// @category Reverse Engineering Skill

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;

public class RESkillExportSelection extends GhidraScript {
    private static final int MAX_BYTES = 4096;
    private static final int MAX_INSTRUCTIONS = 2000;

    private static String escape(String value) {
        if (value == null) return "";
        StringBuilder escaped = new StringBuilder();
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            switch (character) {
                case '\\': escaped.append("\\\\"); break;
                case '"': escaped.append("\\\""); break;
                case '\r': escaped.append("\\r"); break;
                case '\n': escaped.append("\\n"); break;
                case '\t': escaped.append("\\t"); break;
                case '\b': escaped.append("\\b"); break;
                case '\f': escaped.append("\\f"); break;
                default:
                    if (character < 0x20) {
                        escaped.append(String.format("\\u%04X", (int)character));
                    } else {
                        escaped.append(character);
                    }
            }
        }
        return escaped.toString();
    }

    private static String hex(byte[] data) {
        StringBuilder result = new StringBuilder();
        for (int index = 0; index < data.length; index++) {
            if (index > 0) result.append(' ');
            result.append(String.format("%02X", data[index] & 0xff));
        }
        return result.toString();
    }

    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            printerr("No current program.");
            return;
        }
        Address start;
        Address requestedEnd;
        AddressSetView selection = currentSelection;
        if (selection != null && !selection.isEmpty()) {
            start = selection.getMinAddress();
            requestedEnd = selection.getMaxAddress().add(1);
        } else if (currentAddress != null) {
            start = currentAddress;
            requestedEnd = start.add(64);
        } else {
            printerr("No address or selection.");
            return;
        }
        long requestedLength = requestedEnd.subtract(start);
        int length = (int)Math.min(MAX_BYTES, Math.max(0, requestedLength));
        byte[] bytes = new byte[length];
        currentProgram.getMemory().getBytes(start, bytes);
        Address end = start.add(length);
        AddressSet bounded = new AddressSet(start, end.subtract(1));
        List<String> instructionJson = new ArrayList<>();
        int count = 0;
        for (Instruction instruction : currentProgram.getListing().getInstructions(bounded, true)) {
            monitor.checkCancelled();
            if (count++ >= MAX_INSTRUCTIONS) break;
            instructionJson.add("{\"address\":\"" + instruction.getAddress() +
                "\",\"text\":\"" + escape(instruction.toString()) + "\"}");
        }
        Function function = currentProgram.getFunctionManager().getFunctionContaining(start);
        String functionName = function == null ? "" : function.getName();
        String pseudocode = "";
        String pseudocodeError = "";
        if (function != null) {
            DecompInterface decompiler = new DecompInterface();
            try {
                decompiler.openProgram(currentProgram);
                DecompileResults result = decompiler.decompileFunction(function, 30, monitor);
                if (result.decompileCompleted()) {
                    pseudocode = result.getDecompiledFunction().getC();
                } else {
                    pseudocodeError = result.getErrorMessage();
                }
            } finally {
                decompiler.dispose();
            }
        }
        String json = "{\n" +
            "  \"schema_version\": \"0.5.0\",\n" +
            "  \"host\": \"ghidra\",\n" +
            "  \"program\": \"" + escape(currentProgram.getName()) + "\",\n" +
            "  \"executable_path\": \"" + escape(currentProgram.getExecutablePath()) + "\",\n" +
            "  \"language\": \"" + escape(currentProgram.getLanguageID().toString()) + "\",\n" +
            "  \"selection\": {\"start\": \"" + start + "\", \"end_exclusive\": \"" + end +
            "\", \"requested_length\": " + requestedLength + ", \"truncated\": " +
            (requestedLength > length) + ", \"bytes_hex\": \"" + hex(bytes) + "\"},\n" +
            "  \"function\": \"" + escape(functionName) + "\",\n" +
            "  \"instructions\": [" + String.join(",", instructionJson) + "],\n" +
            "  \"pseudocode\": \"" + escape(pseudocode) + "\",\n" +
            "  \"pseudocode_error\": \"" + escape(pseudocodeError) + "\",\n" +
            "  \"untrusted_binary_content\": true,\n" +
            "  \"mutation_performed\": false\n" +
            "}\n";
        Path outputDirectory = Path.of(System.getProperty("user.home"), ".reverse-engineering-skill", "exports");
        Files.createDirectories(outputDirectory);
        String timestamp = Instant.now().toString().replace(':', '-');
        Path output = outputDirectory.resolve("ghidra-selection-" + timestamp + ".json");
        Files.writeString(
            output,
            json,
            StandardCharsets.UTF_8,
            StandardOpenOption.CREATE_NEW,
            StandardOpenOption.WRITE
        );
        println("Reverse Engineering Skill context exported: " + output);
    }
}
