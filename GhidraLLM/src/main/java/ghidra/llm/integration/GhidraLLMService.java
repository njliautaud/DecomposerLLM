package ghidra.llm.integration;

import ghidra.app.plugin.core.analysis.AnalysisManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Import;
import ghidra.program.model.symbol.Export;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class GhidraLLMService {
    private final Program program;
    private final LLMClient llmClient;
    private final AnalysisManager analysisManager;

    public GhidraLLMService(Program program, LLMClient llmClient) {
        this.program = program;
        this.llmClient = llmClient;
        this.analysisManager = new AnalysisManager(program);
    }

    public String queryLLM(String query, String context) throws IOException {
        Map<String, String> metadata = new HashMap<>();
        metadata.put("program_name", program.getName());
        metadata.put("architecture", program.getLanguage().getLanguageDescription().getLanguage().toString());
        
        return llmClient.generateResponse(query, context, metadata);
    }

    public String analyzeBinary() throws IOException, CancelledException {
        BinaryAnalysisRequest request = new BinaryAnalysisRequest();
        request.binaryPath = program.getExecutablePath();
        request.architecture = program.getLanguage().getLanguageDescription().getLanguage().toString();
        request.entryPoint = program.getEntryPoint().getOffset();

        // Add sections
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            Section section = new Section();
            section.name = block.getName();
            section.startAddress = block.getStart().getOffset();
            section.endAddress = block.getEnd().getOffset();
            section.permissions = block.getPermissions().toString();
            request.sections.add(section);
        }

        // Add imports
        for (Import imp : program.getImportList().getImports()) {
            Import import_ = new Import();
            import_.name = imp.getName();
            import_.library = imp.getLibraryName();
            import_.address = imp.getAddress().getOffset();
            request.imports.add(import_);
        }

        // Add exports
        for (Export exp : program.getExportList().getExports()) {
            Export export = new Export();
            export.name = exp.getName();
            export.address = exp.getAddress().getOffset();
            export.type = exp.getType().toString();
            request.exports.add(export);
        }

        return llmClient.analyzeBinary(request);
    }

    public String explainCode(String code, String language) throws IOException {
        CodeExplanationRequest request = new CodeExplanationRequest();
        request.code = code;
        request.language = language;
        request.context = "Current program: " + program.getName();

        return llmClient.explainCode(request);
    }

    public List<String> suggestAnalysis() throws IOException {
        AnalysisSuggestionRequest request = new AnalysisSuggestionRequest();
        request.currentAnalysis = "Analysis of " + program.getName();
        
        // Add completed analysis steps
        for (String step : analysisManager.getCompletedAnalysisSteps()) {
            request.completedSteps.add(step);
        }

        // Add findings
        Map<String, String> findings = new HashMap<>();
        findings.put("architecture", program.getLanguage().getLanguageDescription().getLanguage().toString());
        findings.put("entry_point", program.getEntryPoint().toString());
        request.findings = findings;

        return llmClient.suggestAnalysis(request);
    }

    // Supporting classes for protobuf messages
    private static class BinaryAnalysisRequest {
        String binaryPath;
        String architecture;
        long entryPoint;
        List<Section> sections = new ArrayList<>();
        List<Import> imports = new ArrayList<>();
        List<Export> exports = new ArrayList<>();
    }

    private static class Section {
        String name;
        long startAddress;
        long endAddress;
        String permissions;
    }

    private static class Import {
        String name;
        String library;
        long address;
    }

    private static class Export {
        String name;
        long address;
        String type;
    }

    private static class CodeExplanationRequest {
        String code;
        String language;
        String context;
    }

    private static class AnalysisSuggestionRequest {
        String currentAnalysis;
        List<String> completedSteps = new ArrayList<>();
        Map<String, String> findings;
    }
} 