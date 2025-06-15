package ghidra.llm.integration;

import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import io.grpc.StatusRuntimeException;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

public class GhidraLLMGrpcClient implements LLMClient {
    private static final Logger logger = Logger.getLogger(GhidraLLMGrpcClient.class.getName());
    private final ManagedChannel channel;
    private final GhidraLLMServiceGrpc.GhidraLLMServiceBlockingStub blockingStub;

    public GhidraLLMGrpcClient(String host, int port) {
        this(ManagedChannelBuilder.forAddress(host, port)
                .usePlaintext()
                .build());
    }

    public GhidraLLMGrpcClient(ManagedChannel channel) {
        this.channel = channel;
        blockingStub = GhidraLLMServiceGrpc.newBlockingStub(channel);
    }

    public void shutdown() throws InterruptedException {
        channel.shutdown().awaitTermination(5, TimeUnit.SECONDS);
    }

    @Override
    public String generateResponse(String query, String context, Map<String, String> metadata) throws IOException {
        try {
            QueryRequest request = QueryRequest.newBuilder()
                    .setQuery(query)
                    .setContext(context)
                    .putAllMetadata(metadata)
                    .build();

            QueryResponse response = blockingStub.queryLLM(request);
            return response.getResponse();
        } catch (StatusRuntimeException e) {
            logger.log(Level.WARNING, "RPC failed: {0}", e.getStatus());
            throw new IOException("Failed to generate response", e);
        }
    }

    @Override
    public String analyzeBinary(BinaryAnalysisRequest request) throws IOException {
        try {
            com.ghidra.llm.BinaryAnalysisRequest grpcRequest = com.ghidra.llm.BinaryAnalysisRequest.newBuilder()
                    .setBinaryPath(request.binaryPath)
                    .setArchitecture(request.architecture)
                    .setEntryPoint(request.entryPoint)
                    .addAllSections(convertSections(request.sections))
                    .addAllImports(convertImports(request.imports))
                    .addAllExports(convertExports(request.exports))
                    .build();

            com.ghidra.llm.BinaryAnalysisResponse response = blockingStub.analyzeBinary(grpcRequest);
            return response.getAnalysis();
        } catch (StatusRuntimeException e) {
            logger.log(Level.WARNING, "RPC failed: {0}", e.getStatus());
            throw new IOException("Failed to analyze binary", e);
        }
    }

    @Override
    public String explainCode(CodeExplanationRequest request) throws IOException {
        try {
            com.ghidra.llm.CodeExplanationRequest grpcRequest = com.ghidra.llm.CodeExplanationRequest.newBuilder()
                    .setCode(request.code)
                    .setLanguage(request.language)
                    .setContext(request.context)
                    .build();

            com.ghidra.llm.CodeExplanationResponse response = blockingStub.explainCode(grpcRequest);
            return response.getExplanation();
        } catch (StatusRuntimeException e) {
            logger.log(Level.WARNING, "RPC failed: {0}", e.getStatus());
            throw new IOException("Failed to explain code", e);
        }
    }

    @Override
    public List<String> suggestAnalysis(AnalysisSuggestionRequest request) throws IOException {
        try {
            com.ghidra.llm.AnalysisSuggestionRequest grpcRequest = com.ghidra.llm.AnalysisSuggestionRequest.newBuilder()
                    .setCurrentAnalysis(request.currentAnalysis)
                    .addAllCompletedSteps(request.completedSteps)
                    .putAllFindings(request.findings)
                    .build();

            com.ghidra.llm.AnalysisSuggestionResponse response = blockingStub.suggestAnalysis(grpcRequest);
            return response.getSuggestedStepsList();
        } catch (StatusRuntimeException e) {
            logger.log(Level.WARNING, "RPC failed: {0}", e.getStatus());
            throw new IOException("Failed to suggest analysis", e);
        }
    }

    private List<com.ghidra.llm.Section> convertSections(List<Section> sections) {
        return sections.stream()
                .map(section -> com.ghidra.llm.Section.newBuilder()
                        .setName(section.name)
                        .setStartAddress(section.startAddress)
                        .setEndAddress(section.endAddress)
                        .setPermissions(section.permissions)
                        .build())
                .toList();
    }

    private List<com.ghidra.llm.Import> convertImports(List<Import> imports) {
        return imports.stream()
                .map(imp -> com.ghidra.llm.Import.newBuilder()
                        .setName(imp.name)
                        .setLibrary(imp.library)
                        .setAddress(imp.address)
                        .build())
                .toList();
    }

    private List<com.ghidra.llm.Export> convertExports(List<Export> exports) {
        return exports.stream()
                .map(exp -> com.ghidra.llm.Export.newBuilder()
                        .setName(exp.name)
                        .setAddress(exp.address)
                        .setType(exp.type)
                        .build())
                .toList();
    }
} 