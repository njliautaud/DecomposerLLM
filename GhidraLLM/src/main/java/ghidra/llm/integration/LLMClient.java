package ghidra.llm.integration;

import java.io.IOException;
import java.util.List;
import java.util.Map;

public interface LLMClient {
    /**
     * Generate a response from the LLM based on a query and context
     * @param query The query to send to the LLM
     * @param context Optional context about the current analysis
     * @param metadata Additional metadata about the request
     * @return The LLM's response
     * @throws IOException If there's an error communicating with the LLM
     */
    String generateResponse(String query, String context, Map<String, String> metadata) throws IOException;

    /**
     * Analyze a binary using the LLM
     * @param request The binary analysis request containing program information
     * @return The LLM's analysis of the binary
     * @throws IOException If there's an error communicating with the LLM
     */
    String analyzeBinary(BinaryAnalysisRequest request) throws IOException;

    /**
     * Get an explanation of code from the LLM
     * @param request The code explanation request
     * @return The LLM's explanation of the code
     * @throws IOException If there's an error communicating with the LLM
     */
    String explainCode(CodeExplanationRequest request) throws IOException;

    /**
     * Get analysis suggestions from the LLM
     * @param request The analysis suggestion request
     * @return List of suggested analysis steps
     * @throws IOException If there's an error communicating with the LLM
     */
    List<String> suggestAnalysis(AnalysisSuggestionRequest request) throws IOException;
} 