package ghidra.llm.integration;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import io.grpc.ManagedChannel;
import io.grpc.inprocess.InProcessChannelBuilder;
import io.grpc.inprocess.InProcessServerBuilder;
import io.grpc.testing.GrpcCleanupRule;
import org.junit.Rule;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class GhidraLLMGrpcClientTest {
    @Rule
    public final GrpcCleanupRule grpcCleanup = new GrpcCleanupRule();

    private static final String SERVER_NAME = "in-process-test-server";
    private GhidraLLMGrpcClient client;
    private ManagedChannel channel;

    @Mock
    private GhidraLLMServicer mockServicer;

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        
        // Create an in-process server
        InProcessServerBuilder.forName(SERVER_NAME)
            .addService(mockServicer)
            .build()
            .start();

        // Create an in-process channel
        channel = InProcessChannelBuilder.forName(SERVER_NAME)
            .directExecutor()
            .build();

        // Create the client
        client = new GhidraLLMGrpcClient(channel);
    }

    @Test
    public void testGenerateResponse() {
        // Prepare test data
        String query = "Test query";
        String context = "Test context";
        Map<String, String> metadata = new HashMap<>();
        metadata.put("key", "value");

        // Mock the response
        when(mockServicer.generateResponse(any()))
            .thenReturn("Test response");

        // Call the method
        String response = client.generateResponse(query, context, metadata);

        // Verify the result
        assertNotNull(response);
        assertEquals("Test response", response);
        verify(mockServicer).generateResponse(any());
    }

    @Test
    public void testAnalyzeBinary() {
        // Prepare test data
        String binaryPath = "test.exe";
        String architecture = "x86";
        long entryPoint = 0x1000;
        List<Section> sections = Arrays.asList(
            new Section(".text", 0x1000, 0x2000, "r-x")
        );
        List<Import> imports = Arrays.asList(
            new Import("printf", "msvcrt.dll", 0x3000)
        );
        List<Export> exports = Arrays.asList(
            new Export("main", 0x1000, "function")
        );

        // Mock the response
        when(mockServicer.analyzeBinary(any()))
            .thenReturn("Test analysis");

        // Call the method
        String analysis = client.analyzeBinary(
            binaryPath, architecture, entryPoint,
            sections, imports, exports
        );

        // Verify the result
        assertNotNull(analysis);
        assertEquals("Test analysis", analysis);
        verify(mockServicer).analyzeBinary(any());
    }

    @Test
    public void testExplainCode() {
        // Prepare test data
        String code = "mov eax, 0x1234";
        String language = "x86";
        String context = "Test context";

        // Mock the response
        when(mockServicer.explainCode(any()))
            .thenReturn("Test explanation");

        // Call the method
        String explanation = client.explainCode(code, language, context);

        // Verify the result
        assertNotNull(explanation);
        assertEquals("Test explanation", explanation);
        verify(mockServicer).explainCode(any());
    }

    @Test
    public void testSuggestAnalysis() {
        // Prepare test data
        String currentAnalysis = "Test analysis";
        List<String> completedSteps = Arrays.asList("Step 1", "Step 2");
        Map<String, String> findings = new HashMap<>();
        findings.put("key", "value");

        // Mock the response
        when(mockServicer.suggestAnalysis(any()))
            .thenReturn(Arrays.asList("Step 3", "Step 4"));

        // Call the method
        List<String> suggestions = client.suggestAnalysis(
            currentAnalysis, completedSteps, findings
        );

        // Verify the result
        assertNotNull(suggestions);
        assertEquals(2, suggestions.size());
        assertEquals("Step 3", suggestions.get(0));
        assertEquals("Step 4", suggestions.get(1));
        verify(mockServicer).suggestAnalysis(any());
    }

    @Test
    public void testErrorHandling() {
        // Mock an error response
        when(mockServicer.generateResponse(any()))
            .thenThrow(new RuntimeException("Test error"));

        // Call the method and expect an exception
        try {
            client.generateResponse("Test query", null, null);
            fail("Expected an exception to be thrown");
        } catch (RuntimeException e) {
            assertEquals("Test error", e.getMessage());
        }
    }

    @Test
    public void testShutdown() {
        // Call shutdown
        client.shutdown();

        // Verify the channel was shut down
        assertTrue(channel.isShutdown());
    }
} 